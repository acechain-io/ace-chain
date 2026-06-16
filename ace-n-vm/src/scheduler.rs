//! Parallel transaction scheduler.
//!
//! Builds conflict-free batches from a transaction list and executes
//! each batch in parallel using rayon. Batches run sequentially to
//! preserve block-level determinism.

use std::collections::{HashMap, HashSet};

use ace_model::account::AccountId;
use ace_runtime::types::block::OP_MEV_ACE_OMISSION_EVIDENCE;
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use sha2::{Digest, Sha256};

/// Derive the per-market ACE Liquid book account from a 32-byte market id.
///
/// Must stay byte-for-byte identical to `ace_liquid::state::market_book_id`
/// (domain `"ace-liquid:book:v1:"`). Duplicated here because `ace-liquid`
/// depends on `ace-n-vm`, so this crate cannot depend on it in return.
fn ace_liquid_book_account(market_id: &[u8; 32]) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-liquid:book:v1:");
    hasher.update(market_id);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    AccountId::from_bytes(id)
}

/// The extracted write set for a single transaction.
#[derive(Debug, Clone)]
pub enum WriteSet {
    /// Known, finite set of accounts this transaction writes.
    Accounts(HashSet<AccountId>),
    /// Unknown / unbounded write set — conflicts with everything.
    /// Used for EVM call (0x10) and EVM create (0x11).
    Global,
}

impl WriteSet {
    /// Check whether two write sets conflict (have any overlap).
    pub fn conflicts_with(&self, other: &WriteSet) -> bool {
        match (self, other) {
            (WriteSet::Global, _) | (_, WriteSet::Global) => true,
            (WriteSet::Accounts(a), WriteSet::Accounts(b)) => {
                let (smaller, larger) = if a.len() <= b.len() { (a, b) } else { (b, a) };
                smaller.iter().any(|id| larger.contains(id))
            }
        }
    }
}

/// Extract the write set for a transaction from its payload.
///
/// Sender is always included (nonce mutation on success).
pub fn extract_write_set(tx: &Transaction) -> WriteSet {
    if tx.payload.is_empty() {
        return WriteSet::Accounts(HashSet::new());
    }

    let sender = AccountId::from_bytes(tx.attestation.idcom);
    let opcode = tx.payload[0];

    match opcode {
        // 0x01: Native transfer [nonce:8 LE][to:32][amount:8 LE]
        0x01 => {
            let mut set = HashSet::new();
            set.insert(sender);
            let recipient_offset = if tx.payload.len() >= 49 { 9 } else { 1 };
            if tx.payload.len() >= recipient_offset + 32 {
                let mut to = [0u8; 32];
                to.copy_from_slice(&tx.payload[recipient_offset..recipient_offset + 32]);
                set.insert(AccountId::from_bytes(to));
            }
            WriteSet::Accounts(set)
        }
        // 0x02: Native create account [new_id:32][auth_pubkey:32]
        0x02 => {
            let mut set = HashSet::new();
            set.insert(sender);
            if tx.payload.len() >= 33 {
                let mut new_id = [0u8; 32];
                new_id.copy_from_slice(&tx.payload[1..33]);
                set.insert(AccountId::from_bytes(new_id));
            }
            WriteSet::Accounts(set)
        }
        // 0x10: EVM call — arbitrary bytecode, unknown write set
        // 0x11: EVM create — arbitrary init code, unknown write set
        // 0x12: EVM transfer — can't resolve 20B EVM addr to AccountId without state
        // 0x13: OmniLiquid oAsset withdrawal — touches token ledger, bridge
        // withdrawal index, and reserve accounting.
        0x10..=0x13 => WriteSet::Global,
        // 0x20: SVM invoke — extract ALL declared account keys for the write set.
        // Include both writable and read-only accounts because built-in programs
        // (SystemProgram, SPL Token) may internally modify accounts that the
        // caller declared as read-only (e.g., SPL Token debiting a source
        // account that is only marked as signer, not writable).  Over-declaring
        // the write set is safe (reduces parallelism slightly); under-declaring
        // causes data races.
        // Payload: [opcode:1][program_id:32][num_accounts:1][[pubkey:32][is_signer:1][is_writable:1]]...[data_len:4][data...]
        0x20 => {
            if tx.payload.len() < 34 {
                return WriteSet::Global;
            }
            let mut set = HashSet::new();
            set.insert(sender);
            let mut cursor = 1 + 32; // skip opcode + program_id
            let num_accounts = tx.payload[cursor] as usize;
            cursor += 1;

            for _ in 0..num_accounts {
                if cursor + 34 > tx.payload.len() {
                    break;
                }
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&tx.payload[cursor..cursor + 32]);
                set.insert(AccountId::from_bytes(pubkey));
                cursor += 34;
            }
            WriteSet::Accounts(set)
        }
        // 0x21: SVM transfer [nonce:8 LE][to:32][amount:8 LE]
        0x21 => {
            let mut set = HashSet::new();
            set.insert(sender);
            let recipient_offset = if tx.payload.len() >= 49 { 9 } else { 1 };
            if tx.payload.len() >= recipient_offset + 32 {
                let mut to = [0u8; 32];
                to.copy_from_slice(&tx.payload[recipient_offset..recipient_offset + 32]);
                set.insert(AccountId::from_bytes(to));
            }
            WriteSet::Accounts(set)
        }
        // 0x30: BVM transfer [nonce:8 LE][to:32][value:8 LE]
        0x30 => {
            let mut set = HashSet::new();
            set.insert(sender);
            let recipient_offset = if tx.payload.len() >= 49 { 9 } else { 1 };
            if tx.payload.len() >= recipient_offset + 32 {
                let mut to = [0u8; 32];
                to.copy_from_slice(&tx.payload[recipient_offset..recipient_offset + 32]);
                set.insert(AccountId::from_bytes(to));
            }
            WriteSet::Accounts(set)
        }
        // 0x31: BVM script_exec — only mutates sender's nonce
        0x31 => {
            let mut set = HashSet::new();
            set.insert(sender);
            WriteSet::Accounts(set)
        }
        // 0x32: BVM utxo_spend [num_inputs:1][inputs...][num_outputs:1][outputs...]
        0x32 => {
            if matches!(
                tx.raw_chain.as_ref().map(|raw_chain| raw_chain.kind),
                Some(RawChainKind::Btc)
            ) {
                return WriteSet::Global;
            }
            let mut set = HashSet::new();
            set.insert(sender);

            let mut cursor = 1usize; // skip opcode
            if cursor >= tx.payload.len() {
                return WriteSet::Accounts(set);
            }

            let num_inputs = tx.payload[cursor] as usize;
            cursor += 1;

            // Skip each input: [txid:32][vout:4][script_sig_len:4][script_sig...]
            for _ in 0..num_inputs {
                if cursor + 40 > tx.payload.len() {
                    return WriteSet::Global;
                } // Malformed
                cursor += 36; // txid + vout
                let sig_len =
                    u32::from_le_bytes(tx.payload[cursor..cursor + 4].try_into().unwrap_or([0; 4]))
                        as usize;
                cursor += 4;
                if cursor
                    .checked_add(sig_len)
                    .is_none_or(|c| c > tx.payload.len())
                {
                    return WriteSet::Global;
                }
                cursor += sig_len;
            }

            // Parse outputs: [num_outputs:1][[to:32][value:8][spk_len:4][spk...]]...
            if cursor >= tx.payload.len() {
                return WriteSet::Accounts(set);
            }
            let num_outputs = tx.payload[cursor] as usize;
            cursor += 1;

            for _ in 0..num_outputs {
                if cursor + 40 > tx.payload.len() {
                    return WriteSet::Global;
                }
                let mut to = [0u8; 32];
                to.copy_from_slice(&tx.payload[cursor..cursor + 32]);
                set.insert(AccountId::from_bytes(to));
                cursor += 40; // to + value

                if cursor + 4 > tx.payload.len() {
                    break;
                }
                let spk_len =
                    u32::from_le_bytes(tx.payload[cursor..cursor + 4].try_into().unwrap_or([0; 4]))
                        as usize;
                cursor += 4;
                if cursor
                    .checked_add(spk_len)
                    .is_none_or(|c| c > tx.payload.len())
                {
                    break;
                }
                cursor += spk_len;
            }
            WriteSet::Accounts(set)
        }
        // 0x03: SetAuthPubkey — mutates sender's auth_pubkey / auth_keys + nonce
        // 0x04: AddAuthKey   — mutates sender's auth_keys + nonce
        0x03 | 0x04 => {
            let mut set = HashSet::new();
            set.insert(sender);
            WriteSet::Accounts(set)
        }
        // 0x05: CrossVmSettle — touches bridge, swap pool, and withdrawal state
        // 0x06..=0x0B: HFI Pay lifecycle — touches intent registry, recipient
        // indexes, deposit/destination balances, and sometimes nonce state.
        // 0x0D/0x0E: ACE DeFi bridge system transactions — touch bridge
        // registry, deposit/withdrawal markers, and wrapped-token balances.
        0x05 | 0x06..=0x0B | 0x0D | 0x0E => WriteSet::Global,
        // 0x14: MEV-ACE omission evidence — applies governance slashing.
        OP_MEV_ACE_OMISSION_EVIDENCE => WriteSet::Global,
        // 0x0F: ACE Liquid order book. place(0x02)/cancel(0x03) settle entirely
        // inside the per-market account, so they touch only {sender, market
        // book account} and run in parallel across markets. create/deposit/
        // withdraw bridge the shared token ledger → Global.
        0x0F => {
            const SUB_OFFSET: usize = 1;
            const MARKET_ID_OFFSET: usize = 10; // OP(1) + SUB(1) + nonce(8)
            if tx.payload.len() >= MARKET_ID_OFFSET + 32
                && matches!(tx.payload[SUB_OFFSET], 0x02 | 0x03)
            {
                let mut market_id = [0u8; 32];
                market_id.copy_from_slice(&tx.payload[MARKET_ID_OFFSET..MARKET_ID_OFFSET + 32]);
                let mut set = HashSet::new();
                set.insert(sender);
                set.insert(ace_liquid_book_account(&market_id));
                WriteSet::Accounts(set)
            } else {
                WriteSet::Global
            }
        }
        // 0x0C: ApproveValidator — native state only mutates sender nonce;
        // governance admission is applied sequentially by node.rs after execution.
        0x0C => {
            let mut set = HashSet::new();
            set.insert(sender);
            WriteSet::Accounts(set)
        }
        // 0x40–0x4F: TVM — unbounded write set, must not run in parallel
        0x40..=0x4F => WriteSet::Global,
        // 0x50–0x5F: Move VM.
        // Layout: [opcode:1][nonce:8][module_addr:32][module_name:32]
        //         [func_name_len:2][func_name:var][args_count:2][args:var]
        // For "transfer", args[0] is a 33-byte tagged address (tag:1 + addr:32).
        // We can extract sender+recipient without full parsing and allow parallelism.
        // Anything else (publish_module, unknown functions) falls back to Global.
        0x50..=0x5F => {
            // Minimum offset to reach func_name_len field: 1+8+32+32 = 73
            const FUNC_LEN_OFFSET: usize = 73;
            if tx.payload.len() < FUNC_LEN_OFFSET + 2 {
                return WriteSet::Global;
            }
            let func_name_len =
                u16::from_le_bytes([tx.payload[FUNC_LEN_OFFSET], tx.payload[FUNC_LEN_OFFSET + 1]])
                    as usize;
            let func_start = FUNC_LEN_OFFSET + 2;
            if tx.payload.len() < func_start + func_name_len {
                return WriteSet::Global;
            }
            let func_name = &tx.payload[func_start..func_start + func_name_len];
            if func_name == b"transfer" {
                // args layout after func_name: [args_count:2][tag:1][recipient:32]...
                let args_offset = func_start + func_name_len + 2; // skip args_count
                if tx.payload.len() >= args_offset + 1 + 32 {
                    let recipient_bytes: [u8; 32] = tx.payload
                        [args_offset + 1..args_offset + 1 + 32]
                        .try_into()
                        .unwrap();
                    let mut set = HashSet::new();
                    set.insert(sender);
                    set.insert(AccountId::from_bytes(recipient_bytes));
                    return WriteSet::Accounts(set);
                }
            }
            // publish_module and all other functions: conservative global lock
            WriteSet::Global
        }
        // Unknown opcodes: empty write set, will fail at execution
        _ => WriteSet::Accounts(HashSet::new()),
    }
}

/// A batch of transactions that can execute in parallel.
pub struct Batch {
    /// Indices into the original `&[Transaction]` slice.
    pub tx_indices: Vec<usize>,
    /// Union of all write sets in this batch (for fast conflict checking).
    write_set_union: WriteSet,
}

impl Batch {
    fn new() -> Self {
        Self {
            tx_indices: Vec::new(),
            write_set_union: WriteSet::Accounts(HashSet::new()),
        }
    }

    /// Try to add a transaction to this batch.
    /// Returns false if it conflicts with existing batch contents.
    fn try_add(&mut self, tx_idx: usize, ws: &WriteSet) -> bool {
        // Empty batch always accepts any tx.
        if !self.tx_indices.is_empty() && self.write_set_union.conflicts_with(ws) {
            return false;
        }
        self.tx_indices.push(tx_idx);
        match (&mut self.write_set_union, ws) {
            (WriteSet::Accounts(ref mut union), WriteSet::Accounts(accounts)) => {
                union.extend(accounts.iter().cloned());
            }
            _ => {
                self.write_set_union = WriteSet::Global;
            }
        }
        true
    }
}

/// Build conflict-free batches from a list of transactions.
///
/// Algorithm (greedy, single-pass):
/// - For each tx in order:
///   1. Determine earliest batch (must be after sender's previous tx for nonce ordering)
///   2. Try to add to earliest eligible batch with no write-set conflict
///   3. If none found, create a new batch
///
/// Invariant: tx ordering within each sender is preserved across batches.
pub fn build_batches(txs: &[Transaction]) -> Vec<Batch> {
    let write_sets: Vec<WriteSet> = txs.iter().map(extract_write_set).collect();
    let mut batches: Vec<Batch> = Vec::new();
    let mut sender_latest: HashMap<AccountId, usize> = HashMap::new();

    for (i, tx) in txs.iter().enumerate() {
        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let ws = &write_sets[i];

        // Earliest batch due to same-sender nonce ordering
        let earliest = sender_latest.get(&sender).map(|&b| b + 1).unwrap_or(0);

        let mut placed = false;
        for batch_idx in earliest..batches.len() {
            if batches[batch_idx].try_add(i, ws) {
                sender_latest.insert(sender, batch_idx);
                placed = true;
                break;
            }
        }

        if !placed {
            let mut new_batch = Batch::new();
            new_batch.try_add(i, ws);
            sender_latest.insert(sender, batches.len());
            batches.push(new_batch);
        }
    }

    batches
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_runtime::crypto::sig_algo::{SignatureAlgorithm, TaggedSignature};
    use ace_runtime::types::attestation::{Attestation, Domain};

    fn tx_with_opcode(opcode: u8) -> Transaction {
        tx_with_payload(vec![opcode], [7u8; 32])
    }

    fn tx_with_payload(payload: Vec<u8>, idcom: [u8; 32]) -> Transaction {
        Transaction::new(
            payload,
            Attestation {
                obj_hash: [0u8; 32],
                idcom,
                domain: Domain::new(1, 1),
                context_tag: [0u8; 16],
                credential: TaggedSignature {
                    algorithm: SignatureAlgorithm::MlDsa44,
                    bytes: Vec::new(),
                },
            },
        )
    }

    #[test]
    fn cross_vm_settle_requires_global_write_set() {
        let tx = tx_with_opcode(0x05);
        assert!(matches!(extract_write_set(&tx), WriteSet::Global));
    }

    #[test]
    fn ace_liquid_create_deposit_are_global() {
        // create-market (sub 0x01) and short payloads bridge the shared token
        // ledger / are unclassifiable → Global.
        let tx = tx_with_opcode(0x0F);
        assert!(matches!(extract_write_set(&tx), WriteSet::Global));
    }

    #[test]
    fn ace_liquid_place_is_per_market_parallel() {
        // OP(0x0F) SUB(0x02=place) nonce(8) market_id(32) ...
        let market_id = [0xABu8; 32];
        let sender = [7u8; 32];
        let mut payload = vec![0x0F, 0x02];
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&market_id);
        payload.extend_from_slice(&[0u8; 19]); // side/type/tif/price/qty
        let tx = tx_with_payload(payload, sender);
        let ws = extract_write_set(&tx);
        let book = ace_liquid_book_account(&market_id);
        match ws {
            WriteSet::Accounts(accounts) => {
                assert!(accounts.contains(&AccountId::from_bytes(sender)));
                assert!(accounts.contains(&book));
                assert_eq!(accounts.len(), 2);
            }
            WriteSet::Global => panic!("place order must be per-market, not Global"),
        }

        // A place on a *different* market must not conflict.
        let other_market = [0xCDu8; 32];
        let mut payload2 = vec![0x0F, 0x02];
        payload2.extend_from_slice(&0u64.to_le_bytes());
        payload2.extend_from_slice(&other_market);
        payload2.extend_from_slice(&[0u8; 19]);
        let tx2 = tx_with_payload(payload2, [8u8; 32]);
        assert!(!extract_write_set(&tx).conflicts_with(&extract_write_set(&tx2)));
    }
}
