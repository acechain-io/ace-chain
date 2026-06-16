//! MEV-ACE integration boundary for ACE consensus.
//!
//! `mev-ace-core` is kept as an external protocol library. This module adapts
//! ACE consensus types to the library trait surface without duplicating the
//! protocol state machine inside `ace-consensus`.

use ace_runtime::crypto::sig_algo::{verify_signature, TaggedSignature};
use ace_runtime::crypto::{SignatureAlgorithm, TaggedPubkey};
use ace_runtime::types::block::{
    MevAceCertifiedCommitment, MevAceCertifiedOpening, MevAceCommitReceipt, MevAceCommitment,
    MevAceOmissionKind, MevAceOmissionProof, MevAceOpenReceipt, MevAceOpening,
    MevAceProposalMaterial,
};
use ace_runtime::types::transaction::Transaction;
use mev_ace_core::canonical::CsetLeaf;
use mev_ace_core::messages::{CommitReceipt, Commitment, OpenReceipt, Opening};
use mev_ace_core::omission::{OmissionKind, OmissionProof};
use mev_ace_core::shuffle::fisher_yates;
use mev_ace_core::state::{
    verify_proposal, CertifiedCommitment, CertifiedOpening, ProposalDraft, SignedProposal,
};
use mev_ace_core::traits::{
    self, BondedIdentityStore, DelayError, DelayFunction, Hasher, SignatureScheme,
};
use mev_ace_core::types::{AuthAlg, Hash32, Idcom, Nonce, Signature, Slot, VerificationKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::validator_set::ValidatorSet;

/// Policy values used when ACE drives a MEV-ACE slot state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MevAcePolicy {
    /// Per-identity commitment quota `ell`.
    pub per_identity_commit_quota: usize,
    /// Global admissible-set cap.
    pub max_admissible_set_size: usize,
    /// Whether proposal ordering must be verified by MEV-ACE material.
    pub enforce_proposal_ordering: bool,
}

impl Default for MevAcePolicy {
    fn default() -> Self {
        Self {
            per_identity_commit_quota: 4,
            max_admissible_set_size: mev_ace_core::state::DEFAULT_MAX_ADMISSIBLE_SET_SIZE,
            enforce_proposal_ordering: false,
        }
    }
}

/// SHA-256 hasher matching the MEV-ACE reference deployment.
#[derive(Debug, Default, Clone, Copy)]
pub struct AceMevHasher;

impl traits::Hasher for AceMevHasher {
    fn hash(&self, input: &[u8]) -> Hash32 {
        let digest = Sha256::digest(input);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Hash32(out)
    }
}

/// Development VDF adapter for ACE's MEV-ACE devnet/testnet wiring.
///
/// This is deterministic and cheap, so it is suitable for devnet/testnet
/// wiring and unit tests. A production MEV-ACE deployment should replace this
/// with a calibrated sequential-delay implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct AceDevVdf;

impl DelayFunction for AceDevVdf {
    fn eval(&self, input: &[u8]) -> Result<(Hash32, Vec<u8>), DelayError> {
        let hasher = AceMevHasher;
        let seed = hasher.hash(input);
        let proof = hasher.hash(&seed.0).0.to_vec();
        Ok((seed, proof))
    }

    fn verify(&self, input: &[u8], seed: &Hash32, proof: &[u8]) -> bool {
        let hasher = AceMevHasher;
        let expected_seed = hasher.hash(input);
        let expected_proof = hasher.hash(&expected_seed.0);
        seed == &expected_seed && proof == expected_proof.0
    }

    fn difficulty(&self) -> u64 {
        2
    }
}

/// ACE signature registry for MEV-ACE verification.
#[derive(Debug)]
pub struct AceMevSignatureRegistry {
    ed25519: AceMevSignatureScheme,
    ml_dsa_44: AceMevSignatureScheme,
}

impl Default for AceMevSignatureRegistry {
    fn default() -> Self {
        Self {
            ed25519: AceMevSignatureScheme {
                algorithm: AuthAlg::Ed25519,
            },
            ml_dsa_44: AceMevSignatureScheme {
                algorithm: AuthAlg::MlDsa44,
            },
        }
    }
}

impl traits::SignatureRegistry for AceMevSignatureRegistry {
    fn scheme_for(&self, alg: AuthAlg) -> Option<&dyn SignatureScheme> {
        match alg {
            AuthAlg::Ed25519 => Some(&self.ed25519),
            AuthAlg::MlDsa44 => Some(&self.ml_dsa_44),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AceMevSignatureScheme {
    algorithm: AuthAlg,
}

impl Default for AceMevSignatureScheme {
    fn default() -> Self {
        Self {
            algorithm: AuthAlg::Ed25519,
        }
    }
}

impl SignatureScheme for AceMevSignatureScheme {
    fn algorithm(&self) -> AuthAlg {
        self.algorithm
    }

    fn verification_key_len(&self) -> Option<usize> {
        match self.algorithm {
            AuthAlg::Ed25519 => Some(SignatureAlgorithm::Ed25519.pubkey_len()),
            AuthAlg::MlDsa44 => Some(SignatureAlgorithm::MlDsa44.pubkey_len()),
        }
    }

    fn verify(&self, vk: &VerificationKey, msg: &[u8], sig: &Signature) -> bool {
        let Some(ace_alg) = mev_alg_to_ace_alg(self.algorithm) else {
            return false;
        };
        let pubkey = TaggedPubkey {
            algorithm: ace_alg,
            bytes: vk.0.clone(),
        };
        let signature = TaggedSignature {
            algorithm: ace_alg,
            bytes: sig.0.clone(),
        };
        verify_signature(&pubkey, msg, &signature)
    }
}

/// Owned MEV-ACE validator-set snapshot for a single slot.
#[derive(Debug, Clone)]
pub struct MevAceValidatorSetSnapshot {
    validators: Vec<MevAceValidator>,
    leader_index: u32,
}

#[derive(Debug, Clone)]
struct MevAceValidator {
    index: u32,
    alg: AuthAlg,
    key: VerificationKey,
}

impl MevAceValidatorSetSnapshot {
    /// Build a MEV-ACE-compatible snapshot from ACE's current validator set.
    pub fn from_ace(set: &ValidatorSet) -> Self {
        let leader_index = set
            .validators()
            .first()
            .map_or(0, |validator| validator.index);
        Self::from_ace_for_leader(set, leader_index)
    }

    /// Build a MEV-ACE-compatible snapshot for a slot with an already selected leader.
    pub fn from_ace_for_leader(set: &ValidatorSet, leader_index: u32) -> Self {
        let validators = set
            .validators()
            .iter()
            .filter_map(|validator| {
                let alg = ace_alg_to_mev_alg(validator.signing_pubkey.algorithm)?;
                Some(MevAceValidator {
                    index: validator.index,
                    alg,
                    key: VerificationKey(validator.signing_pubkey.bytes.clone()),
                })
            })
            .collect();
        Self {
            validators,
            leader_index,
        }
    }
}

impl traits::ValidatorSet for MevAceValidatorSetSnapshot {
    fn len(&self) -> usize {
        self.validators.len()
    }

    fn f(&self) -> usize {
        self.validators.len().saturating_sub(1) / 3
    }

    fn q_c(&self) -> usize {
        self.f().saturating_mul(2).saturating_add(1)
    }

    fn q_o(&self) -> usize {
        self.q_c()
    }

    fn receipt_algorithm(&self) -> AuthAlg {
        self.validators
            .iter()
            .map(|validator| validator.alg)
            .next()
            .unwrap_or(AuthAlg::MlDsa44)
    }

    fn validator_alg(&self, index: u32) -> Option<AuthAlg> {
        self.validators
            .iter()
            .find(|validator| validator.index == index)
            .map(|validator| validator.alg)
    }

    fn validator_key(&self, index: u32) -> Option<&VerificationKey> {
        self.validators
            .iter()
            .find(|validator| validator.index == index)
            .map(|validator| &validator.key)
    }

    fn leader_for(&self, slot: Slot) -> u32 {
        let _ = slot;
        self.leader_index
    }
}

/// Convert ACE's runtime signature algorithm registry to MEV-ACE's protocol registry.
pub fn ace_alg_to_mev_alg(algorithm: SignatureAlgorithm) -> Option<AuthAlg> {
    match algorithm {
        SignatureAlgorithm::MlDsa44 => Some(AuthAlg::MlDsa44),
        SignatureAlgorithm::Ed25519 => Some(AuthAlg::Ed25519),
        SignatureAlgorithm::Secp256k1 | SignatureAlgorithm::HmacSha256 => None,
    }
}

fn mev_alg_to_ace_alg(algorithm: AuthAlg) -> Option<SignatureAlgorithm> {
    match algorithm {
        AuthAlg::MlDsa44 => Some(SignatureAlgorithm::MlDsa44),
        AuthAlg::Ed25519 => Some(SignatureAlgorithm::Ed25519),
    }
}

/// Return the deterministic MEV-ACE fair-ordering for a candidate transaction set.
///
/// This is the chain-side ordering hook used by ACE block proposals. It uses
/// MEV-ACE's canonical Fisher-Yates permutation while preserving per-identity
/// transaction lanes, so a proposer cannot arbitrarily arrange cross-identity
/// transactions but same-identity nonce order is not disrupted.
///
/// Scope: this enforces fair proposal ordering for the transactions included in
/// a block. It is not the full commit/open/receipt/VDF lifecycle from
/// `mev-ace-core::state::SlotState`.
pub fn fair_order_transactions(
    parent_hash: [u8; 32],
    slot: u64,
    txs: Vec<Transaction>,
) -> Vec<Transaction> {
    if txs.len() < 2 {
        return txs;
    }

    let seed = fair_order_seed(parent_hash, slot, &txs);
    let hasher = AceMevHasher;

    let mut lanes: BTreeMap<[u8; 32], Vec<Transaction>> = BTreeMap::new();
    for tx in txs {
        lanes.entry(tx.attestation.idcom).or_default().push(tx);
    }

    let mut lane_entries: Vec<([u8; 32], Vec<Transaction>)> = lanes.into_iter().collect();
    let sigma = fisher_yates(&seed, lane_entries.len() as u32, &hasher);

    let mut ordered = Vec::with_capacity(lane_entries.iter().map(|(_, lane)| lane.len()).sum());
    for idx in sigma {
        let (_, lane) = &mut lane_entries[idx as usize];
        ordered.append(lane);
    }
    ordered
}

/// Check whether a proposed block already follows ACE's MEV-ACE fair ordering.
pub fn is_fair_ordered(parent_hash: [u8; 32], slot: u64, txs: &[Transaction]) -> bool {
    if txs.len() < 2 {
        return true;
    }
    let expected_hashes: Vec<[u8; 32]> = fair_order_transactions(parent_hash, slot, txs.to_vec())
        .into_iter()
        .map(|tx| tx.tx_hash())
        .collect();
    txs.iter().map(|tx| tx.tx_hash()).eq(expected_hashes)
}

fn fair_order_seed(parent_hash: [u8; 32], slot: u64, txs: &[Transaction]) -> Hash32 {
    let mut lane_hashes: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
    for tx in txs {
        lane_hashes
            .entry(tx.attestation.idcom)
            .or_default()
            .push(tx.tx_hash());
    }

    let mut input = Vec::with_capacity(32 + 8 + txs.len() * 32);
    input.extend_from_slice(b"ace/mev-fair-order-v1");
    input.extend_from_slice(&parent_hash);
    input.extend_from_slice(&slot.to_be_bytes());
    for (idcom, hashes) in lane_hashes {
        input.extend_from_slice(&idcom);
        for hash in hashes {
            input.extend_from_slice(&hash);
        }
    }
    AceMevHasher.hash(&input)
}

/// Convert runtime MEV-ACE proposal material into the core verifier type.
pub fn proposal_material_to_signed(
    material: &MevAceProposalMaterial,
) -> Result<SignedProposal, String> {
    Ok(SignedProposal {
        proposal: ProposalDraft {
            slot: Slot(material.slot),
            cset_root: Hash32(material.cset_root),
            vdf_seed: Hash32(material.vdf_seed),
            vdf_proof: material.vdf_proof.clone(),
            sigma: material.sigma.clone(),
            omitted: material.omitted.iter().copied().map(Idcom).collect(),
            admissible_set: material
                .admissible_set
                .iter()
                .map(runtime_certified_commitment_to_core)
                .collect(),
            executable_set: material
                .executable_set
                .iter()
                .map(runtime_certified_opening_to_core)
                .collect(),
        },
        sig_proposer: Signature(material.proposer_signature.clone()),
    })
}

/// Verify full MEV-ACE material and ensure it commits exactly to block transactions.
pub fn verify_proposal_material_for_transactions(
    material: &MevAceProposalMaterial,
    parent_hash: [u8; 32],
    txs: &[Transaction],
    validator_set: &MevAceValidatorSetSnapshot,
    identities: &dyn BondedIdentityStore,
) -> Result<(), String> {
    let signed = proposal_material_to_signed(material)?;
    let hasher = AceMevHasher;
    let vdf = AceDevVdf;
    let signatures = AceMevSignatureRegistry::default();
    verify_proposal(
        &signed,
        Slot(material.slot),
        &Hash32(parent_hash),
        MevAcePolicy::default().per_identity_commit_quota,
        MevAcePolicy::default().max_admissible_set_size,
        identities,
        validator_set,
        &signatures,
        &hasher,
        &vdf,
        &[],
    )
    .map_err(|e| e.to_string())?;

    let executable_wires: Vec<&[u8]> = signed
        .proposal
        .executable_set
        .iter()
        .map(|opening| opening.opening.tx.as_slice())
        .collect();
    if executable_wires.len() != txs.len() {
        return Err(format!(
            "MEV-ACE executable set length {} does not match block tx count {}",
            executable_wires.len(),
            txs.len()
        ));
    }
    for (idx, (wire, tx)) in executable_wires.iter().zip(txs).enumerate() {
        if *wire != tx.to_bytes().as_slice() {
            return Err(format!(
                "MEV-ACE executable transaction at index {idx} does not match block transaction"
            ));
        }
    }
    Ok(())
}

pub fn omission_proof_to_core(proof: &MevAceOmissionProof) -> OmissionProof {
    OmissionProof {
        kind: match proof.kind {
            MevAceOmissionKind::Commit => OmissionKind::Commit,
            MevAceOmissionKind::Exec => OmissionKind::Exec,
        },
        slot: Slot(proof.slot),
        commitment: runtime_commitment_to_core(&proof.commitment),
        commit_receipts: proof
            .commit_receipts
            .iter()
            .map(runtime_commit_receipt_to_core)
            .collect(),
        opening: proof.opening.as_ref().map(runtime_opening_to_core),
        open_receipts: proof
            .open_receipts
            .iter()
            .map(runtime_open_receipt_to_core)
            .collect(),
    }
}

fn runtime_certified_commitment_to_core(value: &MevAceCertifiedCommitment) -> CertifiedCommitment {
    CertifiedCommitment {
        leaf: CsetLeaf {
            idcom: Idcom(value.idcom),
            c: Hash32(value.commitment),
        },
        receipts: value
            .receipts
            .iter()
            .map(runtime_commit_receipt_to_core)
            .collect(),
    }
}

fn runtime_certified_opening_to_core(value: &MevAceCertifiedOpening) -> CertifiedOpening {
    CertifiedOpening {
        opening: runtime_opening_to_core(&value.opening),
        receipts: value
            .receipts
            .iter()
            .map(runtime_open_receipt_to_core)
            .collect(),
    }
}

fn runtime_commitment_to_core(value: &MevAceCommitment) -> Commitment {
    Commitment {
        idcom: Idcom(value.idcom),
        c: Hash32(value.commitment),
        slot: Slot(value.slot),
        sig_user: Signature(value.user_signature.clone()),
    }
}

fn runtime_commit_receipt_to_core(value: &MevAceCommitReceipt) -> CommitReceipt {
    CommitReceipt {
        validator_idx: value.validator_idx,
        sig_val: Signature(value.signature.clone()),
    }
}

fn runtime_opening_to_core(value: &MevAceOpening) -> Opening {
    Opening {
        idcom: Idcom(value.idcom),
        c: Hash32(value.commitment),
        slot: Slot(value.slot),
        tx: value.transaction_wire.clone(),
        r: Nonce(value.nonce),
    }
}

fn runtime_open_receipt_to_core(value: &MevAceOpenReceipt) -> OpenReceipt {
    OpenReceipt {
        validator_idx: value.validator_idx,
        sig_val: Signature(value.signature.clone()),
    }
}

#[cfg(test)]
mod tests {
    use ace_model::account::AccountId;
    use ace_runtime::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm, TaggedSignature};
    use ace_runtime::crypto::TaggedPubkey;
    use ace_runtime::types::attestation::{Attestation, Domain, DEFAULT_CONTEXT_TAG};
    use mev_ace_core::messages::{CommitReceipt, Commitment, OpenReceipt, Opening};
    use mev_ace_core::state::{verify_proposal, SignedProposal, SlotState};
    use mev_ace_core::traits::Hasher;
    use mev_ace_core::traits::{BondedIdentityStore, IdentityRecord, SlotPhase};
    use mev_ace_core::types::{
        commit_signing_input, open_signing_input, payload_hash_input, Idcom, Nonce,
    };
    use std::collections::BTreeMap;

    use super::*;
    use crate::validator_set::Validator;

    #[test]
    fn validator_set_exposes_mev_thresholds() {
        let validators = (0..4)
            .map(|i| Validator {
                id_com: AccountId([i as u8; 32]),
                stake: 1,
                index: i,
                signing_pubkey: TaggedPubkey::ed25519([i as u8; 32]),
                capabilities: Default::default(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let snapshot = MevAceValidatorSetSnapshot::from_ace_for_leader(&set, 2);
        assert_eq!(traits::ValidatorSet::f(&snapshot), 1);
        assert_eq!(traits::ValidatorSet::q_c(&snapshot), 3);
        assert_eq!(traits::ValidatorSet::q_o(&snapshot), 3);
        assert_eq!(
            traits::ValidatorSet::validator_alg(&snapshot, 0),
            Some(AuthAlg::Ed25519)
        );
        assert_eq!(traits::ValidatorSet::leader_for(&snapshot, Slot(42)), 2);
    }

    #[test]
    fn hasher_returns_sha256_digest() {
        let hash = AceMevHasher.hash(b"abc");
        assert_eq!(
            hex::encode(hash.0),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fair_order_is_deterministic_and_preserves_identity_lanes() {
        let parent_hash = [0x42; 32];
        let txs = vec![
            tx([0x02; 32], b"a0"),
            tx([0x01; 32], b"b0"),
            tx([0x02; 32], b"a1"),
            tx([0x03; 32], b"c0"),
        ];

        let ordered_a = fair_order_transactions(parent_hash, 7, txs.clone());
        let ordered_b = fair_order_transactions(parent_hash, 7, txs.clone());
        assert_eq!(hashes(&ordered_a), hashes(&ordered_b));
        assert!(is_fair_ordered(parent_hash, 7, &ordered_a));

        let lane_two: Vec<Vec<u8>> = ordered_a
            .iter()
            .filter(|tx| tx.attestation.idcom == [0x02; 32])
            .map(|tx| tx.payload.clone())
            .collect();
        assert_eq!(lane_two, vec![b"a0".to_vec(), b"a1".to_vec()]);
    }

    #[test]
    fn fair_order_verifier_rejects_manual_reordering() {
        let parent_hash = [0x11; 32];
        let txs = vec![
            tx([0x01; 32], b"a"),
            tx([0x02; 32], b"b"),
            tx([0x03; 32], b"c"),
            tx([0x04; 32], b"d"),
        ];
        let ordered = fair_order_transactions(parent_hash, 9, txs);
        let tampered: Vec<_> = ordered.iter().cloned().rev().collect();
        assert!(is_fair_ordered(parent_hash, 9, &ordered));
        assert!(!is_fair_ordered(parent_hash, 9, &tampered));
    }

    #[test]
    fn mev_ace_slot_state_closes_with_ace_crypto() {
        let hasher = AceMevHasher;
        let vdf = AceDevVdf;
        let signatures = AceMevSignatureRegistry::default();
        let slot = Slot(17);
        let parent_hash = Hash32([0x5A; 32]);
        let validators = validator_keys(4);
        let validator_set = test_validator_set(&validators, 0);
        let user_keys = validator_keys(4);
        let mut identities = TestIdentityStore::default();
        let txs: Vec<Transaction> = user_keys
            .iter()
            .enumerate()
            .map(|(idx, key)| {
                let idcom = [idx as u8 + 10; 32];
                identities.insert(idcom, key.public_key());
                tx(idcom, format!("swap-{idx}").as_bytes())
            })
            .collect();

        let mut state = SlotState::with_max_admissible_set_size(slot, 4, 128);
        let mut prepared = Vec::new();
        for (idx, tx) in txs.iter().enumerate() {
            let tx_wire = tx.to_bytes();
            let idcom = Idcom(tx.attestation.idcom);
            let nonce = Nonce([idx as u8 + 1; 32]);
            let c = hasher.hash(&payload_hash_input(&tx_wire, &nonce, &idcom, slot));
            let commit_msg = commit_signing_input(&idcom, &c, slot);
            let cmt = Commitment {
                idcom,
                c,
                slot,
                sig_user: mev_sig(user_keys[idx].sign(&commit_msg)),
            };
            state
                .handle_commitment(cmt.clone(), &identities, &signatures)
                .expect("commitment handled");
            for (validator_idx, key) in validators.iter().enumerate() {
                let receipt = CommitReceipt {
                    validator_idx: validator_idx as u32,
                    sig_val: mev_sig(key.sign(&commit_msg)),
                };
                state
                    .handle_commit_receipt(&idcom, &c, receipt, &validator_set, &signatures)
                    .expect("commit receipt handled");
            }
            prepared.push((
                cmt,
                Opening {
                    idcom,
                    c,
                    slot,
                    tx: tx_wire,
                    r: nonce,
                },
            ));
        }

        state.advance_to(SlotPhase::Vdf).unwrap();
        state
            .compute_order(&parent_hash, &validator_set, &hasher, &vdf)
            .unwrap();
        state.advance_to(SlotPhase::Open).unwrap();

        for (cmt, opening) in &prepared {
            state
                .handle_opening(opening.clone(), &validator_set, &hasher)
                .expect("opening handled");
            let open_msg = open_signing_input(&cmt.idcom, &cmt.c, slot);
            for (validator_idx, key) in validators.iter().enumerate() {
                let receipt = OpenReceipt {
                    validator_idx: validator_idx as u32,
                    sig_val: mev_sig(key.sign(&open_msg)),
                };
                state
                    .handle_open_receipt(&cmt.idcom, &cmt.c, receipt, &validator_set, &signatures)
                    .expect("open receipt handled");
            }
        }

        state.advance_to(SlotPhase::Propose).unwrap();
        let proposal = state.build_proposal(&validator_set).unwrap();
        let sig_proposer = mev_sig(validators[0].sign(&proposal.signing_input(&hasher)));
        let signed = SignedProposal {
            proposal,
            sig_proposer,
        };
        verify_proposal(
            &signed,
            slot,
            &parent_hash,
            4,
            128,
            &identities,
            &validator_set,
            &signatures,
            &hasher,
            &vdf,
            &[],
        )
        .expect("signed MEV-ACE proposal verifies");

        assert_eq!(signed.proposal.executable_set.len(), txs.len());
        for opening in &signed.proposal.executable_set {
            Transaction::from_bytes(&opening.opening.tx)
                .expect("MEV-ACE executable opening carries an ACE transaction");
        }
    }

    fn tx(idcom: [u8; 32], payload: &[u8]) -> Transaction {
        let obj_hash = AceMevHasher.hash(payload).0;
        Transaction::new(
            payload.to_vec(),
            Attestation {
                obj_hash,
                idcom,
                domain: Domain::new(122766, 0),
                context_tag: DEFAULT_CONTEXT_TAG,
                credential: TaggedSignature {
                    algorithm: SignatureAlgorithm::Ed25519,
                    bytes: vec![0xAA; 64],
                },
            },
        )
    }

    fn hashes(txs: &[Transaction]) -> Vec<[u8; 32]> {
        txs.iter().map(|tx| tx.tx_hash()).collect()
    }

    fn mev_sig(sig: TaggedSignature) -> Signature {
        Signature(sig.bytes)
    }

    fn validator_keys(n: usize) -> Vec<LocalSigningKey> {
        (0..n)
            .map(|idx| {
                let mut seed = [0u8; 32];
                seed.fill(idx as u8 + 1);
                LocalSigningKey::from_seed(&seed, SignatureAlgorithm::Ed25519).unwrap()
            })
            .collect()
    }

    fn test_validator_set(
        keys: &[LocalSigningKey],
        leader_index: u32,
    ) -> MevAceValidatorSetSnapshot {
        let validators = keys
            .iter()
            .enumerate()
            .map(|(idx, key)| Validator {
                id_com: AccountId([idx as u8; 32]),
                stake: 1,
                index: idx as u32,
                signing_pubkey: key.public_key(),
                capabilities: Default::default(),
            })
            .collect();
        let set = crate::validator_set::ValidatorSet::new(validators);
        MevAceValidatorSetSnapshot::from_ace_for_leader(&set, leader_index)
    }

    #[derive(Default)]
    struct TestIdentityStore {
        records: BTreeMap<Idcom, IdentityRecord>,
    }

    impl TestIdentityStore {
        fn insert(&mut self, idcom: [u8; 32], pubkey: TaggedPubkey) {
            let Some(alg) = ace_alg_to_mev_alg(pubkey.algorithm) else {
                panic!("unsupported user key algorithm");
            };
            self.records.insert(
                Idcom(idcom),
                IdentityRecord {
                    idcom: Idcom(idcom),
                    vk_auth: VerificationKey(pubkey.bytes),
                    alg,
                    bond: 1,
                    activated_at: Slot(0),
                    revoked_at: None,
                },
            );
        }
    }

    impl BondedIdentityStore for TestIdentityStore {
        fn get(&self, idcom: &Idcom) -> Option<IdentityRecord> {
            self.records.get(idcom).cloned()
        }
    }
}
