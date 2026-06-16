//! Minimal capability-committee helpers for BTC/Solana ingress.

use std::collections::{BTreeMap, BTreeSet};

use ace_consensus::validator_set::{Validator, ValidatorSet};
use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_n_vm::raw_btc::verify_raw_btc_against_state;
use ace_n_vm::raw_solana::verify_raw_solana_transfer_for_slot;
use ace_runtime::crypto::sig_algo::{self, LocalSigningKey};
use ace_runtime::types::capability::{
    CommitteeApproval, CommitteeApprovalMessage, CommitteeCertificate, CommitteeDomain,
};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use sha2::{Digest, Sha256};

pub const COMMITTEE_SIZE: usize = 5;

#[derive(Default)]
pub struct ApprovalCollector {
    by_tx: BTreeMap<[u8; 32], Vec<CommitteeApprovalMessage>>,
}

impl ApprovalCollector {
    pub fn add_verified(
        &mut self,
        message: CommitteeApprovalMessage,
        validators: &ValidatorSet,
    ) -> bool {
        if !verify_approval_message(&message, validators) {
            return false;
        }

        let entry = self.by_tx.entry(message.tx_hash).or_default();
        if entry
            .iter()
            .any(|existing| existing.signer == message.signer)
        {
            return false;
        }
        entry.push(message);
        true
    }

    pub fn discard(&mut self, tx_hash: &[u8; 32]) {
        self.by_tx.remove(tx_hash);
    }

    pub fn prune_to_known<F>(&mut self, mut is_known: F)
    where
        F: FnMut(&[u8; 32]) -> bool,
    {
        self.by_tx.retain(|tx_hash, _| is_known(tx_hash));
    }

    pub fn build_certificate(
        &self,
        tx: &Transaction,
        state: &StateTree,
        validators: &ValidatorSet,
    ) -> Result<Option<CommitteeCertificate>, String> {
        let Some(domain) = tx
            .raw_chain
            .as_ref()
            .and_then(|raw_chain| raw_chain.kind.committee_domain())
        else {
            return Ok(None);
        };
        if let Some(error) = local_validation_error(state, tx) {
            return Err(error);
        }

        let tx_hash = tx.tx_hash();
        let committee = select_committee(validators, domain, &tx_hash);
        if committee.is_empty() {
            return Err(format!("no committee available for domain {:?}", domain));
        }

        let approvals = self
            .by_tx
            .get(&tx_hash)
            .into_iter()
            .flat_map(|messages| messages.iter())
            .filter(|message| message.domain == domain)
            .filter(|message| {
                committee
                    .iter()
                    .any(|validator| validator.signing_pubkey == message.signer)
            })
            .map(|message| CommitteeApproval {
                signer: message.signer.clone(),
                signature: message.signature.clone(),
            })
            .collect::<Vec<_>>();

        if approvals.len() < committee_threshold(committee.len()) {
            return Ok(None);
        }

        Ok(Some(CommitteeCertificate {
            domain,
            tx_hash,
            approvals,
        }))
    }
}

fn verify_approval_message(message: &CommitteeApprovalMessage, validators: &ValidatorSet) -> bool {
    let committee = select_committee(validators, message.domain, &message.tx_hash);
    if !committee
        .iter()
        .any(|validator| validator.signing_pubkey == message.signer)
    {
        return false;
    }

    let signing_message =
        CommitteeApprovalMessage::signing_message(message.domain, &message.tx_hash);
    sig_algo::verify_signature(&message.signer, &signing_message, &message.signature)
}

pub fn sign_local_approval(
    tx: &Transaction,
    state: &StateTree,
    local_id: &AccountId,
    signing_key: &LocalSigningKey,
    validators: &ValidatorSet,
) -> Option<CommitteeApprovalMessage> {
    let domain = tx
        .raw_chain
        .as_ref()
        .and_then(|raw_chain| raw_chain.kind.committee_domain())?;
    if local_validation_error(state, tx).is_some() {
        return None;
    }
    let tx_hash = tx.tx_hash();
    let committee = select_committee(validators, domain, &tx_hash);
    if !committee
        .iter()
        .any(|validator| validator.id_com == *local_id)
    {
        return None;
    }

    let signing_message = CommitteeApprovalMessage::signing_message(domain, &tx_hash);
    let signature = signing_key.sign(&signing_message);
    let signer_pubkey = signing_key.public_key();
    Some(CommitteeApprovalMessage {
        domain,
        tx_hash,
        signer: signer_pubkey,
        signature,
    })
}

pub fn verify_certificate(
    tx: &Transaction,
    state: &StateTree,
    validators: &ValidatorSet,
) -> Result<(), String> {
    let Some(raw_chain) = &tx.raw_chain else {
        return Ok(());
    };
    let Some(domain) = raw_chain.kind.committee_domain() else {
        return Ok(());
    };
    if let Some(error) = local_validation_error(state, tx) {
        return Err(error);
    }
    let Some(certificate) = &raw_chain.committee_certificate else {
        return Err(format!(
            "raw {:?} transaction is missing a committee certificate",
            raw_chain.kind
        ));
    };

    let tx_hash = tx.tx_hash();
    if certificate.domain != domain {
        return Err("committee certificate domain mismatch".into());
    }
    if certificate.tx_hash != tx_hash {
        return Err("committee certificate tx_hash mismatch".into());
    }

    let committee = select_committee(validators, domain, &tx_hash);
    if committee.is_empty() {
        return Err(format!("no committee available for domain {:?}", domain));
    }
    let required = committee_threshold(committee.len());
    let mut seen = BTreeSet::new();
    let signing_message = CommitteeApprovalMessage::signing_message(domain, &tx_hash);
    let mut valid = 0usize;

    for approval in &certificate.approvals {
        if !seen.insert(&approval.signer) {
            continue;
        }

        if !committee
            .iter()
            .any(|validator| validator.signing_pubkey == approval.signer)
        {
            continue;
        }

        if sig_algo::verify_signature(&approval.signer, &signing_message, &approval.signature) {
            valid += 1;
        }
    }

    if valid < required {
        return Err(format!(
            "committee certificate threshold not met: have {}, need {}",
            valid, required
        ));
    }

    Ok(())
}

fn local_validation_error(state: &StateTree, tx: &Transaction) -> Option<String> {
    let raw_chain = tx.raw_chain.as_ref()?;
    match raw_chain.kind {
        RawChainKind::Evm => None,
        RawChainKind::Solana => match verify_raw_solana_transfer_for_slot(
            state,
            &raw_chain.raw_bytes,
            tx.attestation.domain.chain_id,
            tx.attestation.domain.slot as u64,
        ) {
            Ok(verified) if tx.attestation.idcom == verified.sender_idcom => (tx.payload
                != verified.canonical_payload)
                .then_some("solana raw payload does not match canonical reconstruction".into()),
            Ok(_) => Some("solana attestation idcom does not match recovered signer".into()),
            Err(error) => Some(error.to_string()),
        },
        RawChainKind::Btc => match verify_raw_btc_against_state(state, &raw_chain.raw_bytes) {
            Ok(verified) if tx.attestation.idcom == verified.sender_idcom => (tx.payload
                != verified.payload)
                .then_some("btc raw payload does not match canonical reconstruction".into()),
            Ok(_) => Some("btc attestation idcom does not match recovered signer".into()),
            Err(error) => Some(error.to_string()),
        },
        RawChainKind::Tron => None,
    }
}

pub fn select_committee(
    validators: &ValidatorSet,
    domain: CommitteeDomain,
    tx_hash: &[u8; 32],
) -> Vec<Validator> {
    let mut eligible = validators.validators_for_domain(domain);
    eligible.sort_by_key(|validator| {
        let mut hasher = Sha256::new();
        hasher.update(b"ACE-COMMITTEE-V1");
        hasher.update([domain.tag()]);
        hasher.update(tx_hash);
        hasher.update(validator.id_com.0);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hasher.finalize());
        digest
    });
    eligible.truncate(COMMITTEE_SIZE.min(eligible.len()));
    eligible
}

pub fn committee_threshold(size: usize) -> usize {
    match size {
        0 => 0,
        1 => 1,
        _ => (2 * size + 2) / 3, // BFT supermajority: ceil(2n/3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_model::account::Account;
    use ace_n_vm::raw_solana::{derive_ace_solana_blockhash, verify_raw_solana_transfer_for_slot};
    use ace_runtime::crypto::{legacy_idcom_solana, TaggedSignature};
    use ace_runtime::types::attestation::{Attestation, Domain};
    use ace_runtime::types::capability::ValidatorCapabilities;
    use ed25519_dalek::{Signer, SigningKey};

    fn validator(byte: u8, btc: bool, solana: bool) -> (Validator, LocalSigningKey) {
        let seed = [byte; 32];
        let signing_key = LocalSigningKey::from_seed(
            &seed,
            ace_runtime::crypto::sig_algo::SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        (
            Validator {
                id_com: AccountId([byte; 32]),
                stake: 100,
                index: byte as u32,
                signing_pubkey: signing_key.public_key(),
                capabilities: ValidatorCapabilities {
                    evm_core: true,
                    btc_payments: btc,
                    solana_light: solana,
                },
            },
            signing_key,
        )
    }

    fn encode_compact_u16(value: u16) -> Vec<u8> {
        if value < 0x80 {
            return vec![value as u8];
        }
        if value < 0x4000 {
            return vec![((value & 0x7f) as u8) | 0x80, ((value >> 7) & 0x7f) as u8];
        }
        vec![
            ((value & 0x7f) as u8) | 0x80,
            (((value >> 7) & 0x7f) as u8) | 0x80,
            ((value >> 14) & 0x03) as u8,
        ]
    }

    fn build_supported_transfer_tx(
        signer: &SigningKey,
        recipient: [u8; 32],
        recent_blockhash: [u8; 32],
        amount: u64,
    ) -> Vec<u8> {
        let mut message = vec![1, 0, 1];
        message.extend_from_slice(&encode_compact_u16(3));
        message.extend_from_slice(&signer.verifying_key().to_bytes());
        message.extend_from_slice(&recipient);
        message.extend_from_slice(&[0u8; 32]);
        message.extend_from_slice(&recent_blockhash);
        message.extend_from_slice(&encode_compact_u16(1));
        message.push(2);
        message.extend_from_slice(&encode_compact_u16(2));
        message.push(0);
        message.push(1);
        message.extend_from_slice(&encode_compact_u16(12));
        message.extend_from_slice(&2u32.to_le_bytes());
        message.extend_from_slice(&amount.to_le_bytes());

        let mut tx = encode_compact_u16(1);
        tx.extend_from_slice(&signer.sign(&message).to_bytes());
        tx.extend_from_slice(&message);
        tx
    }

    fn valid_solana_fixture() -> (StateTree, Transaction) {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let recipient = [0x55u8; 32];
        let chain_id = 1;
        let slot = 7;
        let raw = build_supported_transfer_tx(
            &signer,
            recipient,
            derive_ace_solana_blockhash(chain_id, slot),
            123,
        );
        let sender_idcom = legacy_idcom_solana(&signer.verifying_key().to_bytes());
        let sender = AccountId::from_bytes(sender_idcom);
        let mut state = StateTree::new();
        state.insert(Account::new(sender));
        let verified = verify_raw_solana_transfer_for_slot(&state, &raw, chain_id, slot)
            .expect("supported solana transfer should validate");

        let tx = Transaction::with_raw_chain(
            verified.canonical_payload.clone(),
            Attestation {
                obj_hash: [0x11; 32],
                idcom: verified.sender_idcom,
                domain: Domain::new(chain_id, slot as u32),
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
            RawChainKind::Solana,
            raw,
        );
        (state, tx)
    }

    #[test]
    fn solana_raw_transactions_require_committee() {
        let (v1, k1) = validator(1, false, true);
        let (v2, k2) = validator(2, false, true);
        let (v3, _k3) = validator(3, false, true);
        let validators = ValidatorSet::new(vec![v1.clone(), v2.clone(), v3.clone()]);
        let (state, tx) = valid_solana_fixture();

        assert!(sign_local_approval(&tx, &state, &v1.id_com, &k1, &validators).is_some());
        assert!(sign_local_approval(&tx, &state, &v2.id_com, &k2, &validators).is_some());
        verify_certificate(&tx, &state, &validators)
            .expect_err("solana raw tx without certificate should fail verification");
    }

    #[test]
    fn solana_raw_transactions_produce_committee_certificates() {
        let (v1, k1) = validator(1, false, true);
        let (v2, k2) = validator(2, false, true);
        let validators = ValidatorSet::new(vec![v1.clone(), v2.clone()]);
        let (state, tx) = valid_solana_fixture();

        let domain = CommitteeDomain::SolanaLight;
        let tx_hash = tx.tx_hash();
        let signing_message = CommitteeApprovalMessage::signing_message(domain, &tx_hash);
        let message1 = CommitteeApprovalMessage {
            domain,
            tx_hash,
            signer: k1.public_key(),
            signature: k1.sign(&signing_message),
        };
        let message2 = CommitteeApprovalMessage {
            domain,
            tx_hash,
            signer: k2.public_key(),
            signature: k2.sign(&signing_message),
        };

        let mut collector = ApprovalCollector::default();
        assert!(collector.add_verified(message1, &validators));
        assert!(collector.add_verified(message2, &validators));
        let cert = collector
            .build_certificate(&tx, &state, &validators)
            .expect("certificate build should succeed")
            .expect("solana raw tx should produce a committee certificate");

        let mut certified_tx = tx.clone();
        certified_tx.attach_committee_certificate(cert);
        verify_certificate(&certified_tx, &state, &validators)
            .expect("solana raw tx with valid certificate should pass verification");
    }

    #[test]
    fn btc_raw_transactions_require_committee() {
        let (v1, k1) = validator(1, true, false);
        let validators = ValidatorSet::new(vec![v1.clone()]);
        let state = StateTree::new();
        let tx = Transaction::with_raw_chain(
            vec![0x31, 0x01],
            Attestation {
                obj_hash: [0x11; 32],
                idcom: [0x22; 32],
                domain: Domain::new(1, 7),
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
            RawChainKind::Btc,
            vec![0x01, 0x02, 0x03],
        );

        assert!(sign_local_approval(&tx, &state, &v1.id_com, &k1, &validators).is_none());
        verify_certificate(&tx, &state, &validators)
            .expect_err("btc raw tx without certificate should fail verification");
    }
}
