//! Transaction types for ACE Runtime.
//!
//! A transaction in ACE Runtime consists of a payload and an attestation.
//! Unlike traditional blockchains, there is no standalone signature field:
//! authorization is carried inside the attestation object.
//!
//! When [`raw_chain`](Transaction::raw_chain) is set, the tx originated from a
//! standard chain format (EVM/Solana/BTC); the runtime verifies the chain's
//! native signature and maps the signer to a legacy idcom instead of ACE attestation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::attestation::{Attestation, Domain};
use super::capability::{CommitteeCertificate, CommitteeDomain};

/// Chain kind for raw standard-format transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RawChainKind {
    Evm = 1,
    Solana = 2,
    Btc = 3,
    Tron = 4,
}

impl RawChainKind {
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(RawChainKind::Evm),
            2 => Some(RawChainKind::Solana),
            3 => Some(RawChainKind::Btc),
            4 => Some(RawChainKind::Tron),
            _ => None,
        }
    }
    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn committee_domain(self) -> Option<CommitteeDomain> {
        match self {
            RawChainKind::Evm => None,
            RawChainKind::Solana => Some(CommitteeDomain::SolanaLight),
            RawChainKind::Btc => Some(CommitteeDomain::BtcPayments),
            RawChainKind::Tron => None,
        }
    }
}

/// Raw signed transaction bytes from a standard chain (EVM EIP-155, Solana, Bitcoin).
/// Used when the tx was submitted via `ace_sendRawTransaction`; verification uses
/// the chain's native signature (ecrecover / Ed25519 / ECDSA) instead of ACE credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawChainPayload {
    pub kind: RawChainKind,
    pub raw_bytes: Vec<u8>,
    #[serde(default)]
    pub committee_certificate: Option<CommitteeCertificate>,
}

/// ZK-ACE per-transaction authorization proof.
///
/// Replaces raw ML-DSA-44 signature verification with a ZK proof that proves
/// knowledge of the Root Entropy Value (REV) behind the identity commitment.
/// Verification cost is constant and independent of the underlying signature
/// algorithm, eliminating the PQC performance penalty on hot paths.
///
/// The proof is bound to (id_com, tx_hash, domain, target, rp_com) and uses
/// NonceRegistry replay-prevention (rp_com = Poseidon2(id_com || nonce)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkAuth {
    /// Circle STARK proof bytes (serialized ZK-ACE proof).
    pub proof: Vec<u8>,
    /// Derivation-target hash: Poseidon2(Derive(REV, Ctx)).
    /// Binds the proof to a specific derived key context.
    pub target: [u8; 32],
    /// Replay-prevention commitment: Poseidon2(id_com || nonce).
    pub rp_com: [u8; 32],
    /// Nonce witness used to compute rp_com. Replay is enforced by the on-chain
    /// ZK replay registry, not by the account sequence nonce.
    pub nonce: u64,
}

/// A transaction in the ACE Runtime.
///
/// Contains the raw payload and its attestation. Optionally carries the original
/// raw chain bytes when the tx was submitted as a standard-format (EVM/Solana/BTC) tx.
/// When `zk_auth` is set, authorization is via ZK proof instead of raw credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Raw transaction payload (instructions, account references, etc.).
    pub payload: Vec<u8>,
    /// Attestation binding payload to identity and domain.
    pub attestation: Attestation,
    /// When set, this tx was submitted as a standard-format tx; verify using chain native sig.
    #[serde(default)]
    pub raw_chain: Option<RawChainPayload>,
    /// When set, this tx uses ZK-ACE authorization instead of a raw ML-DSA-44/Ed25519
    /// credential. The `attestation.credential` field is an empty placeholder; the ZK
    /// proof carries the actual authorization.
    #[serde(default)]
    pub zk_auth: Option<ZkAuth>,
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

impl Transaction {
    /// Create a new transaction with the given payload and attestation.
    pub fn new(payload: Vec<u8>, attestation: Attestation) -> Self {
        Self {
            payload,
            attestation,
            raw_chain: None,
            zk_auth: None,
        }
    }

    /// Create a transaction that carries raw chain bytes (EVM/Solana/BTC standard format).
    pub fn with_raw_chain(
        payload: Vec<u8>,
        attestation: Attestation,
        kind: RawChainKind,
        raw_bytes: Vec<u8>,
    ) -> Self {
        Self {
            payload,
            attestation,
            raw_chain: Some(RawChainPayload {
                kind,
                raw_bytes,
                committee_certificate: None,
            }),
            zk_auth: None,
        }
    }

    /// Attach a committee certificate to the raw-chain wrapper in-place.
    pub fn attach_committee_certificate(&mut self, certificate: CommitteeCertificate) {
        if let Some(raw_chain) = &mut self.raw_chain {
            raw_chain.committee_certificate = Some(certificate);
        }
    }

    /// True if this tx is authorized by a chain-native signature (EVM/Solana/BTC) instead of ACE attestation.
    pub fn is_raw_chain(&self) -> bool {
        self.raw_chain.is_some()
    }

    /// True if this tx uses ZK-ACE per-transaction authorization instead of a raw credential.
    pub fn is_zk_auth(&self) -> bool {
        self.zk_auth.is_some()
    }

    /// Approximate wire size in bytes.
    pub fn wire_size(&self) -> usize {
        let base = self.payload.len() + self.attestation.wire_size();
        if let Some(r) = &self.raw_chain {
            let cert_size = r
                .committee_certificate
                .as_ref()
                .map(|cert| 4 + cert.wire_size())
                .unwrap_or(0);
            base + 1 + 4 + r.raw_bytes.len() + 1 + cert_size
        } else if let Some(zk) = &self.zk_auth {
            // 1 (marker) + 4 (proof_len) + proof + target(32) + rp_com(32) + nonce(8)
            base + 1 + 4 + zk.proof.len() + 32 + 32 + 8
        } else {
            base
        }
    }

    /// Compute the canonical transaction hash used by the mempool, RPC, and
    /// committee approval flow.
    ///
    /// The hash covers: payload_len(4 LE) || payload || attestation_identity(88)
    /// || [raw_chain_kind(1) || raw_chain_bytes_len(4 LE) || raw_chain_bytes]?.
    ///
    /// Design choices:
    /// - Credential excluded: a gossip-relayed tx whose ML-DSA-44 credential has
    ///   been stripped to an empty placeholder (AR-ACE relay path) produces the
    ///   same hash as the full-credential copy, enabling correct dedup.
    /// - Committee certificate excluded: a leader can attach it after mempool
    ///   admission without changing the tx identifier committee members signed.
    /// - raw_chain included: two raw-chain txs with identical ACE payload but
    ///   different raw_bytes (e.g. malleated Solana signatures) must have
    ///   distinct hashes so committee certificates cannot be cross-applied.
    pub fn tx_hash(&self) -> [u8; 32] {
        let payload_len = self.payload.len() as u32;
        let id_bytes = self.attestation.to_identity_bytes();
        let raw_chain_extra = self
            .raw_chain
            .as_ref()
            .map(|r| 1 + 4 + r.raw_bytes.len())
            .unwrap_or(0);
        let mut buf = Vec::with_capacity(4 + self.payload.len() + id_bytes.len() + raw_chain_extra);
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&id_bytes);
        if let Some(r) = &self.raw_chain {
            buf.push(r.kind.tag());
            buf.extend_from_slice(&(r.raw_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&r.raw_bytes);
        }
        sha256_bytes(&buf)
    }

    /// Return whether this transaction's credential has been stripped for
    /// gossip relay (AR-ACE relay path).
    ///
    /// A stripped tx has algorithm = ML-DSA-44 but empty credential bytes.
    /// Only nodes holding the full-credential form can propose or execute the tx.
    /// Other nodes receive the stripped form via gossip and keep it solely for
    /// compact-block dedup and reconstruction; on wire_hash mismatch a validator
    /// fetches the full tx via tx_fetch and executes that.  A node that later
    /// receives the full-credential variant (e.g. via tx_fetch) and upgrades the
    /// mempool entry becomes eligible to propose it as well.
    /// Stripped txs must never be executed directly — they carry no verifiable
    /// authorization.
    pub fn is_credential_stripped(&self) -> bool {
        use crate::crypto::sig_algo::SignatureAlgorithm;
        // ZK-ACE txs carry an empty credential placeholder intentionally — they
        // are NOT gossip-stripped; the ZK proof in `zk_auth` is the real auth.
        if self.zk_auth.is_some() {
            return false;
        }
        self.attestation.credential.algorithm == SignatureAlgorithm::MlDsa44
            && self.attestation.credential.bytes.is_empty()
    }

    /// Return a copy of this transaction with the ML-DSA-44 auth credential
    /// stripped to an empty-bytes placeholder for gossip broadcast (AR-ACE
    /// relay path).
    ///
    /// ML-DSA-44 signatures are 2,420 bytes each; stripping them from gossip
    /// messages removes the dominant per-transaction bandwidth cost on the
    /// relay path.  The stripped tx carries algorithm = ML-DSA-44 with zero
    /// credential bytes (3 wire bytes: alg_tag + len=0) so that:
    ///   - The algorithm tag is preserved — `auth_key_for_algorithm` still
    ///     resolves to the correct ML-DSA-44 public key if the tx is ever
    ///     inspected before execution.
    ///   - `Transaction::is_credential_stripped()` detects the placeholder
    ///     unambiguously (algorithm = MlDsa44 ∧ bytes empty).
    ///   - `TaggedSignature::is_well_formed()` returns `false`, so
    ///     `verify_signature` refuses the placeholder upfront — execution
    ///     of a stripped tx is impossible even if the mempool filter is
    ///     bypassed (defence in depth).
    ///   - Wire and serde deserialization both accept zero-length ML-DSA-44
    ///     as a special case, so stripped txs survive a bincode round-trip
    ///     through gossipsub.
    ///
    /// The full credential is retained in the local mempool.  Non-source
    /// nodes that receive stripped txs cannot propose blocks containing them
    /// (`Mempool::ready_transactions` excludes stripped entries); they will
    /// use stripped txs only for mempool dedup and compact-block
    /// reconstruction.  When a non-source node fetches the full tx via the
    /// compact-block tx-fetch protocol, the mempool entry is upgraded to the
    /// full version (see `Mempool::insert_inner`).
    ///
    /// Ed25519 and Secp256k1 credentials are already compact (64 bytes) and
    /// are left unchanged.
    pub fn stripped_for_gossip(&self) -> Self {
        use crate::crypto::sig_algo::{SignatureAlgorithm, TaggedSignature};
        // Never strip auth-key bootstrap txs (SetAuthPubkey=0x03, AddAuthKey=0x04).
        // These must carry the full credential on the wire because the executing
        // node cannot resolve the verify_key from on-chain state yet — the new
        // key lives in the payload and must be self-verified by the tx credential.
        // Bootstrap txs are rare (once per account per algorithm), so keeping the
        // full 2,420-byte ML-DSA-44 signature here has negligible bandwidth impact.
        if matches!(self.payload.first(), Some(0x03) | Some(0x04)) {
            return self.clone();
        }
        if self.attestation.credential.algorithm == SignatureAlgorithm::MlDsa44 {
            let mut stripped = self.clone();
            stripped.attestation.credential = TaggedSignature::ml_dsa_44_stripped();
            stripped
        } else {
            // Ed25519 / Secp256k1 are already compact — return as-is.
            // (The branch below exists so callers can always use the return value.)
            self.clone()
        }
    }

    /// Compute the hash of the exact wire bytes committed by `tx_merkle_root`.
    pub fn wire_hash(&self) -> [u8; 32] {
        sha256_bytes(&self.to_bytes())
    }

    /// Get the domain from the embedded attestation.
    pub fn domain(&self) -> Domain {
        self.attestation.domain
    }

    /// Get the identity commitment from the embedded attestation.
    pub fn idcom(&self) -> &[u8; 32] {
        &self.attestation.idcom
    }

    /// Serialize transaction to bytes: payload_len(4 LE) || payload || attestation [|| raw_chain].
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_bytes(true)
    }

    /// Serialize transaction bytes excluding auxiliary committee certificates.
    ///
    /// NOTE: No longer the basis of the canonical transaction hash.  `tx_hash()`
    /// now uses `attestation.to_identity_bytes()` (credential-independent) so
    /// that PQC credentials can be stripped for gossip without changing identity.
    /// This method is retained for external tooling that may need the credential-
    /// inclusive-but-certificate-excluded wire form.
    pub fn to_hash_bytes(&self) -> Vec<u8> {
        self.encode_bytes(false)
    }

    fn encode_bytes(&self, include_committee_certificate: bool) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.attestation.to_bytes());
        if let Some(r) = &self.raw_chain {
            buf.push(r.kind.tag());
            buf.extend_from_slice(&(r.raw_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&r.raw_bytes);
            if include_committee_certificate {
                if let Some(cert) = &r.committee_certificate {
                    let cert_bytes = cert.to_bytes();
                    buf.push(1);
                    buf.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&cert_bytes);
                } else {
                    buf.push(0);
                }
            }
        } else if let Some(zk) = &self.zk_auth {
            // 0xFF marker distinguishes zk_auth from RawChainKind tags (1–4).
            buf.push(0xFF);
            buf.extend_from_slice(&(zk.proof.len() as u32).to_le_bytes());
            buf.extend_from_slice(&zk.proof);
            buf.extend_from_slice(&zk.target);
            buf.extend_from_slice(&zk.rp_com);
            buf.extend_from_slice(&zk.nonce.to_le_bytes());
        }
        buf
    }

    /// Deserialize transaction from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 4 {
            return Err("transaction data too short");
        }
        let payload_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        const MAX_PAYLOAD_SIZE: usize = 65_536; // 64 KB, matches mempool config
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err("transaction payload exceeds maximum size");
        }
        let attest_start = 4 + payload_len;
        if data.len() < attest_start + 3 {
            return Err("transaction data too short for payload + attestation");
        }
        let payload = data[4..attest_start].to_vec();
        let attest_consumed = Attestation::bytes_consumed(&data[attest_start..])?;
        let attestation =
            Attestation::from_bytes(&data[attest_start..attest_start + attest_consumed])?;
        let base_end = attest_start + attest_consumed;

        // Check for zk_auth extension (0xFF marker) before attempting raw_chain parse.
        let zk_auth = if data.len() > base_end && data[base_end] == 0xFF {
            let zk_start = base_end + 1;
            if data.len() < zk_start + 4 {
                return Err("zk_auth proof length truncated");
            }
            const MAX_ZK_PROOF_LEN: usize = 65_536;
            let proof_len = u32::from_le_bytes([
                data[zk_start],
                data[zk_start + 1],
                data[zk_start + 2],
                data[zk_start + 3],
            ]) as usize;
            if proof_len > MAX_ZK_PROOF_LEN {
                return Err("zk_auth proof_len exceeds maximum allowed size");
            }
            let payload_start = zk_start + 4;
            // proof + target(32) + rp_com(32) + nonce(8)
            if data.len() != payload_start + proof_len + 32 + 32 + 8 {
                return Err("zk_auth body length mismatch");
            }
            let proof = data[payload_start..payload_start + proof_len].to_vec();
            let target_start = payload_start + proof_len;
            let mut target = [0u8; 32];
            target.copy_from_slice(&data[target_start..target_start + 32]);
            let rp_start = target_start + 32;
            let mut rp_com = [0u8; 32];
            rp_com.copy_from_slice(&data[rp_start..rp_start + 32]);
            let nonce_start = rp_start + 32;
            let nonce = u64::from_le_bytes([
                data[nonce_start],
                data[nonce_start + 1],
                data[nonce_start + 2],
                data[nonce_start + 3],
                data[nonce_start + 4],
                data[nonce_start + 5],
                data[nonce_start + 6],
                data[nonce_start + 7],
            ]);
            Some(ZkAuth {
                proof,
                target,
                rp_com,
                nonce,
            })
        } else {
            None
        };

        let raw_chain = if zk_auth.is_none() && data.len() > base_end {
            let tag = data[base_end];
            let kind = RawChainKind::from_tag(tag).ok_or("invalid raw_chain tag")?;
            if data.len() < base_end + 1 + 4 {
                return Err("transaction raw_chain length truncated");
            }
            let raw_len = u32::from_le_bytes([
                data[base_end + 1],
                data[base_end + 2],
                data[base_end + 3],
                data[base_end + 4],
            ]) as usize;
            if data.len() < base_end + 1 + 4 + raw_len {
                return Err("transaction raw_chain bytes truncated");
            }
            let raw_bytes = data[base_end + 5..base_end + 5 + raw_len].to_vec();
            let mut raw_chain = RawChainPayload {
                kind,
                raw_bytes,
                committee_certificate: None,
            };
            let raw_end = base_end + 5 + raw_len;
            if data.len() > raw_end {
                let cert_present = data[raw_end];
                if cert_present > 1 {
                    return Err("invalid raw_chain committee_certificate tag");
                }
                if cert_present == 1 {
                    if data.len() < raw_end + 1 + 4 {
                        return Err("transaction committee_certificate length truncated");
                    }
                    let cert_len = u32::from_le_bytes([
                        data[raw_end + 1],
                        data[raw_end + 2],
                        data[raw_end + 3],
                        data[raw_end + 4],
                    ]) as usize;
                    if data.len() != raw_end + 1 + 4 + cert_len {
                        return Err("transaction committee_certificate bytes truncated");
                    }
                    raw_chain.committee_certificate = Some(
                        CommitteeCertificate::from_bytes(
                            &data[raw_end + 5..raw_end + 5 + cert_len],
                        )
                        .map_err(|_| "invalid committee_certificate")?,
                    );
                } else if data.len() != raw_end + 1 {
                    return Err("unexpected trailing transaction bytes");
                }
            }
            Some(raw_chain)
        } else {
            None
        };
        Ok(Self {
            payload,
            attestation,
            raw_chain,
            zk_auth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sig_algo::{TaggedPubkey, TaggedSignature};
    use crate::types::capability::CommitteeApproval;

    fn make_attestation() -> Attestation {
        Attestation {
            obj_hash: [0x11; 32],
            idcom: [0x22; 32],
            domain: Domain::new(1, 9),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        }
    }

    fn raw_btc_tx() -> Transaction {
        Transaction::with_raw_chain(
            vec![0x31, 0xAB],
            make_attestation(),
            RawChainKind::Btc,
            vec![0x01, 0x02, 0x03],
        )
    }

    #[test]
    fn attestation_roundtrip() {
        let att = make_attestation();
        let bytes = att.to_bytes();
        let decoded = Attestation::from_bytes(&bytes).expect("attestation must decode");
        assert_eq!(decoded, att);
    }

    #[test]
    fn transaction_roundtrip() {
        let tx = Transaction::new(vec![1, 2, 3], make_attestation());
        let bytes = tx.to_bytes();
        let decoded = Transaction::from_bytes(&bytes).expect("tx must decode");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn canonical_tx_hash_ignores_committee_certificate() {
        let tx = raw_btc_tx();
        let tx_hash = tx.tx_hash();

        let mut certified_tx = tx.clone();
        certified_tx.attach_committee_certificate(CommitteeCertificate {
            domain: CommitteeDomain::BtcPayments,
            tx_hash,
            approvals: vec![CommitteeApproval {
                signer: TaggedPubkey::ed25519([0x33; 32]),
                signature: TaggedSignature::ed25519([0x44; 64]),
            }],
        });

        assert_eq!(tx_hash, certified_tx.tx_hash());
        assert_ne!(tx.to_bytes(), certified_tx.to_bytes());
        assert_ne!(tx.wire_hash(), certified_tx.wire_hash());
    }

    #[test]
    fn transaction_round_trips_with_committee_certificate() {
        let mut tx = raw_btc_tx();
        tx.attach_committee_certificate(CommitteeCertificate {
            domain: CommitteeDomain::BtcPayments,
            tx_hash: tx.tx_hash(),
            approvals: vec![CommitteeApproval {
                signer: TaggedPubkey::ed25519([0x55; 32]),
                signature: TaggedSignature::ed25519([0x66; 64]),
            }],
        });

        let decoded = Transaction::from_bytes(&tx.to_bytes()).expect("transaction must decode");
        assert_eq!(decoded, tx);
        assert_eq!(decoded.tx_hash(), tx.tx_hash());
    }

    // ------------------------------------------------------------------
    // AR-ACE relay path: stripped_for_gossip + stripped placeholder tests.
    // ------------------------------------------------------------------

    fn ml_dsa_44_tx() -> Transaction {
        // Deterministic but non-zero body so the stripped placeholder is
        // clearly distinguishable from the full credential in wire form.
        let att = Attestation {
            obj_hash: [0x77; 32],
            idcom: [0x88; 32],
            domain: Domain::new(42, 7),
            context_tag: [0x03; 16],
            credential: TaggedSignature::ml_dsa_44(vec![0xAA; 2420]),
        };
        Transaction::new(b"pqc-payload".to_vec(), att)
    }

    #[test]
    fn stripped_for_gossip_does_not_panic_on_ml_dsa_44() {
        // Regression guard: prior revision used `TaggedSignature::ml_dsa_44(vec![])`
        // which asserted bytes.len() == 2420 and panicked on every PQC tx broadcast.
        let tx = ml_dsa_44_tx();
        let stripped = tx.stripped_for_gossip();
        assert!(stripped.is_credential_stripped());
    }

    #[test]
    fn stripped_for_gossip_is_noop_for_compact_algorithms() {
        // Ed25519 credentials are already compact; stripping must return an
        // equal transaction (no credential replacement).
        let tx = Transaction::new(b"ed25519-payload".to_vec(), make_attestation());
        let stripped = tx.stripped_for_gossip();
        assert_eq!(stripped, tx);
        assert!(!stripped.is_credential_stripped());
    }

    #[test]
    fn stripped_preserves_tx_hash_but_changes_wire_bytes() {
        let tx = ml_dsa_44_tx();
        let stripped = tx.stripped_for_gossip();

        // tx_hash is credential-independent → stable across the relay hop.
        assert_eq!(stripped.tx_hash(), tx.tx_hash());
        // wire form differs (full credential vs 3-byte placeholder).
        assert_ne!(stripped.to_bytes(), tx.to_bytes());
        assert_ne!(stripped.wire_hash(), tx.wire_hash());
    }

    #[test]
    fn stripped_tx_round_trips_through_to_bytes() {
        let stripped = ml_dsa_44_tx().stripped_for_gossip();
        let bytes = stripped.to_bytes();
        let decoded = Transaction::from_bytes(&bytes).expect("stripped tx must decode");
        assert_eq!(decoded, stripped);
        assert!(decoded.is_credential_stripped());
    }

    #[test]
    fn stripped_placeholder_is_not_well_formed() {
        // Defence-in-depth: even if the mempool filter is bypassed,
        // `verify_signature` refuses the placeholder at the well-formed gate.
        let stripped = ml_dsa_44_tx().stripped_for_gossip();
        assert!(!stripped.attestation.credential.is_well_formed());
    }
}
