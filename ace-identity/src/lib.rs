pub mod ace_chain;

use std::error::Error;

pub use acegf::{
    EncryptedPayload as AceEncryptedPayload, GeneratedWallet, Session, WalletPublicView, ACEGF,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

const ACE_CHAIN_IDCOM_INFO: &[u8] = b"ACE-CHAIN-IDCOM-V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AceChainIdentity {
    pub idcom: [u8; 32],
    pub auth_pubkey: [u8; 32],
    pub xidentity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AceChainAttestation {
    pub obj_hash: [u8; 32],
    pub idcom: [u8; 32],
    pub domain: [u8; 8],
    #[serde(
        serialize_with = "serialize_signature",
        deserialize_with = "deserialize_signature"
    )]
    pub credential: [u8; 64],
}

impl AceChainAttestation {
    pub const WIRE_SIZE: usize = 32 + 32 + 8 + 64;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.obj_hash);
        buf.extend_from_slice(&self.idcom);
        buf.extend_from_slice(&self.domain);
        buf.extend_from_slice(&self.credential);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != Self::WIRE_SIZE {
            return Err("invalid attestation length");
        }

        let mut obj_hash = [0u8; 32];
        obj_hash.copy_from_slice(&data[0..32]);

        let mut idcom = [0u8; 32];
        idcom.copy_from_slice(&data[32..64]);

        let mut domain = [0u8; 8];
        domain.copy_from_slice(&data[64..72]);

        let mut credential = [0u8; 64];
        credential.copy_from_slice(&data[72..136]);

        Ok(Self {
            obj_hash,
            idcom,
            domain,
            credential,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityPublicProfile {
    pub chain: AceChainIdentity,
    pub wallet: WalletPublicView,
}

pub struct LoadedIdentity {
    session: Session,
    chain_id: u32,
    context: Vec<u8>,
    public: IdentityPublicProfile,
}

impl std::fmt::Debug for LoadedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedIdentity")
            .field("chain_id", &self.chain_id)
            .field("public", &self.public)
            .finish()
    }
}

impl LoadedIdentity {
    pub fn open(
        mnemonic: &str,
        passphrase: &str,
        secondary_passphrase: Option<&str>,
        chain_id: u32,
        context: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        let session = ACEGF::open_session(mnemonic, passphrase, secondary_passphrase)?;
        let public = IdentityPublicProfile {
            chain: AceChainIdentity {
                idcom: compute_chain_idcom(&session.auth_pubkey(), chain_id, context),
                auth_pubkey: session.auth_pubkey(),
                xidentity: session.xidentity().to_owned(),
            },
            wallet: session.wallet().clone(),
        };

        Ok(Self {
            session,
            chain_id,
            context: context.to_vec(),
            public,
        })
    }

    pub fn public_profile(&self) -> &IdentityPublicProfile {
        &self.public
    }

    pub fn chain_identity(&self) -> &AceChainIdentity {
        &self.public.chain
    }

    pub fn wallet(&self) -> &WalletPublicView {
        &self.public.wallet
    }

    pub fn xidentity(&self) -> &str {
        self.session.xidentity()
    }

    pub fn auth_pubkey(&self) -> [u8; 32] {
        self.session.auth_pubkey()
    }

    pub fn sign_identity_message(&self, message: &[u8]) -> [u8; 64] {
        self.session.sign_message(message)
    }

    pub fn verify_identity_message(
        auth_pubkey: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        Session::verify_message(auth_pubkey, message, signature)
    }

    pub fn build_attestation(&self, payload: &[u8], slot: u32) -> AceChainAttestation {
        let obj_hash = sha256(payload);
        let idcom = self.public.chain.idcom;
        let domain = encode_domain(self.chain_id, slot);
        let credential = self
            .session
            .sign_message(&attestation_signing_message(&obj_hash, &idcom, &domain));

        AceChainAttestation {
            obj_hash,
            idcom,
            domain,
            credential,
        }
    }

    pub fn verify_attestation(
        attestation: &AceChainAttestation,
        payload: &[u8],
        auth_pubkey: &[u8; 32],
        chain_id: u32,
        context: &[u8],
    ) -> bool {
        if sha256(payload) != attestation.obj_hash {
            return false;
        }

        if compute_chain_idcom(auth_pubkey, chain_id, context) != attestation.idcom {
            return false;
        }

        Session::verify_message(
            auth_pubkey,
            &attestation_signing_message(
                &attestation.obj_hash,
                &attestation.idcom,
                &attestation.domain,
            ),
            &attestation.credential,
        )
    }

    pub fn decrypt_payload(
        &self,
        payload: &AceEncryptedPayload,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.session.decrypt_payload(payload)
    }

    pub fn encrypt_for_recipient(
        &self,
        recipient_xidentity_b64: &str,
        plaintext: &[u8],
    ) -> Result<AceEncryptedPayload, Box<dyn Error>> {
        let _ = self;
        Session::encrypt_for_recipient(recipient_xidentity_b64, plaintext)
    }

    pub fn context(&self) -> &[u8] {
        &self.context
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }
}

pub fn compute_chain_idcom(auth_pubkey: &[u8; 32], chain_id: u32, context: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACE_CHAIN_IDCOM_INFO);
    hasher.update(auth_pubkey);
    hasher.update(chain_id.to_le_bytes());
    hasher.update(context);
    let result = hasher.finalize();

    let mut idcom = [0u8; 32];
    idcom.copy_from_slice(&result);
    idcom
}

fn encode_domain(chain_id: u32, slot: u32) -> [u8; 8] {
    let mut domain = [0u8; 8];
    domain[..4].copy_from_slice(&chain_id.to_le_bytes());
    domain[4..].copy_from_slice(&slot.to_le_bytes());
    domain
}

fn attestation_signing_message(
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &[u8; 8],
) -> [u8; 72] {
    let mut message = [0u8; 72];
    message[..32].copy_from_slice(obj_hash);
    message[32..64].copy_from_slice(idcom);
    message[64..72].copy_from_slice(domain);
    message
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn serialize_signature<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(signature)
}

fn deserialize_signature<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
    if bytes.len() != 64 {
        return Err(serde::de::Error::invalid_length(
            bytes.len(),
            &"a 64-byte Ed25519 signature",
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes);
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loaded_identity_builds_chain_attestation() {
        let generated = ACEGF::generate_wallet("correct horse battery staple", None)
            .expect("wallet generation");
        let identity = LoadedIdentity::open(
            &generated.mnemonic,
            "correct horse battery staple",
            None,
            7,
            b"ctx",
        )
        .expect("load identity");
        let attestation = identity.build_attestation(b"hello", 9);

        assert_eq!(attestation.idcom, identity.chain_identity().idcom);
        assert!(LoadedIdentity::verify_attestation(
            &attestation,
            b"hello",
            &identity.auth_pubkey(),
            identity.chain_id(),
            identity.context(),
        ));
    }
}
