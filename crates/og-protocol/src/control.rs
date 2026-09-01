use ed25519_dalek::{Signature, VerifyingKey};
use og_crypto::identity::{self, Identity};
use serde::{Deserialize, Serialize};

pub const NONCE_LEN: usize = 32;

/// Domain-separation tag for the connect-proof signature, so a signature
/// produced here can never be replayed as valid in an unrelated context.
const PROOF_CONTEXT: &[u8] = b"og-relay-connect-proof-v1";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectChallenge {
    pub nonce: [u8; NONCE_LEN],
}

/// Proof that the connecting client actually holds the private key for the
/// ID it claims — the relay's only defense against ID squatting/hijacking.
/// It proves nothing about message content; the relay still can't decrypt.
///
/// `signature` is `Vec<u8>` rather than `[u8; 64]` because serde's built-in
/// array support tops out at 32 elements; length is validated in `verify`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectProof {
    pub id: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum ControlError {
    #[error("invalid public key in proof")]
    InvalidPublicKey,
    #[error("malformed signature encoding")]
    InvalidSignature,
    #[error("signature does not match the claimed id")]
    ProofFailed,
}

impl ConnectProof {
    pub fn create(identity: &Identity, nonce: &[u8; NONCE_LEN]) -> Self {
        let signature = identity.sign(&proof_message(nonce));
        ConnectProof {
            id: identity.verifying_key().to_bytes(),
            signature: signature.to_bytes().to_vec(),
        }
    }

    /// Verifies the proof against the nonce the relay itself issued, and
    /// returns the now-authenticated verifying key on success.
    pub fn verify(&self, nonce: &[u8; NONCE_LEN]) -> Result<VerifyingKey, ControlError> {
        let vk = VerifyingKey::from_bytes(&self.id).map_err(|_| ControlError::InvalidPublicKey)?;
        let sig_bytes: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| ControlError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        identity::verify(&vk, &proof_message(nonce), &sig).map_err(|_| ControlError::ProofFailed)?;
        Ok(vk)
    }
}

fn proof_message(nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut msg = PROOF_CONTEXT.to_vec();
    msg.extend_from_slice(nonce);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genuine_proof_is_accepted() {
        let identity = Identity::generate();
        let nonce = [9u8; NONCE_LEN];
        let proof = ConnectProof::create(&identity, &nonce);
        let vk = proof.verify(&nonce).unwrap();
        assert_eq!(vk.to_bytes(), identity.verifying_key().to_bytes());
    }

    #[test]
    fn proof_for_a_different_nonce_is_rejected() {
        let identity = Identity::generate();
        let proof = ConnectProof::create(&identity, &[1u8; NONCE_LEN]);
        assert!(proof.verify(&[2u8; NONCE_LEN]).is_err());
    }

    #[test]
    fn cannot_forge_proof_for_someone_elses_id() {
        let victim = Identity::generate();
        let attacker = Identity::generate();
        let nonce = [5u8; NONCE_LEN];
        // Attacker signs with their own key but claims the victim's id.
        let mut forged = ConnectProof::create(&attacker, &nonce);
        forged.id = victim.verifying_key().to_bytes();
        assert!(matches!(forged.verify(&nonce), Err(ControlError::ProofFailed)));
    }

    #[test]
    fn truncated_signature_is_rejected_not_panicking() {
        let identity = Identity::generate();
        let nonce = [1u8; NONCE_LEN];
        let mut proof = ConnectProof::create(&identity, &nonce);
        proof.signature.truncate(10);
        assert!(matches!(proof.verify(&nonce), Err(ControlError::InvalidSignature)));
    }
}
