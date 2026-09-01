use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::handshake::{HandshakeError, Initiator, RawSplit, Responder};
use crate::identity::Identity;
use crate::kdf_pq::{self, EphemeralKemKeypair, PqError};
use crate::ratchet::Ratchet;

/// Fixed by FIPS 203 for the ML-KEM-768 parameter set.
const KEM_CIPHERTEXT_LEN: usize = 1088;
const RATCHET_PUBKEY_LEN: usize = 32;

#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error(transparent)]
    Pq(#[from] PqError),
    #[error("malformed post-handshake payload")]
    MalformedPayload,
}

/// Session establishment, end to end:
///
/// 1. Initiator sends message 1, payload = her ephemeral ML-KEM-768
///    encapsulation key.
/// 2. Responder replies with message 2, payload = the ML-KEM ciphertext
///    (encapsulated against that key) followed by his freshly generated
///    initial ratchet public key.
/// 3. Both sides mix the classical Noise-derived key material with the
///    ML-KEM shared secret (see `kdf_pq::mix_root_key`) to seed a Double
///    Ratchet session, ready to send/receive application messages.
pub struct PendingInitiator {
    inner: Initiator,
    kem: EphemeralKemKeypair,
}

pub fn start_initiator(my_identity: &Identity, peer: &VerifyingKey) -> Result<(PendingInitiator, Vec<u8>), SessionError> {
    let mut inner = Initiator::new(my_identity, peer)?;
    let kem = EphemeralKemKeypair::generate();
    let msg1 = inner.write_message1(kem.encapsulation_key_bytes())?;
    Ok((PendingInitiator { inner, kem }, msg1))
}

impl PendingInitiator {
    pub fn finish(self, message2: &[u8]) -> Result<Ratchet, SessionError> {
        let (payload, split) = self.inner.read_message2(message2)?;
        let (kem_ciphertext, remote_ratchet_pub_bytes) = split_responder_payload(&payload)?;

        let kem_shared = self.kem.decapsulate(kem_ciphertext)?;
        let root_key = kdf_pq::mix_root_key(&combine_noise_split(&split), &kem_shared);

        let remote_ratchet_pub = X25519PublicKey::from(remote_ratchet_pub_bytes);
        Ok(Ratchet::init_initiator(root_key, remote_ratchet_pub))
    }
}

/// Processes an incoming handshake message 1, verifies it really came from
/// `expected_from` (the `from_id` claimed on the envelope that carried it),
/// and returns the message 2 bytes to send back plus the now-ready ratchet.
pub fn respond(my_identity: &Identity, message1: &[u8], expected_from: &VerifyingKey) -> Result<(Vec<u8>, Ratchet), SessionError> {
    let mut responder = Responder::new(my_identity)?;
    let kem_ek_bytes = responder.read_message1(message1)?;
    responder.verify_remote_is(expected_from)?;

    let (kem_ciphertext, kem_shared) = kdf_pq::encapsulate(&kem_ek_bytes)?;
    let initial_keypair = crate::ratchet::new_dh_keypair();
    let initial_public = X25519PublicKey::from(&initial_keypair);

    let mut payload = Vec::with_capacity(KEM_CIPHERTEXT_LEN + RATCHET_PUBKEY_LEN);
    payload.extend_from_slice(&kem_ciphertext);
    payload.extend_from_slice(initial_public.as_bytes());

    let (message2, split) = responder.write_message2(&payload)?;
    let root_key = kdf_pq::mix_root_key(&combine_noise_split(&split), &kem_shared);
    let ratchet = Ratchet::init_responder(root_key, initial_keypair);

    Ok((message2, ratchet))
}

fn split_responder_payload(payload: &[u8]) -> Result<(&[u8], [u8; RATCHET_PUBKEY_LEN]), SessionError> {
    if payload.len() != KEM_CIPHERTEXT_LEN + RATCHET_PUBKEY_LEN {
        return Err(SessionError::MalformedPayload);
    }
    let (ct, pub_bytes) = payload.split_at(KEM_CIPHERTEXT_LEN);
    let mut ratchet_pub = [0u8; RATCHET_PUBKEY_LEN];
    ratchet_pub.copy_from_slice(pub_bytes);
    Ok((ct, ratchet_pub))
}

/// Folds Noise's two directional transport keys into a single 32-byte
/// "noise root key" to feed into `kdf_pq::mix_root_key` alongside the
/// ML-KEM shared secret.
fn combine_noise_split(split: &RawSplit) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&split.initiator_to_responder);
    ikm[32..].copy_from_slice(&split.responder_to_initiator);
    let hk = Hkdf::<Sha256>::new(Some(b"og-noise-root-combine-v1"), &ikm);
    let mut out = [0u8; 32];
    hk.expand(b"root", &mut out).expect("32-byte okm is always valid for HKDF-SHA256");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_session_establishment_yields_working_ratchet() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (pending, msg1) = start_initiator(&alice, &bob.verifying_key()).unwrap();
        let (msg2, mut bob_ratchet) = respond(&bob, &msg1, &alice.verifying_key()).unwrap();
        let mut alice_ratchet = pending.finish(&msg2).unwrap();

        let (header, ciphertext) = alice_ratchet.encrypt(b"hello from alice", b"").unwrap();
        let plaintext = bob_ratchet.decrypt(&header, &ciphertext, b"").unwrap();
        assert_eq!(plaintext, b"hello from alice");
    }

    #[test]
    fn responder_rejects_handshake_claiming_the_wrong_sender() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        let (_pending, msg1) = start_initiator(&alice, &bob.verifying_key()).unwrap();
        // Something upstream (e.g. a forged envelope) claims this handshake
        // came from Mallory, not Alice.
        assert!(respond(&bob, &msg1, &mallory.verifying_key()).is_err());
    }
}
