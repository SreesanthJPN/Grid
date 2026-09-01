use ed25519_dalek::VerifyingKey;
use snow::params::NoiseParams;
use snow::{Builder, HandshakeState};

use crate::identity::{self, Identity, IdentityError};

/// Noise_IK: the initiator already knows the responder's static public key
/// (that's exactly what an off-grid "ID" is), giving mutual authentication,
/// forward secrecy, and key-compromise-impersonation resistance in one
/// handshake, without needing X3DH prekey infrastructure. Both peers must
/// be connected to the relay at the same time to complete it.
const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Generous bound for a handshake message. Actual IK messages with a small
/// payload are well under 200 bytes; this leaves headroom for the ML-KEM-768
/// encapsulation key/ciphertext piggybacked in the handshake payload
/// (~1.1-1.2 KB each) with margin to spare.
const HANDSHAKE_MSG_MAX: usize = 4096;

/// The two directional keys snow derives once a Noise handshake completes.
/// We use these as raw key material for our own Double Ratchet rather than
/// snow's `TransportState` — Noise's job here ends at authenticated key
/// exchange; message encryption is the ratchet's job.
pub struct RawSplit {
    pub initiator_to_responder: [u8; 32],
    pub responder_to_initiator: [u8; 32],
}

#[derive(thiserror::Error, Debug)]
pub enum HandshakeError {
    #[error("noise protocol error: {0}")]
    Noise(String),
    #[error("peer id does not decode to a valid curve point")]
    InvalidPeerId(#[from] IdentityError),
    #[error("handshake is not yet complete")]
    NotFinished,
    #[error("remote static key does not match the claimed id")]
    IdentityMismatch,
}

impl From<snow::Error> for HandshakeError {
    fn from(e: snow::Error) -> Self {
        HandshakeError::Noise(e.to_string())
    }
}

fn pattern() -> NoiseParams {
    NOISE_PATTERN.parse().expect("static pattern string is always valid")
}

/// Initiator role: the party placing the connection, who already knows the
/// responder's ID (their Ed25519 verifying key).
pub struct Initiator {
    state: HandshakeState,
}

impl Initiator {
    pub fn new(my_identity: &Identity, peer: &VerifyingKey) -> Result<Self, HandshakeError> {
        let peer_x25519 = identity::verifying_key_to_x25519(peer)?;
        let state = Builder::new(pattern())
            .local_private_key(&my_identity.dh_secret().to_bytes())?
            .remote_public_key(peer_x25519.as_bytes())?
            .build_initiator()?;
        Ok(Self { state })
    }

    /// Produces handshake message 1 (`-> e, es, s, ss`), carrying
    /// `payload` (e.g. this side's ephemeral ML-KEM encapsulation key)
    /// authenticated-encrypted under the keys established so far.
    pub fn write_message1(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; HANDSHAKE_MSG_MAX];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Consumes handshake message 2 (`<- e, ee, se`), completing the
    /// handshake, and returns the decrypted payload plus the raw session
    /// key split to seed the Double Ratchet.
    pub fn read_message2(mut self, message: &[u8]) -> Result<(Vec<u8>, RawSplit), HandshakeError> {
        let mut buf = vec![0u8; HANDSHAKE_MSG_MAX];
        let len = self.state.read_message(message, &mut buf)?;
        buf.truncate(len);
        let split = raw_split(&mut self.state)?;
        Ok((buf, split))
    }
}

/// Responder role: the party accepting the connection. Unlike XX, IK
/// reveals the initiator's static key only inside message 1 (encrypted
/// under `es`), so it is not known until `read_message1` succeeds.
pub struct Responder {
    state: HandshakeState,
}

impl Responder {
    pub fn new(my_identity: &Identity) -> Result<Self, HandshakeError> {
        let state = Builder::new(pattern())
            .local_private_key(&my_identity.dh_secret().to_bytes())?
            .build_responder()?;
        Ok(Self { state })
    }

    /// Consumes handshake message 1 and returns its decrypted payload.
    /// After this call, `remote_static_x25519` and `verify_remote_is` are
    /// available to authenticate who just connected.
    pub fn read_message1(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; HANDSHAKE_MSG_MAX];
        let len = self.state.read_message(message, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// The initiator's raw X25519 static public key, as proven by the
    /// handshake's `es` term. This is cryptographic fact; it does not by
    /// itself say which "ID" that corresponds to (see `verify_remote_is`).
    pub fn remote_static_x25519(&self) -> Option<[u8; 32]> {
        let s = self.state.get_remote_static()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        Some(out)
    }

    /// Confirms the authenticated remote static key matches the X25519 key
    /// derived from a claimed Ed25519 ID (e.g. the `from_id` on the
    /// envelope that carried this handshake message). This is what stops
    /// an attacker from completing a valid handshake while impersonating
    /// someone else's ID at the routing layer.
    pub fn verify_remote_is(&self, claimed: &VerifyingKey) -> Result<(), HandshakeError> {
        let expected = identity::verifying_key_to_x25519(claimed)?;
        let actual = self.remote_static_x25519().ok_or(HandshakeError::NotFinished)?;
        if expected.as_bytes() != &actual {
            return Err(HandshakeError::IdentityMismatch);
        }
        Ok(())
    }

    /// Produces handshake message 2 (`<- e, ee, se`) carrying `payload`
    /// (e.g. the ML-KEM ciphertext encapsulated against the initiator's
    /// key), completing the handshake, and returns the raw session key
    /// split to seed the Double Ratchet.
    pub fn write_message2(mut self, payload: &[u8]) -> Result<(Vec<u8>, RawSplit), HandshakeError> {
        let mut buf = vec![0u8; HANDSHAKE_MSG_MAX];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        let split = raw_split(&mut self.state)?;
        Ok((buf, split))
    }
}

fn raw_split(state: &mut HandshakeState) -> Result<RawSplit, HandshakeError> {
    if !state.is_handshake_finished() {
        return Err(HandshakeError::NotFinished);
    }
    let (a, b) = state.dangerously_get_raw_split();
    Ok(RawSplit { initiator_to_responder: a, responder_to_initiator: b })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_round_trips_and_splits_agree() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let mut initiator = Initiator::new(&alice, &bob.verifying_key()).unwrap();
        let msg1 = initiator.write_message1(b"alice-hello").unwrap();

        let mut responder = Responder::new(&bob).unwrap();
        let payload1 = responder.read_message1(&msg1).unwrap();
        assert_eq!(payload1, b"alice-hello");
        responder.verify_remote_is(&alice.verifying_key()).unwrap();

        let (msg2, resp_split) = responder.write_message2(b"bob-hello").unwrap();
        let (payload2, init_split) = initiator.read_message2(&msg2).unwrap();
        assert_eq!(payload2, b"bob-hello");

        // Both sides must agree on both directional keys.
        assert_eq!(init_split.initiator_to_responder, resp_split.initiator_to_responder);
        assert_eq!(init_split.responder_to_initiator, resp_split.responder_to_initiator);
        // And the two directions must not collide.
        assert_ne!(init_split.initiator_to_responder, init_split.responder_to_initiator);
    }

    #[test]
    fn wrong_expected_peer_key_breaks_the_handshake() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        // Alice thinks she's talking to Mallory's ID, but the bytes are
        // actually routed to Bob's responder.
        let mut initiator = Initiator::new(&alice, &mallory.verifying_key()).unwrap();
        let msg1 = initiator.write_message1(&[]).unwrap();

        let mut responder = Responder::new(&bob).unwrap();
        assert!(responder.read_message1(&msg1).is_err());
    }

    #[test]
    fn responder_rejects_wrong_claimed_identity() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        let mut initiator = Initiator::new(&alice, &bob.verifying_key()).unwrap();
        let msg1 = initiator.write_message1(&[]).unwrap();

        let mut responder = Responder::new(&bob).unwrap();
        responder.read_message1(&msg1).unwrap();
        // Bob was actually talking to Alice, but something upstream (e.g. a
        // forged envelope `from_id`) claims it was Mallory.
        assert!(responder.verify_remote_is(&mallory.verifying_key()).is_err());
    }

    #[test]
    fn tampered_message_is_rejected_not_panicking() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let mut initiator = Initiator::new(&alice, &bob.verifying_key()).unwrap();
        let mut msg1 = initiator.write_message1(&[]).unwrap();
        *msg1.last_mut().unwrap() ^= 0xFF;

        let mut responder = Responder::new(&bob).unwrap();
        assert!(responder.read_message1(&msg1).is_err());
    }
}
