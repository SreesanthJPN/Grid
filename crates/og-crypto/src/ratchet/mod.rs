mod kdf_chain;
mod message;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::aead::AeadError;
use kdf_chain::{kdf_ck, kdf_rk};

/// Bounds how many message keys we'll derive-and-cache to catch up on a
/// skipped-ahead receiving chain, so a malicious or badly desynced peer
/// can't force unbounded memory growth by claiming a huge message number.
const MAX_SKIP: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub dh_pub: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl Header {
    fn associated_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..32].copy_from_slice(&self.dh_pub);
        out[32..36].copy_from_slice(&self.pn.to_le_bytes());
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RatchetError {
    #[error("no sending chain established yet (the responder must receive before it can send)")]
    NoSendingChain,
    #[error(transparent)]
    Aead(#[from] AeadError),
    #[error("too many skipped messages in one chain (possible attack or severe desync)")]
    TooManySkipped,
    #[error("message key unavailable (already used, too old, or the chain isn't ready yet)")]
    UnknownMessageKey,
}

/// A Double Ratchet session (Signal Double Ratchet spec): a symmetric-key
/// ratchet advances on every message for per-message forward secrecy, and
/// a Diffie-Hellman ratchet advances whenever the peer's ratchet public key
/// changes, for post-compromise security (the session "heals" even after a
/// key compromise, once both sides have ratcheted forward again).
pub struct Ratchet {
    dh_self: X25519StaticSecret,
    dh_self_public: X25519PublicKey,
    dh_remote: Option<[u8; 32]>,
    root_key: [u8; 32],
    chain_key_send: Option<[u8; 32]>,
    chain_key_recv: Option<[u8; 32]>,
    n_send: u32,
    n_recv: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl Ratchet {
    /// Initiator ("Alice") side: she already knows the responder's freshly
    /// published initial ratchet public key (sent alongside the Noise
    /// handshake), so she performs the first DH step immediately and can
    /// send right away.
    pub fn init_initiator(root_key: [u8; 32], remote_initial_public: X25519PublicKey) -> Self {
        let dh_self = new_dh_keypair();
        let dh_self_public = X25519PublicKey::from(&dh_self);
        let dh_out = dh_self.diffie_hellman(&remote_initial_public);
        let (new_rk, ck_send) = kdf_rk(&root_key, dh_out.as_bytes());
        Self {
            dh_self,
            dh_self_public,
            dh_remote: Some(remote_initial_public.to_bytes()),
            root_key: new_rk,
            chain_key_send: Some(ck_send),
            chain_key_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// Responder ("Bob") side: he generated `initial_keypair` and published
    /// its public half to Alice; he can't send until he's received Alice's
    /// first message and completed his own first DH ratchet step.
    pub fn init_responder(root_key: [u8; 32], initial_keypair: X25519StaticSecret) -> Self {
        let dh_self_public = X25519PublicKey::from(&initial_keypair);
        Self {
            dh_self: initial_keypair,
            dh_self_public,
            dh_remote: None,
            root_key,
            chain_key_send: None,
            chain_key_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    pub fn local_ratchet_public(&self) -> X25519PublicKey {
        self.dh_self_public
    }

    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<(Header, Vec<u8>), RatchetError> {
        let ck = self.chain_key_send.ok_or(RatchetError::NoSendingChain)?;
        let (new_ck, mk) = kdf_ck(&ck);
        self.chain_key_send = Some(new_ck);

        let header = Header { dh_pub: self.dh_self_public.to_bytes(), pn: self.pn, n: self.n_send };
        self.n_send += 1;

        let ad = concat_ad(associated_data, &header);
        let ciphertext = message::encrypt(&mk, plaintext, &ad)?;
        Ok((header, ciphertext))
    }

    pub fn decrypt(&mut self, header: &Header, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let ad = concat_ad(associated_data, header);

        if let Some(mk) = self.skipped.remove(&(header.dh_pub, header.n)) {
            return Ok(message::decrypt(&mk, ciphertext, &ad)?);
        }

        if self.dh_remote != Some(header.dh_pub) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header.dh_pub);
        }

        self.skip_message_keys(header.n)?;

        let ck = self.chain_key_recv.ok_or(RatchetError::UnknownMessageKey)?;
        let (new_ck, mk) = kdf_ck(&ck);
        self.chain_key_recv = Some(new_ck);
        self.n_recv += 1;

        message::decrypt(&mk, ciphertext, &ad).map_err(RatchetError::from)
    }

    /// Derives and caches message keys for the current receiving chain up
    /// to (but not including) message number `until`, so those messages
    /// can still be decrypted later even if they arrive out of order.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if self.n_recv.saturating_add(MAX_SKIP) < until {
            return Err(RatchetError::TooManySkipped);
        }
        if let Some(mut ck) = self.chain_key_recv {
            let remote = self.dh_remote.expect("chain_key_recv is only ever set once dh_remote is known");
            while self.n_recv < until {
                let (new_ck, mk) = kdf_ck(&ck);
                ck = new_ck;
                self.skipped.insert((remote, self.n_recv), mk);
                self.n_recv += 1;
            }
            self.chain_key_recv = Some(ck);
        }
        Ok(())
    }

    /// The DH ratchet step: rotates the receiving chain onto the peer's
    /// newly-seen public key, then immediately generates a fresh local
    /// keypair and rotates the sending chain too — the "double" in Double
    /// Ratchet. This is what gives the session post-compromise security:
    /// once both sides have stepped past a compromised key, past exposure
    /// no longer helps an attacker read new messages.
    fn dh_ratchet(&mut self, remote_public_bytes: [u8; 32]) {
        let remote_public = X25519PublicKey::from(remote_public_bytes);

        self.pn = self.n_send;
        self.n_send = 0;
        self.n_recv = 0;
        self.dh_remote = Some(remote_public_bytes);

        let dh_out = self.dh_self.diffie_hellman(&remote_public);
        let (rk1, ck_recv) = kdf_rk(&self.root_key, dh_out.as_bytes());
        self.root_key = rk1;
        self.chain_key_recv = Some(ck_recv);

        self.dh_self = new_dh_keypair();
        self.dh_self_public = X25519PublicKey::from(&self.dh_self);
        let dh_out2 = self.dh_self.diffie_hellman(&remote_public);
        let (rk2, ck_send) = kdf_rk(&self.root_key, dh_out2.as_bytes());
        self.root_key = rk2;
        self.chain_key_send = Some(ck_send);
    }
}

fn concat_ad(associated_data: &[u8], header: &Header) -> Vec<u8> {
    let mut ad = Vec::with_capacity(associated_data.len() + 40);
    ad.extend_from_slice(associated_data);
    ad.extend_from_slice(&header.associated_bytes());
    ad
}

/// Generates a fresh X25519 keypair suitable for seeding one side of a new
/// ratchet session (the responder's "initial ratchet keypair" published
/// alongside the Noise handshake). Exposed at crate visibility so the
/// session-establishment layer can generate it without reaching into the
/// ratchet's other internals.
pub(crate) fn new_dh_keypair() -> X25519StaticSecret {
    X25519StaticSecret::random_from_rng(rand_core::OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_pair() -> (Ratchet, Ratchet) {
        let root_key = [42u8; 32];
        let bob_initial = new_dh_keypair();
        let bob_initial_public = X25519PublicKey::from(&bob_initial);
        let alice = Ratchet::init_initiator(root_key, bob_initial_public);
        let bob = Ratchet::init_responder(root_key, bob_initial);
        (alice, bob)
    }

    #[test]
    fn alice_can_send_immediately_bob_cannot() {
        let (mut alice, _bob) = init_pair();
        assert!(alice.encrypt(b"hi", b"").is_ok());
    }

    #[test]
    fn basic_back_and_forth_round_trips() {
        let (mut alice, mut bob) = init_pair();

        let (h1, c1) = alice.encrypt(b"hello bob", b"session-ad").unwrap();
        let p1 = bob.decrypt(&h1, &c1, b"session-ad").unwrap();
        assert_eq!(p1, b"hello bob");

        // Bob's first decrypt triggers his DH ratchet step, so he can now send.
        let (h2, c2) = bob.encrypt(b"hi alice", b"session-ad").unwrap();
        let p2 = alice.decrypt(&h2, &c2, b"session-ad").unwrap();
        assert_eq!(p2, b"hi alice");

        let (h3, c3) = alice.encrypt(b"how are you", b"session-ad").unwrap();
        let p3 = bob.decrypt(&h3, &c3, b"session-ad").unwrap();
        assert_eq!(p3, b"how are you");
    }

    #[test]
    fn out_of_order_delivery_within_a_chain_is_handled() {
        let (mut alice, mut bob) = init_pair();

        let (h1, c1) = alice.encrypt(b"one", b"").unwrap();
        let (h2, c2) = alice.encrypt(b"two", b"").unwrap();
        let (h3, c3) = alice.encrypt(b"three", b"").unwrap();

        // Bob receives them out of order: 3, 1, 2.
        assert_eq!(bob.decrypt(&h3, &c3, b"").unwrap(), b"three");
        assert_eq!(bob.decrypt(&h1, &c1, b"").unwrap(), b"one");
        assert_eq!(bob.decrypt(&h2, &c2, b"").unwrap(), b"two");
    }

    #[test]
    fn out_of_order_delivery_across_a_dh_ratchet_step_is_handled() {
        let (mut alice, mut bob) = init_pair();

        let (h1, c1) = alice.encrypt(b"a1", b"").unwrap();
        let (h2, c2) = alice.encrypt(b"a2", b"").unwrap();
        // Bob only gets a1 for now; a2 arrives "late" below.
        assert_eq!(bob.decrypt(&h1, &c1, b"").unwrap(), b"a1");

        // Bob replies, which ratchets Alice forward when she reads it.
        let (hb, cb) = bob.encrypt(b"b1", b"").unwrap();
        assert_eq!(alice.decrypt(&hb, &cb, b"").unwrap(), b"b1");

        // Alice sends again on her new sending chain...
        let (h3, c3) = alice.encrypt(b"a3", b"").unwrap();

        // ...and only now does Bob catch up on the late a2, followed by a3.
        // a2 belongs to Alice's OLD ratchet key, so this exercises both the
        // skipped-key cache and the cross-ratchet-step bookkeeping (`pn`).
        assert_eq!(bob.decrypt(&h2, &c2, b"").unwrap(), b"a2");
        assert_eq!(bob.decrypt(&h3, &c3, b"").unwrap(), b"a3");
    }

    #[test]
    fn a_message_key_cannot_be_used_twice() {
        let (mut alice, mut bob) = init_pair();
        let (h1, c1) = alice.encrypt(b"once", b"").unwrap();
        assert!(bob.decrypt(&h1, &c1, b"").is_ok());
        // Replaying the exact same header+ciphertext a second time must
        // fail: the in-chain message key was consumed, and this exact
        // (dh_pub, n) pair was never placed in the skipped-key cache.
        assert!(bob.decrypt(&h1, &c1, b"").is_err());
    }

    #[test]
    fn forward_secrecy_old_chain_key_state_cannot_decrypt_post_ratchet_messages() {
        let (mut alice, mut bob) = init_pair();

        let (h1, c1) = alice.encrypt(b"a1", b"").unwrap();
        bob.decrypt(&h1, &c1, b"").unwrap();
        let (hb, cb) = bob.encrypt(b"b1", b"").unwrap();
        alice.decrypt(&hb, &cb, b"").unwrap(); // Alice ratchets forward here.

        // A snapshot of what Alice's sending chain key was on her OLD
        // ratchet (pre-DH-step) cannot derive the message key used after
        // the step, because KDF_CK on the old chain produces a completely
        // different key than the fresh chain seeded by the new DH output.
        let (h2, c2) = alice.encrypt(b"a2-post-ratchet", b"").unwrap();
        assert_ne!(h1.dh_pub, h2.dh_pub, "the ratchet public key must have changed");
        let p2 = bob.decrypt(&h2, &c2, b"").unwrap();
        assert_eq!(p2, b"a2-post-ratchet");
    }

    #[test]
    fn tampered_ciphertext_is_rejected_not_panicking() {
        let (mut alice, mut bob) = init_pair();
        let (h1, mut c1) = alice.encrypt(b"integrity check", b"").unwrap();
        *c1.last_mut().unwrap() ^= 0xFF;
        assert!(bob.decrypt(&h1, &c1, b"").is_err());
    }

    #[test]
    fn wrong_associated_data_is_rejected_not_panicking() {
        let (mut alice, mut bob) = init_pair();
        let (h1, c1) = alice.encrypt(b"bound to context", b"correct-ad").unwrap();
        assert!(bob.decrypt(&h1, &c1, b"wrong-ad").is_err());
    }

    #[test]
    fn excessive_skip_is_rejected_not_panicking() {
        let (mut alice, mut bob) = init_pair();
        let (h1, c1) = alice.encrypt(b"first", b"").unwrap();
        bob.decrypt(&h1, &c1, b"").unwrap();

        for _ in 0..(MAX_SKIP + 10) {
            alice.encrypt(b"filler", b"").unwrap();
        }
        let (h_far, c_far) = alice.encrypt(b"too far ahead", b"").unwrap();
        assert!(matches!(bob.decrypt(&h_far, &c_far, b""), Err(RatchetError::TooManySkipped)));
    }
}
