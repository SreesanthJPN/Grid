use og_crypto::ratchet::Header;
use serde::{Deserialize, Serialize};

/// What actually rides inside an `Envelope`'s payload once it reaches its
/// destination. The relay never parses this — it only ever sees the
/// padded, opaque `payload` bytes. Distinguishes session-establishment
/// traffic (the Noise handshake messages) from an already-ratcheting
/// session's messages, so a receiver knows how to interpret whatever it
/// gets from a given sender.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SessionMessage {
    HandshakeMsg1(Vec<u8>),
    HandshakeMsg2(Vec<u8>),
    Ratchet { header: Header, ciphertext: Vec<u8> },
}

/// What the Double Ratchet's plaintext actually contains, once decrypted.
/// Kept separate from `SessionMessage` so new message kinds (typing
/// indicators, delivery acknowledgements, voice control) can be added
/// later without touching session-establishment framing.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PlaintextMessage {
    Text(String),
}
