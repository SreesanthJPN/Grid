use serde::{Deserialize, Serialize};

use crate::padding::{self, PaddingError};

/// The only thing the relay ever routes: a padded, opaque ciphertext blob
/// addressed by raw Ed25519 public-key bytes. `payload` is produced by the
/// E2E crypto layer upstream (og-crypto's Noise handshake / Double Ratchet)
/// — the relay never has the key material needed to read it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Envelope {
    pub to_id: [u8; 32],
    pub from_id: [u8; 32],
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn new(to_id: [u8; 32], from_id: [u8; 32], seq: u64, ciphertext: &[u8]) -> Result<Self, PaddingError> {
        let payload = padding::pad(ciphertext)?;
        Ok(Envelope { to_id, from_id, seq, payload })
    }

    pub fn unpad_payload(&self) -> Result<Vec<u8>, PaddingError> {
        padding::unpad(&self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_ciphertext() {
        let ciphertext = b"opaque-bytes-only-the-recipient-can-open";
        let env = Envelope::new([1u8; 32], [2u8; 32], 0, ciphertext).unwrap();
        assert_eq!(env.unpad_payload().unwrap(), ciphertext);
    }

    #[test]
    fn oversized_ciphertext_is_rejected() {
        let ciphertext = vec![0u8; padding::MAX_PAYLOAD_LEN + 1];
        assert!(Envelope::new([0u8; 32], [0u8; 32], 0, &ciphertext).is_err());
    }
}
