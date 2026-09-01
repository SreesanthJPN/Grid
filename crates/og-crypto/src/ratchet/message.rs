use crate::aead::{self, AeadKey};

/// A ratchet message key `mk` is derived fresh per message by the
/// symmetric-key chain and is used for exactly one encryption, ever — so
/// an all-zero nonce is safe here (there is no key reuse to protect
/// against within a single-use key).
pub fn encrypt(mk: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, aead::AeadError> {
    let key = AeadKey::from_bytes(*mk);
    let nonce = [0u8; aead::NONCE_LEN];
    aead::seal(&key, &nonce, associated_data, plaintext)
}

pub fn decrypt(mk: &[u8; 32], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, aead::AeadError> {
    let key = AeadKey::from_bytes(*mk);
    let nonce = [0u8; aead::NONCE_LEN];
    aead::open(&key, &nonce, associated_data, ciphertext)
}
