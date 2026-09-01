use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::RngCore;
use zeroize::ZeroizeOnDrop;

pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

#[derive(Clone, ZeroizeOnDrop)]
pub struct AeadKey([u8; KEY_LEN]);

impl AeadKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AeadError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (ciphertext may be corrupt or tampered)")]
    Decrypt,
}

pub fn seal(key: &AeadKey, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| AeadError::Encrypt)
}

pub fn open(key: &AeadKey, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| AeadError::Decrypt)
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut n);
    n
}
