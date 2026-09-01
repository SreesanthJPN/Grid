use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, Key, MlKem768};
use sha2::Sha256;
use zeroize::Zeroize;

#[derive(thiserror::Error, Debug)]
pub enum PqError {
    #[error("malformed ML-KEM encapsulation key")]
    InvalidEncapsulationKey,
    #[error("malformed or wrong-length ML-KEM ciphertext")]
    InvalidCiphertext,
}

/// Ephemeral ML-KEM-768 keypair generated per-session by the Noise
/// initiator, piggybacked onto the classical handshake for defense against
/// a "harvest now, decrypt later" quantum adversary. Security holds as
/// long as EITHER X25519 or ML-KEM remains unbroken — this only adds
/// assurance, it never subtracts from the classical guarantee.
pub struct EphemeralKemKeypair {
    decap: DecapsulationKey<MlKem768>,
    encap_bytes: Vec<u8>,
}

impl EphemeralKemKeypair {
    /// Generates a fresh keypair. The encapsulation (public) key bytes
    /// (`encapsulation_key_bytes`) go in the Noise message 1 payload; the
    /// decapsulation (secret) key never leaves this struct.
    pub fn generate() -> Self {
        let (decap, encap) = MlKem768::generate_keypair();
        let encap_bytes = encap.to_bytes().to_vec();
        Self { decap, encap_bytes }
    }

    pub fn encapsulation_key_bytes(&self) -> &[u8] {
        &self.encap_bytes
    }

    /// Recovers the shared secret from a ciphertext received in message 2.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], PqError> {
        let shared = self.decap.decapsulate_slice(ciphertext).map_err(|_| PqError::InvalidCiphertext)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&shared);
        Ok(out)
    }
}

/// Responder side: encapsulate a fresh shared secret against the
/// initiator's encapsulation-key bytes (received in message 1). Returns
/// the ciphertext to send back in message 2, plus the shared secret.
pub fn encapsulate(encapsulation_key_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), PqError> {
    let key_array: Key<EncapsulationKey<MlKem768>> =
        encapsulation_key_bytes.try_into().map_err(|_| PqError::InvalidEncapsulationKey)?;
    let ek = EncapsulationKey::<MlKem768>::new(&key_array).map_err(|_| PqError::InvalidEncapsulationKey)?;
    let (ciphertext, shared) = ek.encapsulate();
    let mut out = [0u8; 32];
    out.copy_from_slice(&shared);
    Ok((ciphertext.to_vec(), out))
}

/// Mixes the classical Noise-derived root key with the post-quantum KEM
/// shared secret via HKDF, producing the Double Ratchet's initial root
/// key: `root_key = HKDF(salt = noise_root_key, ikm = kem_shared_secret)`.
pub fn mix_root_key(noise_root_key: &[u8; 32], kem_shared_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(noise_root_key), kem_shared_secret);
    let mut out = [0u8; 32];
    hk.expand(b"og-pq-root-mix-v1", &mut out).expect("32-byte okm length is always valid for HKDF-SHA256");
    out
}

impl Drop for EphemeralKemKeypair {
    fn drop(&mut self) {
        self.encap_bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_exchange_agrees_on_shared_secret() {
        let initiator_kp = EphemeralKemKeypair::generate();
        let (ciphertext, responder_secret) = encapsulate(initiator_kp.encapsulation_key_bytes()).unwrap();
        let initiator_secret = initiator_kp.decapsulate(&ciphertext).unwrap();
        assert_eq!(initiator_secret, responder_secret);
    }

    #[test]
    fn tampered_ciphertext_yields_different_secret_not_panicking() {
        let initiator_kp = EphemeralKemKeypair::generate();
        let (mut ciphertext, responder_secret) = encapsulate(initiator_kp.encapsulation_key_bytes()).unwrap();
        *ciphertext.last_mut().unwrap() ^= 0xFF;
        // ML-KEM uses implicit rejection: a corrupted ciphertext decapsulates
        // to a pseudorandom (not an error) but different shared secret,
        // rather than failing loudly. The important property is that it
        // never silently agrees with the honest secret.
        let initiator_secret = initiator_kp.decapsulate(&ciphertext).unwrap();
        assert_ne!(initiator_secret, responder_secret);
    }

    #[test]
    fn malformed_encapsulation_key_is_rejected_not_panicking() {
        let bogus = vec![0u8; 10];
        assert!(matches!(encapsulate(&bogus), Err(PqError::InvalidEncapsulationKey)));
    }

    #[test]
    fn root_mixing_is_deterministic_and_sensitive_to_both_inputs() {
        let noise_root = [1u8; 32];
        let kem_secret = [2u8; 32];
        let a = mix_root_key(&noise_root, &kem_secret);
        let b = mix_root_key(&noise_root, &kem_secret);
        assert_eq!(a, b);

        let different_noise = mix_root_key(&[9u8; 32], &kem_secret);
        assert_ne!(a, different_noise);

        let different_kem = mix_root_key(&noise_root, &[9u8; 32]);
        assert_ne!(a, different_kem);
    }
}
