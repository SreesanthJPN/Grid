use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// bech32 human-readable part for an off-grid identity, e.g. "og1qw...".
pub const ID_HRP: &str = "og";

#[derive(thiserror::Error, Debug)]
pub enum IdentityError {
    #[error("invalid identity id encoding")]
    InvalidId,
    #[error("id has an unexpected prefix")]
    WrongPrefix,
    #[error("public key does not decode to a valid curve point")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    BadSignature,
}

/// A user's self-sovereign identity: one Ed25519 keypair used both to sign
/// (proof-of-possession, message authentication) and, via a deterministic
/// birational derivation, as an X25519 keypair for Diffie-Hellman. There is
/// only ever one keypair to generate, back up, and share as an ID.
pub struct Identity {
    signing_key: SigningKey,
    dh_secret: X25519StaticSecret,
}

impl Identity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        Self::from_signing_key(signing_key)
    }

    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self::from_signing_key(signing_key)
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let dh_secret = derive_x25519_secret(&signing_key);
        Self { signing_key, dh_secret }
    }

    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn dh_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.dh_secret)
    }

    pub fn dh_secret(&self) -> &X25519StaticSecret {
        &self.dh_secret
    }

    /// The shareable identity string, e.g. "og1...".
    pub fn id(&self) -> String {
        encode_id(&self.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }
}

/// Derives this identity's private X25519 (DH) scalar from its Ed25519 seed,
/// using the same seed-expansion clamping Ed25519 itself uses (RFC 8032):
/// SHA-512(seed), take the low 32 bytes, clamp. Those clamped bytes ARE a
/// valid X25519 scalar by construction, so this needs no extra derivation
/// step beyond what `x25519_dalek::StaticSecret::from` already clamps.
fn derive_x25519_secret(signing_key: &SigningKey) -> X25519StaticSecret {
    let seed = signing_key.to_bytes();
    let hash = Sha512::digest(seed);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    let secret = X25519StaticSecret::from(scalar_bytes);
    scalar_bytes.zeroize();
    secret
}

/// Derives the X25519 DH public key belonging to a peer's Ed25519 verifying
/// key, via the standard Edwards -> Montgomery birational map. This lets any
/// peer compute the other side's DH public key from their shared "ID" alone.
pub fn verifying_key_to_x25519(vk: &VerifyingKey) -> Result<X25519PublicKey, IdentityError> {
    let compressed = CompressedEdwardsY(vk.to_bytes());
    let edwards = compressed.decompress().ok_or(IdentityError::InvalidPublicKey)?;
    let montgomery = edwards.to_montgomery();
    Ok(X25519PublicKey::from(montgomery.to_bytes()))
}

pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), IdentityError> {
    vk.verify(msg, sig).map_err(|_| IdentityError::BadSignature)
}

pub fn encode_id(pubkey: &[u8; 32]) -> String {
    let hrp = bech32::Hrp::parse(ID_HRP).expect("static HRP is always valid");
    bech32::encode::<bech32::Bech32>(hrp, pubkey).expect("32-byte payload always encodes")
}

pub fn decode_id(id: &str) -> Result<VerifyingKey, IdentityError> {
    let (hrp, data) = bech32::decode(id).map_err(|_| IdentityError::InvalidId)?;
    if hrp.as_str() != ID_HRP {
        return Err(IdentityError::WrongPrefix);
    }
    let bytes: [u8; 32] = data.try_into().map_err(|_| IdentityError::InvalidId)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| IdentityError::InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_round_trips_through_bech32() {
        let identity = Identity::generate();
        let id = identity.id();
        assert!(id.starts_with("og1"));
        let decoded = decode_id(&id).expect("valid id decodes");
        assert_eq!(decoded.to_bytes(), identity.verifying_key().to_bytes());
    }

    #[test]
    fn same_seed_yields_same_identity() {
        let seed = [7u8; 32];
        let a = Identity::from_seed(seed);
        let b = Identity::from_seed(seed);
        assert_eq!(a.id(), b.id());
        assert_eq!(a.dh_public().to_bytes(), b.dh_public().to_bytes());
    }

    #[test]
    fn different_seeds_yield_different_ids() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn peer_can_derive_dh_public_key_from_id_alone() {
        let identity = Identity::generate();
        let derived = verifying_key_to_x25519(&identity.verifying_key()).expect("valid conversion");
        assert_eq!(derived.to_bytes(), identity.dh_public().to_bytes());
    }

    #[test]
    fn signature_round_trips() {
        let identity = Identity::generate();
        let msg = b"prove you hold this id";
        let sig = identity.sign(msg);
        assert!(verify(&identity.verifying_key(), msg, &sig).is_ok());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let identity = Identity::generate();
        let sig = identity.sign(b"hello");
        assert!(verify(&identity.verifying_key(), b"goodbye", &sig).is_err());
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let hrp = bech32::Hrp::parse("xx").unwrap();
        let bogus = bech32::encode::<bech32::Bech32>(hrp, &[0u8; 32]).unwrap();
        assert!(matches!(decode_id(&bogus), Err(IdentityError::WrongPrefix)));
    }
}
