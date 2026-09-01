use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::aead::{self, AeadKey, NONCE_LEN};
use crate::identity::Identity;

pub const SALT_LEN: usize = 16;
const AAD: &[u8] = b"og-identity-v1";

#[derive(thiserror::Error, Debug)]
pub enum KeystoreError {
    #[error("failed to derive key from passphrase (bad Argon2 parameters)")]
    Kdf,
    #[error(transparent)]
    Aead(#[from] aead::AeadError),
    #[error("corrupt or truncated keystore file")]
    Corrupt,
    #[error("io error: {0}")]
    Io(String),
    #[error("os keychain error: {0}")]
    Keychain(String),
}

/// Argon2id cost parameters. Desktop can afford a generous memory cost;
/// mobile uses the OWASP floor to avoid jank on low-end devices.
#[derive(Clone, Copy)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub const DESKTOP: KdfParams = KdfParams { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 };
    pub const MOBILE: KdfParams = KdfParams { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };
}

pub struct EncryptedIdentity {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub params: KdfParams,
}

fn derive_key(passphrase: &[u8], salt: &[u8], params: &KdfParams) -> Result<AeadKey, KeystoreError> {
    let argon2_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(aead::KEY_LEN))
        .map_err(|_| KeystoreError::Kdf)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut out = [0u8; aead::KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| KeystoreError::Kdf)?;
    let key = AeadKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// Encrypts an identity's private seed for storage, deriving the encryption
/// key from a user passphrase via Argon2id. The seed is zeroized from local
/// memory as soon as it has been sealed.
pub fn seal_identity(identity: &Identity, passphrase: &[u8], params: KdfParams) -> Result<EncryptedIdentity, KeystoreError> {
    let mut salt = [0u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt, &params)?;

    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let mut seed = identity.seed_bytes();
    let ciphertext = aead::seal(&key, &nonce, AAD, &seed)?;
    seed.zeroize();

    Ok(EncryptedIdentity { salt, nonce, ciphertext, params })
}

/// Decrypts an identity's private seed given the correct passphrase. Wrong
/// passphrases fail AEAD authentication and are rejected, not silently
/// accepted with garbage key material.
pub fn open_identity(enc: &EncryptedIdentity, passphrase: &[u8]) -> Result<Identity, KeystoreError> {
    let key = derive_key(passphrase, &enc.salt, &enc.params)?;
    let mut seed_vec = aead::open(&key, &enc.nonce, AAD, &enc.ciphertext)?;
    if seed_vec.len() != 32 {
        seed_vec.zeroize();
        return Err(KeystoreError::Corrupt);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_vec);
    seed_vec.zeroize();
    let identity = Identity::from_seed(seed);
    Ok(identity)
}

#[derive(Serialize, Deserialize)]
struct KeystoreFile {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl From<&EncryptedIdentity> for KeystoreFile {
    fn from(e: &EncryptedIdentity) -> Self {
        KeystoreFile {
            memory_kib: e.params.memory_kib,
            iterations: e.params.iterations,
            parallelism: e.params.parallelism,
            salt: e.salt.to_vec(),
            nonce: e.nonce.to_vec(),
            ciphertext: e.ciphertext.clone(),
        }
    }
}

impl TryFrom<KeystoreFile> for EncryptedIdentity {
    type Error = KeystoreError;

    fn try_from(f: KeystoreFile) -> Result<Self, KeystoreError> {
        let salt: [u8; SALT_LEN] = f.salt.try_into().map_err(|_| KeystoreError::Corrupt)?;
        let nonce: [u8; NONCE_LEN] = f.nonce.try_into().map_err(|_| KeystoreError::Corrupt)?;
        Ok(EncryptedIdentity {
            salt,
            nonce,
            ciphertext: f.ciphertext,
            params: KdfParams {
                memory_kib: f.memory_kib,
                iterations: f.iterations,
                parallelism: f.parallelism,
            },
        })
    }
}

pub fn save_to_file(enc: &EncryptedIdentity, path: &Path) -> Result<(), KeystoreError> {
    let file = KeystoreFile::from(enc);
    let bytes = postcard::to_allocvec(&file).map_err(|_| KeystoreError::Corrupt)?;
    std::fs::write(path, bytes).map_err(|e| KeystoreError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| KeystoreError::Io(e.to_string()))?;
    }
    Ok(())
}

pub fn load_from_file(path: &Path) -> Result<EncryptedIdentity, KeystoreError> {
    let bytes = std::fs::read(path).map_err(|e| KeystoreError::Io(e.to_string()))?;
    let file: KeystoreFile = postcard::from_bytes(&bytes).map_err(|_| KeystoreError::Corrupt)?;
    file.try_into()
}

/// Stores an arbitrary secret (e.g. a passphrase, so the user isn't prompted
/// every launch) in the OS keychain/keystore. Desktop platforms (Windows
/// Credential Manager, macOS/iOS Keychain, Linux Secret Service) are covered
/// directly by the `keyring` crate; Android requires the companion
/// `android-keyring` backend wired to the host app's JNI context, which is
/// out of scope until the native Android client exists.
pub fn store_in_os_keychain(service: &str, account: &str, secret: &[u8]) -> Result<(), KeystoreError> {
    let entry = keyring::Entry::new(service, account).map_err(|e| KeystoreError::Keychain(e.to_string()))?;
    entry.set_secret(secret).map_err(|e| KeystoreError::Keychain(e.to_string()))
}

pub fn load_from_os_keychain(service: &str, account: &str) -> Result<Vec<u8>, KeystoreError> {
    let entry = keyring::Entry::new(service, account).map_err(|e| KeystoreError::Keychain(e.to_string()))?;
    entry.get_secret().map_err(|e| KeystoreError::Keychain(e.to_string()))
}

pub fn delete_from_os_keychain(service: &str, account: &str) -> Result<(), KeystoreError> {
    let entry = keyring::Entry::new(service, account).map_err(|e| KeystoreError::Keychain(e.to_string()))?;
    entry.delete_credential().map_err(|e| KeystoreError::Keychain(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_recovers_identity() {
        let identity = Identity::generate();
        let original_id = identity.id();
        let enc = seal_identity(&identity, b"correct horse battery staple", KdfParams::MOBILE).unwrap();
        let recovered = open_identity(&enc, b"correct horse battery staple").unwrap();
        assert_eq!(recovered.id(), original_id);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let identity = Identity::generate();
        let enc = seal_identity(&identity, b"right passphrase", KdfParams::MOBILE).unwrap();
        let result = open_identity(&enc, b"wrong passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn file_round_trip_preserves_identity() {
        let identity = Identity::generate();
        let enc = seal_identity(&identity, b"pw", KdfParams::MOBILE).unwrap();
        let path = std::env::temp_dir().join(format!("og-keystore-test-{}.bin", std::process::id()));
        save_to_file(&enc, &path).unwrap();
        let loaded = load_from_file(&path).unwrap();
        let recovered = open_identity(&loaded, b"pw").unwrap();
        assert_eq!(recovered.id(), identity.id());
        std::fs::remove_file(&path).ok();
    }
}
