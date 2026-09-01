//! UniFFI binding surface: the thin, mobile-facing export layer over
//! `og-crypto`. The core crypto crate stays completely unaware of FFI —
//! it has no uniffi dependency of its own — so nothing about the
//! security-critical code changes shape to accommodate mobile bindings.
//! This crate only wraps and re-exposes what's already there.

uniffi::setup_scaffolding!();

use std::sync::Arc;

use og_crypto::identity::Identity;

#[derive(thiserror::Error, Debug, uniffi::Error)]
pub enum OgError {
    #[error("that id does not decode to a valid identity")]
    InvalidId,
}

/// A self-sovereign identity: one Ed25519 keypair, exposed to Kotlin/Swift
/// as an opaque object. The private key material never crosses the FFI
/// boundary as a plain value — only derived, non-secret operations
/// (like the shareable id string) do.
#[derive(uniffi::Object)]
pub struct OgIdentity {
    inner: Identity,
}

#[uniffi::export]
impl OgIdentity {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self { inner: Identity::generate() })
    }

    /// The shareable id string, e.g. "og1...".
    pub fn id(&self) -> String {
        self.inner.id()
    }
}

/// Decodes an "og1..." id string back into the raw 32-byte Ed25519
/// public key it encodes, or an error if it's malformed.
#[uniffi::export]
fn og_decode_id(id: String) -> Result<Vec<u8>, OgError> {
    og_crypto::identity::decode_id(&id).map(|vk| vk.to_bytes().to_vec()).map_err(|_| OgError::InvalidId)
}
