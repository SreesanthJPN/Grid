use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::TransportError;

/// The relay's own long-lived identity: a self-signed certificate and its
/// private key, shared between the QUIC and TCP+TLS listeners so a relay
/// has exactly one identity to distribute and pin, regardless of which
/// transport a client reaches it through.
pub struct RelayIdentity {
    pub cert_der: CertificateDer<'static>,
    priv_key_der_bytes: Vec<u8>,
}

impl RelayIdentity {
    pub fn generate() -> Result<Self, TransportError> {
        let cert = rcgen::generate_simple_self_signed(vec!["og-relay".into()]).map_err(|e| TransportError::Tls(e.to_string()))?;
        let cert_der = CertificateDer::from(cert.cert);
        let priv_key_der_bytes = cert.signing_key.serialize_der();
        Ok(Self { cert_der, priv_key_der_bytes })
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    pub fn private_key(&self) -> PrivatePkcs8KeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.priv_key_der_bytes.clone())
    }
}
