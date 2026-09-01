use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// Pins the client's connection to one exact, known certificate: the
/// relay's own long-lived self-signed identity, distributed out of band
/// (the same trust model as an SSH host key). There is no CA chain to
/// validate — if the presented certificate isn't byte-for-byte the one
/// pinned here, the connection is rejected outright, regardless of
/// whether it would otherwise look "valid".
///
/// This is deliberately simpler than SPKI-hash pinning: since the relay's
/// certificate is self-signed and never rotated silently, pinning the
/// whole certificate is no less secure and needs no ASN.1 parsing.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    expected: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl PinnedCertVerifier {
    pub fn new(expected: CertificateDer<'static>) -> Arc<Self> {
        Arc::new(Self { expected, provider: Arc::new(rustls::crypto::ring::default_provider()) })
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref() == self.expected.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General("relay certificate does not match the pinned identity".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
