use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{ClientConfig, Endpoint};
use quinn_proto::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;

use crate::pinning::PinnedCertVerifier;
use crate::TransportError;

/// Builds a QUIC client endpoint that will only ever trust the one
/// pinned relay certificate — not any certificate authority.
pub fn make_client_endpoint(bind_addr: SocketAddr, pinned_relay_cert: CertificateDer<'static>) -> Result<Endpoint, TransportError> {
    crate::install_crypto_provider();
    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(PinnedCertVerifier::new(pinned_relay_cert))
        .with_no_client_auth();

    let quic_client_config = QuicClientConfig::try_from(rustls_config).map_err(|e| TransportError::Tls(e.to_string()))?;
    let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
    client_config.transport_config(crate::keep_alive_transport_config());

    let mut endpoint = Endpoint::client(bind_addr).map_err(|e| TransportError::Io(e.to_string()))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
