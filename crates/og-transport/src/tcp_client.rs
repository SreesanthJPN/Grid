use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_socks::tcp::Socks5Stream;

use crate::pinning::PinnedCertVerifier;
use crate::TransportError;

/// Connects to `target_host:target_port` — pass a `.onion` address here
/// to reach a Tor hidden service — and wraps the connection in TLS
/// pinned to `pinned_relay_cert`. If `socks_proxy` is set, the TCP
/// connection is made through that SOCKS5 proxy (e.g. Tor's local proxy,
/// typically `127.0.0.1:9050`) with the hostname resolved BY the proxy,
/// never locally: resolving a `.onion` address any other way doesn't
/// work, and for an ordinary hostname it would leak the destination to
/// a DNS resolver outside the Tor circuit.
pub async fn connect_tcp(
    target_host: &str,
    target_port: u16,
    socks_proxy: Option<SocketAddr>,
    pinned_relay_cert: CertificateDer<'static>,
) -> Result<TlsStream<TcpStream>, TransportError> {
    crate::install_crypto_provider();

    let tcp = match socks_proxy {
        Some(proxy) => Socks5Stream::connect(proxy, (target_host, target_port))
            .await
            .map_err(|e| TransportError::Socks(e.to_string()))?
            .into_inner(),
        None => TcpStream::connect((target_host, target_port)).await.map_err(|e| TransportError::Io(e.to_string()))?,
    };

    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(PinnedCertVerifier::new(pinned_relay_cert))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(rustls_config));

    // The TLS layer still wants a `ServerName`, but our trust model
    // doesn't depend on it matching anything real — the custom verifier
    // ignores it and checks the pinned certificate bytes instead — so
    // any syntactically valid name works here.
    let server_name = ServerName::try_from("og-relay").map_err(|e| TransportError::Tls(e.to_string()))?;
    connector.connect(server_name, tcp).await.map_err(|e| TransportError::Tls(e.to_string()))
}
