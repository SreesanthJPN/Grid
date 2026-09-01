use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::{RelayIdentity, TransportError};

/// Plain-TCP-plus-TLS counterpart to the QUIC listener, for reaching the
/// relay over paths that can't carry QUIC's UDP traffic — most notably a
/// Tor onion service, which only ever forwards TCP. Authenticated the
/// same way as the QUIC path: a pinned self-signed certificate, no CA.
pub struct TcpAcceptor {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TcpAcceptor {
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.listener.local_addr().map_err(|e| TransportError::Io(e.to_string()))
    }

    pub async fn accept(&self) -> Result<(TlsStream<TcpStream>, SocketAddr), TransportError> {
        let (tcp, peer_addr) = self.listener.accept().await.map_err(|e| TransportError::Io(e.to_string()))?;
        let tls = self.acceptor.accept(tcp).await.map_err(|e| TransportError::Tls(e.to_string()))?;
        Ok((tls, peer_addr))
    }
}

pub async fn make_tcp_listener(bind_addr: SocketAddr, identity: &RelayIdentity) -> Result<TcpAcceptor, TransportError> {
    crate::install_crypto_provider();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert_der()], identity.private_key().into())
        .map_err(|e| TransportError::Tls(e.to_string()))?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(bind_addr).await.map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(TcpAcceptor { listener, acceptor })
}
