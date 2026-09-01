pub mod client_conn;
pub mod framing;
pub mod identity;
pub mod pinning;
pub mod server_conn;
pub mod tcp_client;
pub mod tcp_server;

pub use client_conn::make_client_endpoint;
pub use identity::RelayIdentity;
pub use server_conn::make_server_endpoint;
pub use tcp_client::connect_tcp;
pub use tcp_server::make_tcp_listener;

use tokio::io::{AsyncRead, AsyncWrite};

/// Either transport's read/write half, boxed to a common type so
/// connection-handling code (the relay's per-connection loop, the CLI's
/// send/receive tasks) doesn't need to be generic or duplicated per
/// transport. The cost is one allocation and dynamic dispatch per
/// connection — irrelevant next to a QUIC/TLS handshake.
pub type BoxedRecv = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxedSend = Box<dyn AsyncWrite + Unpin + Send>;

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(String),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("socks proxy error: {0}")]
    Socks(String),
}

/// Installs `ring` as the process-wide default rustls crypto provider.
/// Required once per process before building any endpoint. Safe to call
/// more than once (e.g. from both a server and a client in the same test
/// binary) — a second install attempt is treated as a no-op, not an error.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// quinn's default QUIC idle timeout is 30 seconds with no automatic
/// keep-alive, so a connection with no application traffic (e.g. a chat
/// session that's just idle, not actively sending) gets silently torn
/// down. Sending a PING comfortably inside that window keeps it alive
/// regardless of whether either side has anything to say.
pub(crate) fn keep_alive_transport_config() -> std::sync::Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    std::sync::Arc::new(config)
}
