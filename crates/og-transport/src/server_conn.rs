use std::net::SocketAddr;

use quinn::{Endpoint, ServerConfig};

use crate::{RelayIdentity, TransportError};

/// Builds a QUIC server endpoint bound to `bind_addr`, authenticated by
/// `identity`. There is no CA involved, by design: the relay's identity
/// is a keypair it controls, not a name a CA vouches for — clients pin
/// the certificate directly (see `pinning::PinnedCertVerifier`).
pub fn make_server_endpoint(bind_addr: SocketAddr, identity: &RelayIdentity) -> Result<Endpoint, TransportError> {
    crate::install_crypto_provider();
    let mut server_config = ServerConfig::with_single_cert(vec![identity.cert_der()], identity.private_key().into())
        .map_err(|e| TransportError::Tls(e.to_string()))?;
    server_config.transport_config(crate::keep_alive_transport_config());
    Endpoint::server(server_config, bind_addr).map_err(|e| TransportError::Io(e.to_string()))
}
