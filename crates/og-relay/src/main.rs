use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use og_transport::RelayIdentity;
use tracing::info;

/// The dumb, strictly-stateless off-grid relay. It moves opaque encrypted
/// bytes between two connected IDs and nothing else: no accounts, no
/// message storage (not even encrypted), no content logging. If a
/// recipient isn't connected right now, the sender is told immediately —
/// there is no queue to wait in.
///
/// Both listeners (QUIC and TCP) share one relay identity/certificate,
/// so there is exactly one thing for clients to pin regardless of which
/// transport they reach the relay through. At least one must be enabled.
#[derive(Parser, Debug)]
struct Args {
    /// QUIC listen address, for clients connecting directly. Omit for a
    /// TCP-only deployment (e.g. behind a Tor onion service, where QUIC's
    /// UDP traffic can't be carried anyway).
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Plain-TCP+TLS listen address, for paths that can't carry QUIC's
    /// UDP traffic — most notably a Tor onion service, which only ever
    /// forwards TCP. Typically bound to localhost and pointed to by a
    /// HiddenServicePort in torrc.
    #[arg(long)]
    listen_tcp: Option<SocketAddr>,

    /// Where to write this run's relay certificate, for clients to pin.
    /// NOTE: a fresh identity (and certificate) is generated every time
    /// the relay starts, so this file must be redistributed to clients
    /// after every restart in the current version.
    #[arg(long, default_value = "og-relay-cert.der")]
    cert_out: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if args.listen.is_none() && args.listen_tcp.is_none() {
        anyhow::bail!("at least one of --listen (QUIC) or --listen-tcp must be given");
    }

    let identity = RelayIdentity::generate()?;
    std::fs::write(&args.cert_out, identity.cert_der())?;
    info!(cert_file = %args.cert_out.display(), "distribute this certificate file to clients for pinning");

    let router = og_relay::router::Router::new();

    let quic_task = if let Some(quic_addr) = args.listen {
        let quic_endpoint = og_transport::make_server_endpoint(quic_addr, &identity)?;
        info!(bind = %quic_addr, "og-relay listening (quic)");
        Some(tokio::spawn(og_relay::run_relay_quic(quic_endpoint, router.clone())))
    } else {
        None
    };

    let tcp_task = if let Some(tcp_addr) = args.listen_tcp {
        let acceptor = og_transport::make_tcp_listener(tcp_addr, &identity).await?;
        info!(bind = %tcp_addr, "og-relay listening (tcp)");
        Some(tokio::spawn(og_relay::run_relay_tcp(acceptor, router)))
    } else {
        None
    };

    match (quic_task, tcp_task) {
        (Some(quic_task), Some(tcp_task)) => {
            tokio::select! {
                r = quic_task => r??,
                r = tcp_task => r??,
            }
        }
        (Some(quic_task), None) => quic_task.await??,
        (None, Some(tcp_task)) => tcp_task.await??,
        (None, None) => unreachable!("checked above"),
    }

    Ok(())
}
