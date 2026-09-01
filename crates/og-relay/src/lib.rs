pub mod connect;
pub mod router;

use std::sync::Arc;
use std::time::Duration;

use og_protocol::{Envelope, Frame};
use og_transport::tcp_server::TcpAcceptor;
use og_transport::{BoxedRecv, BoxedSend};
use quinn::Endpoint;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{info, warn};

use router::Router;

/// Runs the relay's QUIC accept loop against an already-bound endpoint
/// until it closes, routing all connections into `router`. Split out from
/// `main` so integration tests can drive the exact same
/// connection-handling logic the real binary uses.
pub async fn run_relay_quic(endpoint: Endpoint, router: Arc<Router>) -> anyhow::Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_quic_connection(incoming, router).await {
                warn!(error = %e, "quic connection ended");
            }
        });
    }
    Ok(())
}

async fn handle_quic_connection(incoming: quinn::Incoming, router: Arc<Router>) -> anyhow::Result<()> {
    let connection = incoming.await?;
    // The relay speaks first (it issues the connect challenge), so it must
    // be the one to open the stream: a stream only becomes visible to the
    // peer's `accept_bi()` once the opener actually writes to it, and the
    // client has nothing to say until it's seen the challenge.
    let (send, recv) = connection.open_bi().await?;
    let result = handle_authenticated_connection(Box::new(send), Box::new(recv), router).await;
    // Give the peer a moment to receive any final message (e.g. a
    // rejection) before this handle drops — a handle drop tears the QUIC
    // connection down immediately, which can race ahead of in-flight
    // stream data that hasn't been acknowledged yet.
    let _ = tokio::time::timeout(Duration::from_secs(2), connection.closed()).await;
    result
}

/// Runs the relay's TCP+TLS accept loop until the listener errors,
/// routing all connections into `router`. This is the path for reaching
/// the relay somewhere that can't carry QUIC's UDP traffic — most
/// notably a Tor onion service, which only ever forwards TCP.
pub async fn run_relay_tcp(acceptor: TcpAcceptor, router: Arc<Router>) -> anyhow::Result<()> {
    loop {
        let (stream, peer_addr) = acceptor.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            let (recv, send) = tokio::io::split(stream);
            if let Err(e) = handle_authenticated_connection(Box::new(send), Box::new(recv), router).await {
                warn!(error = %e, peer = %peer_addr, "tcp connection ended");
            }
        });
    }
}

/// Transport-agnostic connection handling, shared by both the QUIC and
/// TCP+TLS accept loops: proof-of-possession, registration, then
/// forwarding for the connection's lifetime.
async fn handle_authenticated_connection(mut send: BoxedSend, mut recv: BoxedRecv, router: Arc<Router>) -> anyhow::Result<()> {
    let verifying_key = match connect::challenge_and_verify(&mut send, &mut recv).await {
        Ok(vk) => vk,
        Err(e) => {
            let _ = og_transport::framing::send_frame(&mut send, &Frame::ConnectRejected { reason: e.to_string() }).await;
            let _ = send.shutdown().await;
            return Err(e.into());
        }
    };
    let id = verifying_key.to_bytes();
    let id_str = og_crypto::identity::encode_id(&id);

    let (outbox_tx, mut outbox_rx) = mpsc::unbounded_channel();
    if !router.register(id, outbox_tx) {
        og_transport::framing::send_frame(&mut send, &Frame::ConnectRejected { reason: "id already has a live connection".into() })
            .await?;
        let _ = send.shutdown().await;
        return Ok(());
    }
    info!(id = %id_str, "client connected");

    og_transport::framing::send_frame(&mut send, &Frame::ConnectAccepted).await?;

    let result = serve_connection(&mut send, &mut recv, &router, id, &mut outbox_rx).await;
    router.unregister(&id);
    info!(id = %id_str, "client disconnected");
    result
}

/// Services one authenticated connection for its lifetime: frames the
/// client sends (outgoing envelopes) are routed to their recipient, and
/// envelopes routed to this client by others are written back out. Only
/// routing metadata (`to_id`/`from_id`/length) is ever inspected — the
/// `payload` bytes pass through untouched and unlogged.
async fn serve_connection(
    send: &mut BoxedSend,
    recv: &mut BoxedRecv,
    router: &Arc<Router>,
    my_id: [u8; 32],
    outbox_rx: &mut mpsc::UnboundedReceiver<Envelope>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            incoming = og_transport::framing::recv_frame(recv) => {
                match incoming? {
                    Frame::Envelope(env) => {
                        if env.from_id != my_id {
                            anyhow::bail!("client sent an envelope with a forged from_id");
                        }
                        let to_id = env.to_id;
                        if !router.route(env) {
                            og_transport::framing::send_frame(send, &Frame::RecipientUnreachable { to_id }).await?;
                        }
                    }
                    other => anyhow::bail!("unexpected frame on an established connection: {other:?}"),
                }
            }
            Some(env) = outbox_rx.recv() => {
                og_transport::framing::send_frame(send, &Frame::Envelope(env)).await?;
            }
        }
    }
}
