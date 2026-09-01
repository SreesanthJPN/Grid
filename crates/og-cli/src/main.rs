mod contacts;
mod identity_store;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use clap::Parser;
use crossterm::style::Stylize;
use ed25519_dalek::VerifyingKey;
use og_crypto::identity::{self, Identity};
use og_crypto::ratchet::Ratchet;
use og_crypto::session::{self, PendingInitiator};
use og_protocol::{Envelope, Frame, PlaintextMessage, SessionMessage};
use og_transport::{BoxedRecv, BoxedSend};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use contacts::Contacts;

/// Off-grid encrypted chat — terminal client. Every message exchanged
/// with a peer is end-to-end encrypted before it ever reaches the relay,
/// regardless of which transport carries it there.
#[derive(Parser, Debug)]
#[command(name = "og-cli")]
struct Args {
    /// Relay address to connect to. For QUIC, "host:port" (e.g.
    /// 127.0.0.1:4433). For TCP, also "host:port", where host may be a
    /// Tor ".onion" address — resolution happens at the SOCKS proxy, not
    /// locally, so this is not required to be a literal IP.
    #[arg(long)]
    relay: String,

    /// Which transport to use. QUIC is direct-connection only; TCP is
    /// required to reach a relay through a SOCKS proxy (e.g. Tor).
    #[arg(long, value_enum, default_value = "quic")]
    transport: Transport,

    /// SOCKS5 proxy address for the TCP transport, e.g. Tor's default
    /// local proxy at 127.0.0.1:9050. Ignored for QUIC. Required to
    /// reach a ".onion" relay address.
    #[arg(long)]
    socks_proxy: Option<SocketAddr>,

    /// Path to the relay's certificate file (printed by og-relay on
    /// startup), pinned instead of trusting any certificate authority.
    #[arg(long)]
    relay_cert: PathBuf,

    /// Directory for this client's identity and contacts.
    #[arg(long, default_value = ".offgrid")]
    data_dir: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Quic,
    Tcp,
}

/// How to close the connection gracefully on quit. An abrupt process
/// exit without this would leave the relay thinking this id still has a
/// live connection — for QUIC, until its idle timeout fires; TCP doesn't
/// have that problem (a socket shutdown is visible to the peer almost
/// immediately), but is handled the same way for symmetry.
enum ConnectionHandle {
    Quic(quinn::Connection),
    Tcp,
}

impl ConnectionHandle {
    async fn close_gracefully(&self, send: &mut BoxedSend) {
        match self {
            ConnectionHandle::Quic(connection) => connection.close(0u32.into(), b"client quit"),
            ConnectionHandle::Tcp => {
                let _ = send.shutdown().await;
            }
        }
    }
}

enum Event {
    Line(String),
    Frame(Frame),
    NetworkClosed,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Identity load/create happens before the async runtime starts: it
    // needs a masked passphrase prompt via crossterm raw mode, which is
    // simplest to reason about as a plain blocking step up front.
    let identity = identity_store::load_or_create(&args.data_dir.join("identity.bin"))?;
    let contacts = Contacts::load_or_default(args.data_dir.join("contacts.bin"));

    tokio::runtime::Runtime::new()?.block_on(async_main(args, identity, contacts))
}

async fn async_main(args: Args, identity: Identity, mut contacts: Contacts) -> anyhow::Result<()> {
    let cert_der = rustls::pki_types::CertificateDer::from(std::fs::read(&args.relay_cert)?);

    let (conn_handle, mut send, mut recv): (ConnectionHandle, BoxedSend, BoxedRecv) = match args.transport {
        Transport::Quic => {
            let relay_addr: SocketAddr = args.relay.parse().map_err(|_| anyhow::anyhow!("--relay must be host:port for QUIC (got {:?})", args.relay))?;
            let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let endpoint = og_transport::make_client_endpoint(bind_any, cert_der)?;
            let connection = endpoint.connect(relay_addr, "og-relay")?.await?;
            // The relay speaks first on this connection (it issues the
            // connect challenge), so it is the one that opens the
            // stream; we accept it.
            let (send, recv) = connection.accept_bi().await?;
            (ConnectionHandle::Quic(connection), Box::new(send), Box::new(recv))
        }
        Transport::Tcp => {
            let (host, port_str) = args.relay.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("--relay must be host:port"))?;
            let port: u16 = port_str.parse().map_err(|_| anyhow::anyhow!("invalid port in --relay"))?;
            if args.socks_proxy.is_none() && host.ends_with(".onion") {
                anyhow::bail!("a .onion relay address requires --socks-proxy (e.g. 127.0.0.1:9050 for Tor)");
            }
            let stream = og_transport::connect_tcp(host, port, args.socks_proxy, cert_der).await?;
            let (recv, send) = tokio::io::split(stream);
            (ConnectionHandle::Tcp, Box::new(send), Box::new(recv))
        }
    };

    let nonce = match og_transport::framing::recv_frame(&mut recv).await? {
        Frame::ConnectChallenge(c) => c.nonce,
        other => anyhow::bail!("relay sent an unexpected frame: {other:?}"),
    };
    let proof = og_protocol::ConnectProof::create(&identity, &nonce);
    og_transport::framing::send_frame(&mut send, &Frame::ConnectProof(proof)).await?;
    match og_transport::framing::recv_frame(&mut recv).await? {
        Frame::ConnectAccepted => {}
        Frame::ConnectRejected { reason } => anyhow::bail!("relay rejected this connection: {reason}"),
        other => anyhow::bail!("relay sent an unexpected frame: {other:?}"),
    }

    print_system(&format!("connected. your id: {}", identity.id()));
    print_system("commands: /whoami  /add <nickname> <og1...>  /contacts  /talk <nickname|og1...>  /quit");

    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();

    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(Event::Line(line)).is_err() {
                    break;
                }
            }
        });
    }

    tokio::spawn(async move {
        loop {
            match og_transport::framing::recv_frame(&mut recv).await {
                Ok(frame) => {
                    if tx.send(Event::Frame(frame)).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = tx.send(Event::NetworkClosed);
                    break;
                }
            }
        }
    });

    let mut sessions: HashMap<[u8; 32], Ratchet> = HashMap::new();
    let mut pending: HashMap<[u8; 32], PendingInitiator> = HashMap::new();
    let mut active: Option<[u8; 32]> = None;
    let mut seq: u64 = 0;
    let my_id = identity.verifying_key().to_bytes();

    while let Some(event) = rx.recv().await {
        match event {
            Event::NetworkClosed => {
                print_error("connection to relay lost");
                break;
            }
            Event::Line(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some(rest) = line.strip_prefix('/') {
                    let should_quit =
                        handle_command(rest, &identity, &mut contacts, &mut active, &mut pending, &sessions, &mut send, &mut seq, my_id)
                            .await;
                    if should_quit {
                        break;
                    }
                    continue;
                }
                let Some(peer) = active else {
                    print_error("no active conversation — use /talk <nickname|og1...> first");
                    continue;
                };
                let Some(ratchet) = sessions.get_mut(&peer) else {
                    print_error("session with this peer isn't established yet — try again in a moment");
                    continue;
                };
                let plaintext = postcard::to_allocvec(&PlaintextMessage::Text(line.to_string())).unwrap();
                let ad = session_ad(&my_id, &peer);
                match ratchet.encrypt(&plaintext, &ad) {
                    Ok((header, ciphertext)) => {
                        let msg = SessionMessage::Ratchet { header, ciphertext };
                        if send_envelope(&mut send, peer, my_id, &mut seq, &msg).await.is_ok() {
                            print_outgoing(line);
                        } else {
                            print_error("failed to send — connection may be lost");
                        }
                    }
                    Err(e) => print_error(&format!("encryption failed: {e}")),
                }
            }
            Event::Frame(Frame::Envelope(env)) => {
                if let Err(e) =
                    handle_incoming_envelope(env, &identity, &contacts, &mut sessions, &mut pending, &mut send, &mut seq, my_id).await
                {
                    print_error(&format!("failed to process incoming message: {e}"));
                }
            }
            Event::Frame(Frame::RecipientUnreachable { to_id }) => {
                print_error(&format!("{} is not currently reachable", display_name(&contacts, &to_id)));
            }
            Event::Frame(other) => {
                print_error(&format!("unexpected frame from relay: {other:?}"));
            }
        }
    }

    // Close gracefully rather than letting the process just end: an
    // abrupt exit leaves the relay's connection-loss detection to fall
    // back on the QUIC idle timeout, during which this id would look
    // (wrongly) like it still has a live connection to anyone else.
    conn_handle.close_gracefully(&mut send).await;
    Ok(())
}

/// Returns `true` if this command means the client should quit.
#[allow(clippy::too_many_arguments)]
async fn handle_command(
    cmd: &str,
    identity: &Identity,
    contacts: &mut Contacts,
    active: &mut Option<[u8; 32]>,
    pending: &mut HashMap<[u8; 32], PendingInitiator>,
    sessions: &HashMap<[u8; 32], Ratchet>,
    send: &mut BoxedSend,
    seq: &mut u64,
    my_id: [u8; 32],
) -> bool {
    let mut parts = cmd.split_whitespace();
    match parts.next().unwrap_or("") {
        "whoami" => print_system(&format!("your id: {}", identity.id())),
        "add" => {
            let (Some(nick), Some(id_str)) = (parts.next(), parts.next()) else {
                print_error("usage: /add <nickname> <og1...>");
                return false;
            };
            match identity::decode_id(id_str) {
                Ok(vk) => {
                    contacts.add(nick.to_string(), vk.to_bytes());
                    let _ = contacts.save();
                    print_system(&format!("added {nick} -> {id_str}"));
                }
                Err(_) => print_error("that doesn't look like a valid og1... id"),
            }
        }
        "contacts" => {
            for (nick, id) in contacts.list() {
                println!("  {nick}  {}", identity::encode_id(&id));
            }
        }
        "talk" => {
            let Some(target) = parts.next() else {
                print_error("usage: /talk <nickname|og1...>");
                return false;
            };
            let Some(peer_id) = contacts.resolve(target) else {
                print_error("unknown nickname and not a valid og1... id");
                return false;
            };
            *active = Some(peer_id);
            print_system(&format!("talking to {}", display_name(contacts, &peer_id)));
            if !sessions.contains_key(&peer_id) && !pending.contains_key(&peer_id) {
                match VerifyingKey::from_bytes(&peer_id) {
                    Ok(peer_vk) => match session::start_initiator(identity, &peer_vk) {
                        Ok((pending_session, msg1)) => {
                            pending.insert(peer_id, pending_session);
                            let msg = SessionMessage::HandshakeMsg1(msg1);
                            if send_envelope(send, peer_id, my_id, seq, &msg).await.is_ok() {
                                print_system("establishing session...");
                            }
                        }
                        Err(e) => print_error(&format!("failed to start session: {e}")),
                    },
                    Err(_) => print_error("invalid peer id"),
                }
            }
        }
        "quit" => {
            print_system("bye");
            return true;
        }
        other => print_error(&format!("unknown command: /{other}")),
    }
    false
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming_envelope(
    env: Envelope,
    identity: &Identity,
    contacts: &Contacts,
    sessions: &mut HashMap<[u8; 32], Ratchet>,
    pending: &mut HashMap<[u8; 32], PendingInitiator>,
    send: &mut BoxedSend,
    seq: &mut u64,
    my_id: [u8; 32],
) -> anyhow::Result<()> {
    let payload = env.unpad_payload()?;
    let msg: SessionMessage = postcard::from_bytes(&payload)?;
    let from_id = env.from_id;

    match msg {
        SessionMessage::HandshakeMsg1(bytes) => {
            let peer_vk = VerifyingKey::from_bytes(&from_id)?;
            let (msg2, ratchet) = session::respond(identity, &bytes, &peer_vk).map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;
            sessions.insert(from_id, ratchet);
            let reply = SessionMessage::HandshakeMsg2(msg2);
            send_envelope(send, from_id, my_id, seq, &reply).await?;
            print_system(&format!("{} started a session with you", display_name(contacts, &from_id)));
        }
        SessionMessage::HandshakeMsg2(bytes) => {
            let pending_session = pending.remove(&from_id).ok_or_else(|| anyhow::anyhow!("no matching pending session"))?;
            let ratchet = pending_session.finish(&bytes).map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;
            sessions.insert(from_id, ratchet);
            print_system(&format!("session established with {}", display_name(contacts, &from_id)));
        }
        SessionMessage::Ratchet { header, ciphertext } => {
            let ratchet = sessions.get_mut(&from_id).ok_or_else(|| anyhow::anyhow!("no established session with this sender"))?;
            let ad = session_ad(&from_id, &my_id);
            let plaintext = ratchet.decrypt(&header, &ciphertext, &ad).map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;
            let PlaintextMessage::Text(text) = postcard::from_bytes(&plaintext)?;
            print_incoming(&display_name(contacts, &from_id), &text);
        }
    }
    Ok(())
}

async fn send_envelope(send: &mut BoxedSend, to_id: [u8; 32], my_id: [u8; 32], seq: &mut u64, msg: &SessionMessage) -> anyhow::Result<()> {
    let payload = postcard::to_allocvec(msg)?;
    let envelope = Envelope::new(to_id, my_id, *seq, &payload)?;
    *seq += 1;
    og_transport::framing::send_frame(send, &Frame::Envelope(envelope)).await?;
    Ok(())
}

/// Associated data binding a ratchet message to the specific pair of
/// participants, in a fixed sender-then-recipient order both sides can
/// reconstruct identically from their own point of view.
fn session_ad(sender: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(sender);
    ad.extend_from_slice(recipient);
    ad
}

fn display_name(contacts: &Contacts, id: &[u8; 32]) -> String {
    contacts.nickname_for(id).map(str::to_string).unwrap_or_else(|| identity::encode_id(id))
}

fn print_system(msg: &str) {
    println!("{}", format!("· {msg}").dark_grey());
}

fn print_error(msg: &str) {
    println!("{}", format!("! {msg}").red());
}

fn print_incoming(who: &str, text: &str) {
    println!("{} {text}", format!("{who}:").cyan().bold());
}

fn print_outgoing(text: &str) {
    println!("{} {text}", "you:".green().bold());
}
