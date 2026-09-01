//! End-to-end proof that two clients can establish an authenticated,
//! encrypted session and exchange text through the relay — and that the
//! relay's own routing path never carries anything but ciphertext. This
//! also exercises the relay's other core security properties: proof of
//! possession at connect time, and the strict zero-storage behavior when
//! a recipient isn't currently connected.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ed25519_dalek::VerifyingKey;
use og_crypto::identity::Identity;
use og_crypto::ratchet::Header;
use og_crypto::session;
use og_protocol::{ConnectProof, Envelope, Frame};
use og_transport::framing;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use serde::{Deserialize, Serialize};

/// A minimal stand-in for what Milestone 7's CLI will formalize: how two
/// sessions frame their handshake vs. ongoing ratchet messages inside an
/// `Envelope`'s opaque payload. The relay never parses this — it only
/// ever sees `Envelope.payload` as opaque bytes.
#[derive(Serialize, Deserialize)]
enum AppMessage {
    HandshakeMsg1(Vec<u8>),
    HandshakeMsg2(Vec<u8>),
    Ratchet { header: Header, ciphertext: Vec<u8> },
}

struct Client {
    identity: Identity,
    _connection: Connection,
    send: SendStream,
    recv: RecvStream,
    seq: u64,
}

impl Client {
    fn id(&self) -> [u8; 32] {
        self.identity.verifying_key().to_bytes()
    }

    /// Sends an application message wrapped in an `Envelope`, and returns
    /// the exact bytes that crossed the wire to the relay — the thing a
    /// test proving "the relay can't decrypt" needs to inspect.
    async fn send_app(&mut self, to_id: [u8; 32], msg: &AppMessage) -> Vec<u8> {
        let payload = postcard::to_allocvec(msg).unwrap();
        let envelope = Envelope::new(to_id, self.id(), self.seq, &payload).unwrap();
        self.seq += 1;
        let frame = Frame::Envelope(envelope);
        let wire_bytes = og_protocol::encode(&frame).unwrap();
        framing::send_frame(&mut self.send, &frame).await.unwrap();
        wire_bytes
    }

    async fn recv_frame(&mut self) -> Frame {
        framing::recv_frame(&mut self.recv).await.unwrap()
    }

    async fn recv_app(&mut self) -> AppMessage {
        match self.recv_frame().await {
            Frame::Envelope(env) => {
                let payload = env.unpad_payload().unwrap();
                postcard::from_bytes(&payload).unwrap()
            }
            other => panic!("expected an Envelope frame, got {other:?}"),
        }
    }
}

async fn start_relay() -> (SocketAddr, rustls::pki_types::CertificateDer<'static>) {
    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let identity = og_transport::RelayIdentity::generate().unwrap();
    let cert_der = identity.cert_der();
    let endpoint = og_transport::make_server_endpoint(bind_any, &identity).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let router = og_relay::router::Router::new();
    tokio::spawn(og_relay::run_relay_quic(endpoint, router));
    (addr, cert_der)
}

fn client_endpoint(cert_der: rustls::pki_types::CertificateDer<'static>) -> Endpoint {
    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    og_transport::make_client_endpoint(bind_any, cert_der).unwrap()
}

/// Connects and completes the relay's proof-of-possession handshake with
/// the client's real identity.
async fn connect_client(endpoint: &Endpoint, server_addr: SocketAddr, identity: Identity) -> Client {
    let connection = endpoint.connect(server_addr, "og-relay").unwrap().await.unwrap();
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();

    let nonce = match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectChallenge(c) => c.nonce,
        other => panic!("expected ConnectChallenge, got {other:?}"),
    };
    let proof = ConnectProof::create(&identity, &nonce);
    framing::send_frame(&mut send, &Frame::ConnectProof(proof)).await.unwrap();
    match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectAccepted => {}
        other => panic!("expected ConnectAccepted, got {other:?}"),
    }

    Client { identity, _connection: connection, send, recv, seq: 0 }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_clients_establish_a_session_and_the_relay_never_sees_plaintext() {
    let (server_addr, cert_der) = start_relay().await;

    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let bob_verifying = bob_identity.verifying_key();
    let alice_verifying = alice_identity.verifying_key();

    let mut alice = connect_client(&client_endpoint(cert_der.clone()), server_addr, alice_identity).await;
    let mut bob = connect_client(&client_endpoint(cert_der), server_addr, bob_identity).await;

    // --- session establishment (Noise_IK + PQ hybrid + ratchet init), the
    // handshake bytes themselves also travel as opaque envelope payloads ---
    let (pending, msg1) = session::start_initiator(&alice.identity, &bob_verifying).unwrap();
    alice.send_app(bob.id(), &AppMessage::HandshakeMsg1(msg1)).await;

    let msg1_bytes = match bob.recv_app().await {
        AppMessage::HandshakeMsg1(b) => b,
        _ => panic!("expected HandshakeMsg1"),
    };
    let (msg2, mut bob_ratchet) = session::respond(&bob.identity, &msg1_bytes, &alice_verifying).unwrap();
    bob.send_app(alice.id(), &AppMessage::HandshakeMsg2(msg2)).await;

    let msg2_bytes = match alice.recv_app().await {
        AppMessage::HandshakeMsg2(b) => b,
        _ => panic!("expected HandshakeMsg2"),
    };
    let mut alice_ratchet = pending.finish(&msg2_bytes).unwrap();

    // --- an actual application message ---
    let plaintext = b"hello bob, this is off-grid and the relay can't read this";
    let (header, ciphertext) = alice_ratchet.encrypt(plaintext, b"").unwrap();

    // The ciphertext itself must not leak the plaintext.
    assert!(!contains_subsequence(&ciphertext, plaintext));

    let wire_bytes = alice.send_app(bob.id(), &AppMessage::Ratchet { header, ciphertext }).await;

    // This is the actual proof that "the relay cannot decrypt": scan the
    // EXACT bytes that cross the relay's routing path (the encoded
    // Frame::Envelope, which the relay parses only for
    // to_id/from_id/length and forwards byte-for-byte, unmodified) for
    // the plaintext, in both raw and UTF-8-decoded form.
    assert!(!contains_subsequence(&wire_bytes, plaintext), "plaintext must never appear in what the relay routes");
    if let Ok(s) = std::str::from_utf8(&wire_bytes) {
        assert!(!s.contains(std::str::from_utf8(plaintext).unwrap()));
    }

    let received = match bob.recv_app().await {
        AppMessage::Ratchet { header, ciphertext } => (header, ciphertext),
        _ => panic!("expected Ratchet message"),
    };
    let decrypted = bob_ratchet.decrypt(&received.0, &received.1, b"").unwrap();
    assert_eq!(decrypted, plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_rejects_a_connection_that_cannot_prove_its_claimed_id() {
    let (server_addr, cert_der) = start_relay().await;
    let endpoint = client_endpoint(cert_der);

    let victim = Identity::generate();
    let attacker = Identity::generate();

    let connection = endpoint.connect(server_addr, "og-relay").unwrap().await.unwrap();
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();

    let nonce = match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectChallenge(c) => c.nonce,
        other => panic!("expected ConnectChallenge, got {other:?}"),
    };

    // The attacker signs the nonce with their OWN key, but claims the
    // victim's id in the proof — exactly the id-squatting attack the
    // relay's proof-of-possession step exists to stop.
    let signature = attacker.sign(&nonce);
    let forged = ConnectProof { id: VerifyingKey::to_bytes(&victim.verifying_key()), signature: signature.to_bytes().to_vec() };
    framing::send_frame(&mut send, &Frame::ConnectProof(forged)).await.unwrap();

    match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectRejected { .. } => {}
        other => panic!("expected ConnectRejected, got {other:?}"),
    }
    connection.close(0u32.into(), b"done");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_connection_claiming_a_live_id_is_rejected() {
    let (server_addr, cert_der) = start_relay().await;
    let identity_bytes = Identity::generate().seed_bytes();

    let first = connect_client(&client_endpoint(cert_der.clone()), server_addr, Identity::from_seed(identity_bytes)).await;

    // A second connection claiming the exact same id, while the first is
    // still live — the relay holds no queue, so this can only mean
    // squatting/collision, not a legitimate second device.
    let connection = client_endpoint(cert_der).connect(server_addr, "og-relay").unwrap().await.unwrap();
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    let nonce = match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectChallenge(c) => c.nonce,
        other => panic!("expected ConnectChallenge, got {other:?}"),
    };
    let proof = ConnectProof::create(&Identity::from_seed(identity_bytes), &nonce);
    framing::send_frame(&mut send, &Frame::ConnectProof(proof)).await.unwrap();
    match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectRejected { .. } => {}
        other => panic!("expected ConnectRejected for a duplicate live id, got {other:?}"),
    }
    connection.close(0u32.into(), b"done");

    drop(first);
}

#[tokio::test(flavor = "multi_thread")]
async fn sending_to_an_offline_recipient_gets_an_immediate_response_with_nothing_buffered() {
    let (server_addr, cert_der) = start_relay().await;

    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let bob_id = bob_identity.verifying_key().to_bytes();

    let mut alice = connect_client(&client_endpoint(cert_der.clone()), server_addr, alice_identity).await;

    // Bob has never connected. Alice's message must be rejected
    // immediately, not queued.
    alice.send_app(bob_id, &AppMessage::HandshakeMsg1(vec![1, 2, 3])).await;
    match alice.recv_frame().await {
        Frame::RecipientUnreachable { to_id } => assert_eq!(to_id, bob_id),
        other => panic!("expected RecipientUnreachable, got {other:?}"),
    }

    // Bob connects only now. If the relay buffered anything, it would
    // arrive here — it must not.
    let mut bob = connect_client(&client_endpoint(cert_der), server_addr, bob_identity).await;
    let timed_out = tokio::time::timeout(std::time::Duration::from_millis(300), bob.recv_frame()).await;
    assert!(timed_out.is_err(), "bob must receive nothing: the zero-storage relay buffers no messages");
}
