//! Proves the relay's TCP+TLS path (the one reachable through a Tor
//! onion service, which can't carry QUIC's UDP traffic) works on its
//! own, and that a client connected over TCP and a client connected over
//! QUIC can reach each other through the same relay — the whole point of
//! running both listeners off one shared identity and router.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use og_crypto::identity::Identity;
use og_protocol::{ConnectProof, Envelope, Frame};
use og_transport::{framing, BoxedRecv, BoxedSend, RelayIdentity};

async fn start_dual_relay() -> (SocketAddr, SocketAddr, rustls::pki_types::CertificateDer<'static>) {
    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let identity = RelayIdentity::generate().unwrap();
    let cert_der = identity.cert_der();

    let quic_endpoint = og_transport::make_server_endpoint(bind_any, &identity).unwrap();
    let quic_addr = quic_endpoint.local_addr().unwrap();

    let tcp_acceptor = og_transport::make_tcp_listener(bind_any, &identity).await.unwrap();
    let tcp_addr = tcp_acceptor.local_addr().unwrap();

    let router = og_relay::router::Router::new();
    tokio::spawn(og_relay::run_relay_quic(quic_endpoint, router.clone()));
    tokio::spawn(og_relay::run_relay_tcp(tcp_acceptor, router));

    (quic_addr, tcp_addr, cert_der)
}

/// Connects over TCP and completes the relay's proof-of-possession
/// handshake, returning boxed send/recv halves so the rest of the test
/// can drive them the same way regardless of transport.
async fn connect_tcp_client(tcp_addr: SocketAddr, cert_der: rustls::pki_types::CertificateDer<'static>, identity: &Identity) -> (BoxedSend, BoxedRecv) {
    let stream = og_transport::connect_tcp("127.0.0.1", tcp_addr.port(), None, cert_der).await.unwrap();
    let (recv, send) = tokio::io::split(stream);
    let mut send: BoxedSend = Box::new(send);
    let mut recv: BoxedRecv = Box::new(recv);

    let nonce = match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectChallenge(c) => c.nonce,
        other => panic!("expected ConnectChallenge, got {other:?}"),
    };
    let proof = ConnectProof::create(identity, &nonce);
    framing::send_frame(&mut send, &Frame::ConnectProof(proof)).await.unwrap();
    match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectAccepted => {}
        other => panic!("expected ConnectAccepted, got {other:?}"),
    }
    (send, recv)
}

async fn connect_quic_client(
    quic_addr: SocketAddr,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    identity: &Identity,
) -> (BoxedSend, BoxedRecv) {
    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint = og_transport::make_client_endpoint(bind_any, cert_der).unwrap();
    let connection = endpoint.connect(quic_addr, "og-relay").unwrap().await.unwrap();
    let (send, recv) = connection.accept_bi().await.unwrap();
    let mut send: BoxedSend = Box::new(send);
    let mut recv: BoxedRecv = Box::new(recv);
    // Leak the connection deliberately: dropping it would tear the QUIC
    // connection down immediately, and this test only needs it to
    // outlive the function, not to be cleaned up carefully.
    std::mem::forget(connection);

    let nonce = match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectChallenge(c) => c.nonce,
        other => panic!("expected ConnectChallenge, got {other:?}"),
    };
    let proof = ConnectProof::create(identity, &nonce);
    framing::send_frame(&mut send, &Frame::ConnectProof(proof)).await.unwrap();
    match framing::recv_frame(&mut recv).await.unwrap() {
        Frame::ConnectAccepted => {}
        other => panic!("expected ConnectAccepted, got {other:?}"),
    }
    (send, recv)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_client_completes_connect_handshake_through_the_relay() {
    let (_quic_addr, tcp_addr, cert_der) = start_dual_relay().await;
    let alice = Identity::generate();
    // Success is just not panicking anywhere inside connect_tcp_client.
    let _ = connect_tcp_client(tcp_addr, cert_der, &alice).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_client_and_tcp_client_reach_each_other_through_the_same_relay() {
    let (quic_addr, tcp_addr, cert_der) = start_dual_relay().await;

    let alice = Identity::generate(); // connects over QUIC
    let bob = Identity::generate(); // connects over TCP (the Tor-reachable path)
    let bob_id = bob.verifying_key().to_bytes();
    let alice_id = alice.verifying_key().to_bytes();

    let (mut alice_send, _alice_recv) = connect_quic_client(quic_addr, cert_der.clone(), &alice).await;
    let (_bob_send, mut bob_recv) = connect_tcp_client(tcp_addr, cert_der, &bob).await;

    let envelope = Envelope::new(bob_id, alice_id, 0, b"reaches bob over tcp from a quic sender").unwrap();
    framing::send_frame(&mut alice_send, &Frame::Envelope(envelope)).await.unwrap();

    match framing::recv_frame(&mut bob_recv).await.unwrap() {
        Frame::Envelope(env) => {
            assert_eq!(env.from_id, alice_id);
            assert_eq!(env.unpad_payload().unwrap(), b"reaches bob over tcp from a quic sender");
        }
        other => panic!("expected an Envelope, got {other:?}"),
    }
}
