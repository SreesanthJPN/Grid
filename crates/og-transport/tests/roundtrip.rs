use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use og_protocol::Frame;
use og_transport::RelayIdentity;

#[tokio::test]
async fn client_and_server_exchange_a_frame_over_pinned_quic() {
    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let identity = RelayIdentity::generate().unwrap();

    let server_endpoint = og_transport::make_server_endpoint(bind_any, &identity).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();

        let request = og_transport::framing::recv_frame(&mut recv).await.unwrap();
        assert!(matches!(request, Frame::ConnectChallenge(_)));

        og_transport::framing::send_frame(&mut send, &Frame::ConnectAccepted).await.unwrap();
        send.finish().unwrap();

        // Keep the connection (and its as-yet-unacknowledged reply data)
        // alive until the client has read it and closed gracefully — a
        // handle drop in quinn immediately tears the connection down,
        // which can race ahead of in-flight stream data.
        connection.closed().await;
    });

    let client_endpoint = og_transport::make_client_endpoint(bind_any, identity.cert_der()).unwrap();
    let connection = client_endpoint.connect(server_addr, "og-relay").unwrap().await.unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();

    let challenge = Frame::ConnectChallenge(og_protocol::ConnectChallenge { nonce: [9u8; 32] });
    og_transport::framing::send_frame(&mut send, &challenge).await.unwrap();
    send.finish().unwrap();

    let reply = og_transport::framing::recv_frame(&mut recv).await.unwrap();
    assert!(matches!(reply, Frame::ConnectAccepted));

    connection.close(0u32.into(), b"done");
    server_task.await.unwrap();
}

#[tokio::test]
async fn client_rejects_a_relay_presenting_the_wrong_certificate() {
    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let identity = RelayIdentity::generate().unwrap();
    let decoy_identity = RelayIdentity::generate().unwrap();

    let server_endpoint = og_transport::make_server_endpoint(bind_any, &identity).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = server_endpoint.accept().await;
    });

    // A second, unrelated relay identity — simulates an attacker running a
    // QUIC server on the same address with a different keypair (or a
    // successful DNS-hijack redirecting the client to the wrong host).
    let client_endpoint = og_transport::make_client_endpoint(bind_any, decoy_identity.cert_der()).unwrap();
    let result = client_endpoint.connect(server_addr, "og-relay").unwrap().await;
    assert!(result.is_err(), "connection must fail when the presented cert doesn't match the pin");
}

#[tokio::test]
async fn client_and_server_exchange_a_frame_over_pinned_tcp() {
    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let identity = RelayIdentity::generate().unwrap();

    let acceptor = og_transport::make_tcp_listener(bind_any, &identity).await.unwrap();
    let server_addr = acceptor.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _peer) = acceptor.accept().await.unwrap();
        let (mut recv, mut send) = tokio::io::split(stream);

        let request = og_transport::framing::recv_frame(&mut recv).await.unwrap();
        assert!(matches!(request, Frame::ConnectChallenge(_)));

        og_transport::framing::send_frame(&mut send, &Frame::ConnectAccepted).await.unwrap();
    });

    let stream = og_transport::connect_tcp("127.0.0.1", server_addr.port(), None, identity.cert_der()).await.unwrap();
    let (mut recv, mut send) = tokio::io::split(stream);

    let challenge = Frame::ConnectChallenge(og_protocol::ConnectChallenge { nonce: [9u8; 32] });
    og_transport::framing::send_frame(&mut send, &challenge).await.unwrap();

    let reply = og_transport::framing::recv_frame(&mut recv).await.unwrap();
    assert!(matches!(reply, Frame::ConnectAccepted));

    server_task.await.unwrap();
}

#[tokio::test]
async fn tcp_client_rejects_a_relay_presenting_the_wrong_certificate() {
    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let identity = RelayIdentity::generate().unwrap();
    let decoy_identity = RelayIdentity::generate().unwrap();

    let acceptor = og_transport::make_tcp_listener(bind_any, &identity).await.unwrap();
    let server_addr = acceptor.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = acceptor.accept().await;
    });

    let result = og_transport::connect_tcp("127.0.0.1", server_addr.port(), None, decoy_identity.cert_der()).await;
    assert!(result.is_err(), "connection must fail when the presented cert doesn't match the pin");
}
