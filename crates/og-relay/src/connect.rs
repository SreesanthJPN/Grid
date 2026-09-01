use ed25519_dalek::VerifyingKey;
use og_protocol::control::NONCE_LEN;
use og_protocol::{ConnectChallenge, ControlError, Frame};
use og_transport::{framing, BoxedRecv, BoxedSend, TransportError};
use rand_core::RngCore;

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("unexpected frame during connect handshake")]
    UnexpectedFrame,
    #[error(transparent)]
    ProofFailed(#[from] ControlError),
}

/// The relay side of the connect handshake: challenge the client to prove
/// it holds the private key for the ID it's about to claim, before
/// registering that ID in the router. This is the relay's only defense
/// against ID squatting/hijacking; it says nothing about, and grants no
/// visibility into, message content.
pub async fn challenge_and_verify(send: &mut BoxedSend, recv: &mut BoxedRecv) -> Result<VerifyingKey, ConnectError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);

    framing::send_frame(send, &Frame::ConnectChallenge(ConnectChallenge { nonce })).await?;

    match framing::recv_frame(recv).await? {
        Frame::ConnectProof(proof) => Ok(proof.verify(&nonce)?),
        _ => Err(ConnectError::UnexpectedFrame),
    }
}
