use og_protocol::Frame;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::TransportError;

/// Generous bound on one framed message, well above what a padded
/// `og_protocol` envelope or control message ever produces — this exists
/// purely to stop a peer from claiming an enormous length prefix and
/// forcing an unbounded allocation before any content is even parsed.
const MAX_FRAME_LEN: u32 = 128 * 1024;

/// Wire framing on top of any ordered byte stream: `[4-byte LE
/// length][og_protocol frame bytes]`. Generic over `AsyncWrite` so the
/// exact same framing works whether the underlying connection is a QUIC
/// stream or a plain TCP+TLS stream (e.g. reached through Tor) — a
/// `Frame` value still needs explicit message boundaries either way.
pub async fn send_frame<W: AsyncWrite + Unpin + ?Sized>(stream: &mut W, frame: &Frame) -> Result<(), TransportError> {
    let bytes = og_protocol::encode(frame).map_err(|e| TransportError::Protocol(e.to_string()))?;
    let len = u32::try_from(bytes.len()).map_err(|_| TransportError::Protocol("frame too large to encode".into()))?;
    stream.write_all(&len.to_le_bytes()).await.map_err(|e| TransportError::Io(e.to_string()))?;
    stream.write_all(&bytes).await.map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(())
}

pub async fn recv_frame<R: AsyncRead + Unpin + ?Sized>(stream: &mut R) -> Result<Frame, TransportError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| TransportError::Io(e.to_string()))?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(TransportError::Protocol("frame exceeds maximum allowed length".into()));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.map_err(|e| TransportError::Io(e.to_string()))?;
    og_protocol::decode(&buf).map_err(|e| TransportError::Protocol(e.to_string()))
}
