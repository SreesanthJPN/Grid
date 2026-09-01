pub mod app;
pub mod control;
pub mod envelope;
pub mod padding;

use serde::{Deserialize, Serialize};

pub use app::{PlaintextMessage, SessionMessage};
pub use control::{ConnectChallenge, ConnectProof, ControlError};
pub use envelope::Envelope;

pub const PROTOCOL_VERSION: u8 = 1;

/// Every message that crosses a client<->relay QUIC stream. Kept as one
/// versioned enum from day one so the wire format can evolve later without
/// breaking the relay's "opaque bytes" property for the `Envelope` variant.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Frame {
    ConnectChallenge(ConnectChallenge),
    ConnectProof(ConnectProof),
    ConnectAccepted,
    ConnectRejected { reason: String },
    Envelope(Envelope),
    /// Sent back to a sender when `to_id` has no live connection. There is
    /// no queueing behind this: the zero-storage relay model means the
    /// sender must retry once the recipient is online.
    RecipientUnreachable { to_id: [u8; 32] },
}

#[derive(thiserror::Error, Debug)]
pub enum FrameError {
    #[error("failed to encode frame")]
    Encode,
    #[error("failed to decode frame (malformed bytes or unsupported version)")]
    Decode,
}

/// Wire framing: `[1-byte protocol version][postcard-encoded Frame]`. The
/// version byte lets a receiver reject an unknown/future version before
/// attempting to parse attacker-controlled bytes as a `Frame` at all.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(64);
    out.push(PROTOCOL_VERSION);
    let body = postcard::to_allocvec(frame).map_err(|_| FrameError::Encode)?;
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
    let (version, body) = bytes.split_first().ok_or(FrameError::Decode)?;
    if *version != PROTOCOL_VERSION {
        return Err(FrameError::Decode);
    }
    postcard::from_bytes(body).map_err(|_| FrameError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_frame_round_trips() {
        let env = Envelope::new([1u8; 32], [2u8; 32], 42, b"ciphertext").unwrap();
        let frame = Frame::Envelope(env);
        let bytes = encode(&frame).unwrap();
        let decoded = decode(&bytes).unwrap();
        match decoded {
            Frame::Envelope(e) => assert_eq!(e.unpad_payload().unwrap(), b"ciphertext"),
            _ => panic!("wrong variant decoded"),
        }
    }

    #[test]
    fn control_frames_round_trip() {
        let challenge = Frame::ConnectChallenge(ConnectChallenge { nonce: [7u8; control::NONCE_LEN] });
        let bytes = encode(&challenge).unwrap();
        assert!(matches!(decode(&bytes).unwrap(), Frame::ConnectChallenge(_)));

        let unreachable = Frame::RecipientUnreachable { to_id: [3u8; 32] };
        let bytes = encode(&unreachable).unwrap();
        assert!(matches!(decode(&bytes).unwrap(), Frame::RecipientUnreachable { .. }));
    }

    #[test]
    fn wrong_version_byte_is_rejected() {
        let frame = Frame::ConnectAccepted;
        let mut bytes = encode(&frame).unwrap();
        bytes[0] = PROTOCOL_VERSION.wrapping_add(1);
        assert!(matches!(decode(&bytes), Err(FrameError::Decode)));
    }

    #[test]
    fn garbage_bytes_are_rejected_without_panicking() {
        // A grab-bag of malformed inputs an attacker-controlled peer might
        // send: empty, truncated, and structurally-plausible-but-wrong.
        let cases: &[&[u8]] = &[
            &[],
            &[PROTOCOL_VERSION],
            &[PROTOCOL_VERSION, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0xFF; 32],
            &[PROTOCOL_VERSION, 0x00, 0x01, 0x02],
        ];
        for case in cases {
            assert!(decode(case).is_err());
        }
    }
}
