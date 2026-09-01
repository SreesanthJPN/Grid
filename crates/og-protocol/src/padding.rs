/// Fixed padding buckets (bytes). Chosen as a geometric progression so many
/// different real message sizes round up to a size shared by many other
/// messages, denying a passive observer message-length as a content
/// fingerprinting signal.
const BUCKETS: &[usize] = &[256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

pub const MAX_PAYLOAD_LEN: usize = 65536 - LEN_PREFIX;
const LEN_PREFIX: usize = 4;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PaddingError {
    #[error("payload of {0} bytes exceeds the largest padding bucket")]
    TooLarge(usize),
    #[error("padded buffer too short to contain a length prefix")]
    Truncated,
    #[error("declared length exceeds the padded buffer")]
    LengthMismatch,
}

pub fn pad(data: &[u8]) -> Result<Vec<u8>, PaddingError> {
    let needed = data.len() + LEN_PREFIX;
    let bucket = *BUCKETS
        .iter()
        .find(|&&b| b >= needed)
        .ok_or(PaddingError::TooLarge(data.len()))?;
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out.resize(bucket, 0);
    Ok(out)
}

pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, PaddingError> {
    if padded.len() < LEN_PREFIX {
        return Err(PaddingError::Truncated);
    }
    let len = u32::from_le_bytes(padded[0..LEN_PREFIX].try_into().unwrap()) as usize;
    if LEN_PREFIX + len > padded.len() {
        return Err(PaddingError::LengthMismatch);
    }
    Ok(padded[LEN_PREFIX..LEN_PREFIX + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_round_trips() {
        for len in [0usize, 1, 255, 256, 257, 4092, 4093, 65532] {
            let data = vec![0xABu8; len];
            let padded = pad(&data).unwrap();
            assert!(BUCKETS.contains(&padded.len()));
            let recovered = unpad(&padded).unwrap();
            assert_eq!(recovered, data);
        }
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let data = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(pad(&data), Err(PaddingError::TooLarge(_))));
    }

    #[test]
    fn different_lengths_in_same_bucket_produce_same_size() {
        let a = pad(&vec![1u8; 10]).unwrap();
        let b = pad(&vec![2u8; 200]).unwrap();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn truncated_input_is_rejected_not_panicking() {
        assert!(matches!(unpad(&[0u8; 2]), Err(PaddingError::Truncated)));
        assert!(matches!(unpad(&[]), Err(PaddingError::Truncated)));
    }

    #[test]
    fn corrupted_length_prefix_is_rejected_not_panicking() {
        let mut padded = pad(b"hello").unwrap();
        padded[0..4].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert!(matches!(unpad(&padded), Err(PaddingError::LengthMismatch)));
    }
}
