use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// `KDF_RK` (Signal Double Ratchet spec): advances the root key using a
/// fresh DH output, producing a new root key and a new chain key.
pub fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut okm = [0u8; 64];
    hk.expand(b"og-ratchet-rk-v1", &mut okm).expect("64-byte okm is always valid for HKDF-SHA256");
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    new_ck.copy_from_slice(&okm[32..]);
    (new_rk, new_ck)
}

/// `KDF_CK` (Signal Double Ratchet spec): advances a chain key one step,
/// producing the next chain key and a one-time message key, via HMAC with
/// distinct single-byte constants so the two outputs are independent.
pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha256::new_from_slice(chain_key).expect("any length key is valid for HMAC");
    mac.update(&[0x01]);
    let mk = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(chain_key).expect("any length key is valid for HMAC");
    mac.update(&[0x02]);
    let new_ck = mac.finalize().into_bytes();

    let mut mk_out = [0u8; 32];
    let mut ck_out = [0u8; 32];
    mk_out.copy_from_slice(&mk);
    ck_out.copy_from_slice(&new_ck);
    (ck_out, mk_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_rk_is_deterministic() {
        let (rk1, ck1) = kdf_rk(&[1u8; 32], &[2u8; 32]);
        let (rk2, ck2) = kdf_rk(&[1u8; 32], &[2u8; 32]);
        assert_eq!(rk1, rk2);
        assert_eq!(ck1, ck2);
        assert_ne!(rk1, ck1);
    }

    #[test]
    fn kdf_ck_advances_and_message_key_differ() {
        let ck0 = [7u8; 32];
        let (ck1, mk1) = kdf_ck(&ck0);
        let (ck2, mk2) = kdf_ck(&ck1);
        assert_ne!(ck0, ck1);
        assert_ne!(ck1, ck2);
        assert_ne!(mk1, mk2);
        assert_ne!(ck1, mk1);
    }
}
