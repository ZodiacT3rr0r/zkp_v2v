//! Fiat-Shamir heuristic for non-interactive challenge derivation.
//!
//! Uses domain separation and explicit 8-byte big-endian length prefixes per element:
//!   challenge = SHA-256("V2V_ZKP_FS_v2" || count:u64_be || [len_i:u64_be || bytes_i]...) mod Q
//! preventing concatenation ambiguity (e.g., [12, 3] vs [1, 23]).

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

const FS_DOMAIN_TAG: &[u8] = b"V2V_ZKP_FS_v2";

/// Compute a length-prefixed, domain-separated Fiat-Shamir challenge from a slice of BigUint elements.
pub fn fiat_shamir(elems: &[&BigUint], q: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(FS_DOMAIN_TAG);
    hasher.update((elems.len() as u64).to_be_bytes());
    for e in elems {
        let bytes = e.to_bytes_be();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    let hash_bytes = hasher.finalize();
    BigUint::from_bytes_be(&hash_bytes) % q
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn test_q() -> BigUint {
        let pc = crate::group::PedersenCommitment::new();
        pc.q
    }

    #[test]
    fn test_fiat_shamir_deterministic() {
        let q = test_q();
        let a = BigUint::from(123u32);
        let b = BigUint::from(456u32);
        let r1 = fiat_shamir(&[&a, &b], &q);
        let r2 = fiat_shamir(&[&a, &b], &q);
        assert_eq!(r1, r2, "fiat_shamir must be deterministic");
    }

    #[test]
    fn test_fiat_shamir_order_sensitive() {
        let q = test_q();
        let a = BigUint::from(123u32);
        let b = BigUint::from(456u32);
        let r1 = fiat_shamir(&[&a, &b], &q);
        let r2 = fiat_shamir(&[&b, &a], &q);
        assert_ne!(r1, r2, "fiat_shamir must be order-sensitive");
    }

    #[test]
    fn test_fiat_shamir_in_range() {
        let q = test_q();
        let a = BigUint::from(123u32);
        let b = BigUint::from(456u32);
        let result = fiat_shamir(&[&a, &b], &q);
        assert!(result < q, "result must be less than Q");
    }

    #[test]
    fn test_fiat_shamir_single_element() {
        let q = test_q();
        let a = BigUint::from(999_999u32);
        let result = fiat_shamir(&[&a], &q);
        assert!(result < q, "single-element call must not panic and result < Q");
    }

    #[test]
    fn test_fiat_shamir_length_prefixed_no_concat_collision() {
        let q = test_q();
        let r1 = fiat_shamir(&[&BigUint::from(12u32), &BigUint::from(3u32)], &q);
        let r2 = fiat_shamir(&[&BigUint::from(1u32), &BigUint::from(23u32)], &q);
        assert_ne!(r1, r2, "length-prefixed transcript must separate [12, 3] from [1, 23]");
    }
}
