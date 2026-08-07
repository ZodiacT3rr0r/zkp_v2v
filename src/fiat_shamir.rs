//! Fiat-Shamir heuristic for non-interactive challenge derivation.
//!
//! challenge = SHA-256(decimal(e0) || decimal(e1) || ...) mod Q
//! where decimal(x) = base-10 string of BigUint, no leading zeros, no separator.

use num_bigint::BigUint;
use sha2::{Sha256, Digest};

/// Compute a Fiat-Shamir challenge from a slice of BigUint elements.
///
/// The challenge is SHA-256 of the concatenation of each element's
/// decimal string representation, reduced modulo `q`.
pub fn fiat_shamir(elems: &[&BigUint], q: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    for e in elems {
        hasher.update(e.to_str_radix(10).as_bytes());
    }
    let hash_bytes = hasher.finalize();
    BigUint::from_bytes_be(&hash_bytes) % q
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    /// Q for testing — use the actual IKE Group 2 Q.
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
}
