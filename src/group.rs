//! Pedersen commitment scheme over the IKE Group 2 safe prime.
//!
//! Group parameters:
//!   P = RFC 2409 IKE Group 2 safe prime (1024-bit)
//!   G = 2
//!   Q = (P - 1) / 2
//!   H = u^2 mod P where u is derived via domain-separated SHA-256 hash-to-subgroup
//!       (nothing-up-my-sleeve construction — nobody knows log_G(H))

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use sha2::{Sha256, Digest};

/// IKE Group 2 safe prime P (1024-bit), hex-encoded.
const P_HEX: &str = "\
    FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
    FFFFFFFFFFFFFFFF";

/// Pedersen commitment: Cm(x, r) = G^x · H^r mod P
#[derive(Clone, Debug)]
pub struct PedersenCommitment {
    pub p: BigUint,
    pub g: BigUint,
    pub h: BigUint,
    pub q: BigUint,
}

impl PedersenCommitment {
    /// Construct a new PedersenCommitment with the IKE Group 2 parameters.
    ///
    /// H is derived via nothing-up-my-sleeve hash-to-subgroup (NOT G^seed):
    ///   u = expand_sha256("V2V_ZKP_h_v2_num") mod (P - 3) + 2
    ///   H = u^2 mod P  (projects u directly into prime-order-Q subgroup G_Q)
    /// Because H is never computed by raising G to a known exponent, nobody
    /// knows log_G(H), preserving computational binding.
    pub fn new() -> Self {
        let p = BigUint::parse_bytes(P_HEX.as_bytes(), 16)
            .expect("P_HEX is a valid hex constant");
        let g = BigUint::from(2u32);
        let q = (&p - BigUint::one()) / BigUint::from(2u32);

        let mut u_bytes = [0u8; 128];
        for chunk_idx in 0u8..4 {
            let mut hasher = Sha256::new();
            hasher.update(b"V2V_ZKP_h_v2_num");
            hasher.update([chunk_idx]);
            let digest = hasher.finalize();
            let start = (chunk_idx as usize) * 32;
            u_bytes[start..start + 32].copy_from_slice(&digest);
        }
        let u = (BigUint::from_bytes_be(&u_bytes) % (&p - BigUint::from(3u32)))
            + BigUint::from(2u32);
        let h = u.modpow(&BigUint::from(2u32), &p);
        assert!(
            h != BigUint::one() && h != g && h.modpow(&q, &p) == BigUint::one(),
            "derived H must be a non-trivial generator of subgroup G_Q"
        );

        PedersenCommitment { p, g, h, q }
    }

    /// Check that `elem` lies in the prime-order-Q subgroup G_Q of Z*_P:
    ///   1 <= elem < P  and  elem^Q == 1 (mod P).
    pub fn is_valid_element(&self, elem: &BigUint) -> bool {
        elem >= &BigUint::one()
            && elem < &self.p
            && elem.modpow(&self.q, &self.p) == BigUint::one()
    }

    /// Commit to value `x` with randomness `r`: Cm(x,r) = G^x · H^r mod P
    pub fn commit(&self, x: &BigUint, r: &BigUint) -> BigUint {
        let gx = self.g.modpow(x, &self.p);
        let hr = self.h.modpow(r, &self.p);
        (gx * hr) % &self.p
    }

    /// Commit to value `x` with a fresh random `r`.
    /// Returns (commitment, r).
    pub fn commit_with_random(&self, x: &BigUint) -> (BigUint, BigUint) {
        let r = self.rand_zq();
        let cm = self.commit(x, &r);
        (cm, r)
    }

    /// Verify that `cm` is a valid commitment to `(x, r)`.
    pub fn verify_open(&self, cm: &BigUint, x: &BigUint, r: &BigUint) -> bool {
        &self.commit(x, r) == cm
    }

    /// Homomorphic multiplication: cm1 · cm2 mod P
    /// Corresponds to Cm(x1+x2, r1+r2) when cm1=Cm(x1,r1) and cm2=Cm(x2,r2).
    pub fn mul(&self, cm1: &BigUint, cm2: &BigUint) -> BigUint {
        (cm1 * cm2) % &self.p
    }

    /// Homomorphic scaling: cm^s mod P
    /// Corresponds to Cm(s·x, s·r) when cm=Cm(x,r).
    pub fn scale(&self, cm: &BigUint, s: &BigUint) -> BigUint {
        cm.modpow(s, &self.p)
    }

    /// Generate a uniform random value from {1, ..., Q-1}.
    pub fn rand_zq(&self) -> BigUint {
        let mut rng = rand::rngs::OsRng;
        loop {
            let v = rng.gen_biguint_below(&self.q);
            if v > BigUint::from(0u32) {
                return v;
            }
        }
    }

    /// Modular inverse of `a` mod Q: a^(Q-2) mod Q.
    pub fn modinv(&self, a: &BigUint) -> BigUint {
        let exp = &self.q - BigUint::from(2u32);
        a.modpow(&exp, &self.q)
    }

    /// Modular inverse of `a` mod P: a^(P-2) mod P.
    /// Needed by OR-proof to divide commitments in the group Z*_P.
    pub fn modinv_p(&self, a: &BigUint) -> BigUint {
        let exp = &self.p - BigUint::from(2u32);
        a.modpow(&exp, &self.p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    fn test_commit_open() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(42u32);
        let (cm, r) = pc.commit_with_random(&x);
        assert!(pc.verify_open(&cm, &x, &r), "commitment should open correctly");
    }

    #[test]
    fn test_commit_wrong_x() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(42u32);
        let (cm, r) = pc.commit_with_random(&x);
        let wrong_x = BigUint::from(43u32);
        assert!(
            !pc.verify_open(&cm, &wrong_x, &r),
            "commitment should not open with wrong x"
        );
    }

    #[test]
    fn test_homomorphic_add() {
        let pc = PedersenCommitment::new();
        let x1 = BigUint::from(100u32);
        let x2 = BigUint::from(200u32);
        let (cm1, r1) = pc.commit_with_random(&x1);
        let (cm2, r2) = pc.commit_with_random(&x2);
        let product = pc.mul(&cm1, &cm2);
        let sum_x = BigUint::from(300u32);
        let sum_r = (&r1 + &r2) % &pc.q;
        let expected = pc.commit(&sum_x, &sum_r);
        assert_eq!(product, expected, "homomorphic addition must hold");
    }

    #[test]
    fn test_homomorphic_scale() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(50u32);
        let s = BigUint::from(3u32);
        let (cm, r) = pc.commit_with_random(&x);
        let scaled = pc.scale(&cm, &s);
        let expected_x = BigUint::from(150u32);
        let expected_r = (&r * &s) % &pc.q;
        let expected = pc.commit(&expected_x, &expected_r);
        assert_eq!(scaled, expected, "homomorphic scaling must hold");
    }

    #[test]
    fn test_modinv_q() {
        let pc = PedersenCommitment::new();
        let a = pc.rand_zq();
        let inv = pc.modinv(&a);
        let product = (&a * &inv) % &pc.q;
        assert_eq!(product, BigUint::one(), "a * modinv(a) mod Q must be 1");
    }

    #[test]
    fn test_modinv_p() {
        let pc = PedersenCommitment::new();
        let a = pc.rand_zq();
        let inv = pc.modinv_p(&a);
        let product = (&a * &inv) % &pc.p;
        assert_eq!(product, BigUint::one(), "a * modinv_p(a) mod P must be 1");
    }

    #[test]
    fn test_h_differs_from_g() {
        let pc = PedersenCommitment::new();
        assert_ne!(pc.h, pc.g, "H must differ from G");
        assert_ne!(pc.h, BigUint::one(), "H must not be 1");
        assert!(pc.is_valid_element(&pc.h), "H must be in prime-order subgroup G_Q");
        assert!(pc.is_valid_element(&pc.g), "G must be in prime-order subgroup G_Q");
        // P - 1 has order 2 (not in G_Q) and must be rejected.
        let p_minus_1 = &pc.p - BigUint::one();
        assert!(!pc.is_valid_element(&p_minus_1), "P-1 is outside G_Q");
    }
}
