//! Sigma protocol ZKP constructions.
//!
//! Implements four proof types:
//! - ZkpCm:  proof of commitment opening
//! - OrBit:  OR proof that a commitment is to 0 or 1
//! - ZkpNN:  non-negativity proof via bit decomposition (0..2^bits-1)
//! - ZkpSum: proof that committed values sum to a public total

use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Serialize, Deserialize};

use crate::group::PedersenCommitment;
use crate::fiat_shamir::fiat_shamir;

// ── Serde helpers ────────────────────────────────────────────────────────────

/// Serialize/deserialize a single BigUint as a decimal string.
pub mod biguint_serde {
    use num_bigint::BigUint;
    use num_traits::Num;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_str_radix(10))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BigUint::from_str_radix(&s, 10).map_err(serde::de::Error::custom)
    }
}

/// Serialize/deserialize a Vec<BigUint> as a Vec of decimal strings.
pub mod vec_biguint_serde {
    use num_bigint::BigUint;
    use num_traits::Num;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[BigUint], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let strings: Vec<String> = values.iter().map(|v| v.to_str_radix(10)).collect();
        strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<BigUint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .iter()
            .map(|s| BigUint::from_str_radix(s, 10).map_err(serde::de::Error::custom))
            .collect()
    }
}

// ── Modular arithmetic helpers ───────────────────────────────────────────────

/// (a - b) mod q, safe for BigUint (no underflow).
fn mod_sub(a: &BigUint, b: &BigUint, q: &BigUint) -> BigUint {
    let a_mod = a % q;
    let b_mod = b % q;
    if a_mod >= b_mod {
        (a_mod - b_mod) % q
    } else {
        (q + a_mod - b_mod) % q
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ZkpCm — proof of commitment opening
// ═══════════════════════════════════════════════════════════════════════════════

/// Proof that the prover knows (x, r) such that cm = G^x · H^r mod P.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkpCmProof {
    #[serde(with = "biguint_serde")]
    pub cm: BigUint,
    #[serde(with = "biguint_serde")]
    pub C0: BigUint,
    #[serde(with = "biguint_serde")]
    pub zx: BigUint,
    #[serde(with = "biguint_serde")]
    pub zr: BigUint,
}

/// Prove knowledge of (x, r) opening commitment cm = G^x · H^r mod P.
#[allow(non_snake_case)]
pub fn zkpcm_prove(pc: &PedersenCommitment, x: &BigUint, r: &BigUint) -> ZkpCmProof {
    let cm = pc.commit(x, r);
    let xp = pc.rand_zq();
    let rp = pc.rand_zq();
    let C0 = pc.commit(&xp, &rp);
    let b = fiat_shamir(&[&cm, &C0], &pc.q);
    let zx = (&xp + &b * x) % &pc.q;
    let zr = (&rp + &b * r) % &pc.q;
    ZkpCmProof { cm, C0, zx, zr }
}

/// Verify a ZkpCm proof.
#[allow(non_snake_case)]
pub fn zkpcm_verify(pc: &PedersenCommitment, proof: &ZkpCmProof) -> bool {
    if !pc.is_valid_element(&proof.cm) || !pc.is_valid_element(&proof.C0) {
        return false;
    }
    let b = fiat_shamir(&[&proof.cm, &proof.C0], &pc.q);
    // lhs = G^zx · H^zr mod P
    let lhs = pc.commit(&proof.zx, &proof.zr);
    // rhs = C0 · cm^b mod P
    let cm_b = proof.cm.modpow(&b, &pc.p);
    let rhs = (&proof.C0 * &cm_b) % &pc.p;
    lhs == rhs
}

// ═══════════════════════════════════════════════════════════════════════════════
// OR-bit — proves cm commits to 0 or 1
// ═══════════════════════════════════════════════════════════════════════════════

/// OR proof that a commitment cm = G^b · H^r mod P with b ∈ {0, 1}.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OrBitProof {
    #[serde(with = "biguint_serde")]
    pub C0_0: BigUint,
    #[serde(with = "biguint_serde")]
    pub b0: BigUint,
    #[serde(with = "biguint_serde")]
    pub zr0: BigUint,
    #[serde(with = "biguint_serde")]
    pub C0_1: BigUint,
    #[serde(with = "biguint_serde")]
    pub b1: BigUint,
    #[serde(with = "biguint_serde")]
    pub zr1: BigUint,
}

/// Prove that cm commits to bit value `b` ∈ {0, 1} with randomness `r`.
/// Returns Err if b is not 0 or 1.
#[allow(non_snake_case)]
pub fn or_bit_prove(
    pc: &PedersenCommitment,
    b: u8,
    r: &BigUint,
    cm: &BigUint,
) -> Result<OrBitProof, String> {
    if b > 1 {
        return Err(format!("or_bit_prove: b must be 0 or 1, got {}", b));
    }

    if b == 0 {
        // Real branch 0: cm = H^r (since G^0 = 1)
        let rp = pc.rand_zq();
        let C0_0 = pc.h.modpow(&rp, &pc.p);

        // Simulate branch 1
        let b1s = pc.rand_zq();
        let zr1s = pc.rand_zq();
        // cm_g = cm · G^(-1) mod P
        let g_inv = pc.modinv_p(&pc.g);
        let cm_g = (cm * &g_inv) % &pc.p;
        // C0_1 = H^zr1s · (cm_g^b1s)^(-1) mod P
        let cm_g_pow = cm_g.modpow(&b1s, &pc.p);
        let cm_g_pow_inv = pc.modinv_p(&cm_g_pow);
        let C0_1 = (pc.h.modpow(&zr1s, &pc.p) * &cm_g_pow_inv) % &pc.p;

        let beta = fiat_shamir(&[cm, &C0_0, &C0_1], &pc.q);
        let b0 = mod_sub(&beta, &b1s, &pc.q);
        let zr0 = (&rp + &b0 * r) % &pc.q;

        Ok(OrBitProof {
            C0_0,
            b0,
            zr0,
            C0_1,
            b1: b1s,
            zr1: zr1s,
        })
    } else {
        // b == 1
        // Real branch 1: cm = G · H^r, so cm_g = cm · G^(-1) = H^r
        let rp = pc.rand_zq();
        let C0_1 = pc.h.modpow(&rp, &pc.p);

        // Simulate branch 0
        let b0s = pc.rand_zq();
        let zr0s = pc.rand_zq();
        // C0_0 = H^zr0s · (cm^b0s)^(-1) mod P
        let cm_pow = cm.modpow(&b0s, &pc.p);
        let cm_pow_inv = pc.modinv_p(&cm_pow);
        let C0_0 = (pc.h.modpow(&zr0s, &pc.p) * &cm_pow_inv) % &pc.p;

        let beta = fiat_shamir(&[cm, &C0_0, &C0_1], &pc.q);
        let b1 = mod_sub(&beta, &b0s, &pc.q);
        let zr1 = (&rp + &b1 * r) % &pc.q;

        Ok(OrBitProof {
            C0_0,
            b0: b0s,
            zr0: zr0s,
            C0_1,
            b1,
            zr1,
        })
    }
}

/// Verify an OR-bit proof against commitment `cm`.
#[allow(non_snake_case)]
pub fn or_bit_verify(pc: &PedersenCommitment, cm: &BigUint, proof: &OrBitProof) -> bool {
    if !pc.is_valid_element(cm)
        || !pc.is_valid_element(&proof.C0_0)
        || !pc.is_valid_element(&proof.C0_1)
    {
        return false;
    }
    let beta = fiat_shamir(&[cm, &proof.C0_0, &proof.C0_1], &pc.q);

    // Check (b0 + b1) mod Q == beta
    if (&proof.b0 + &proof.b1) % &pc.q != beta {
        return false;
    }

    // Branch 0: H^zr0 mod P == C0_0 · cm^b0 mod P
    let lhs0 = pc.h.modpow(&proof.zr0, &pc.p);
    let rhs0 = (&proof.C0_0 * cm.modpow(&proof.b0, &pc.p)) % &pc.p;
    if lhs0 != rhs0 {
        return false;
    }

    // Branch 1: H^zr1 mod P == C0_1 · cm_g^b1 mod P
    let g_inv = pc.modinv_p(&pc.g);
    let cm_g = (cm * &g_inv) % &pc.p;
    let lhs1 = pc.h.modpow(&proof.zr1, &pc.p);
    let rhs1 = (&proof.C0_1 * cm_g.modpow(&proof.b1, &pc.p)) % &pc.p;
    if lhs1 != rhs1 {
        return false;
    }

    true
}

// ═══════════════════════════════════════════════════════════════════════════════
// ZkpNN — non-negativity proof (bit decomposition, covers 0..2^bits-1)
// ═══════════════════════════════════════════════════════════════════════════════

/// Proof that a committed value is non-negative and fits within `bits` bits.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkpNNProof {
    #[serde(with = "biguint_serde")]
    pub cm: BigUint,
    pub bits: u8,
    #[serde(with = "vec_biguint_serde")]
    pub bit_cms: Vec<BigUint>,
    pub bit_pfs: Vec<OrBitProof>,
    #[serde(with = "biguint_serde")]
    pub sc_C0: BigUint,
    #[serde(with = "biguint_serde")]
    pub sc_zr: BigUint,
}

/// Prove that x is non-negative and x < 2^bits.
/// Returns Err if x >= 2^bits.
#[allow(non_snake_case)]
pub fn zkpnn_prove(
    pc: &PedersenCommitment,
    x: &BigUint,
    r: &BigUint,
    bits: u8,
) -> Result<ZkpNNProof, String> {
    let max_val = BigUint::one() << (bits as usize);
    if x >= &max_val {
        return Err(format!(
            "zkpnn_prove: x ({}) >= 2^{} ({})",
            x, bits, max_val
        ));
    }

    let cm = pc.commit(x, r);

    // Bit decomposition
    let mut bit_cms = Vec::with_capacity(bits as usize);
    let mut bit_pfs = Vec::with_capacity(bits as usize);
    let mut rs = Vec::with_capacity(bits as usize);

    for i in 0..bits as usize {
        let bit_val = if (x >> i) & BigUint::one() == BigUint::one() {
            1u8
        } else {
            0u8
        };
        let ri = pc.rand_zq();
        let cmi = pc.commit(&BigUint::from(bit_val as u32), &ri);
        let pfi = or_bit_prove(pc, bit_val, &ri, &cmi)?;
        bit_cms.push(cmi);
        bit_pfs.push(pfi);
        rs.push(ri);
    }

    // agg_r = sum(ri * 2^i) mod Q
    let mut agg_r = BigUint::zero();
    for i in 0..bits as usize {
        let weight = BigUint::one() << i;
        agg_r = (&agg_r + &rs[i] * &weight) % &pc.q;
    }

    // delta_r = (agg_r - r) mod Q
    let delta_r = mod_sub(&agg_r, r, &pc.q);

    // product = prod(cmi^(2^i) mod P)
    let mut product = BigUint::one();
    for i in 0..bits as usize {
        let exp = BigUint::one() << i;
        let cm_pow = bit_cms[i].modpow(&exp, &pc.p);
        product = (&product * &cm_pow) % &pc.p;
    }

    // Schnorr-like proof that ratio = H^delta_r (binds cm, product, sc_C0, and all bit_cms)
    let rp = pc.rand_zq();
    let sc_C0 = pc.h.modpow(&rp, &pc.p);
    let mut transcript: Vec<&BigUint> = Vec::with_capacity(3 + bit_cms.len());
    transcript.push(&cm);
    transcript.push(&product);
    transcript.push(&sc_C0);
    for bcm in &bit_cms {
        transcript.push(bcm);
    }
    let beta = fiat_shamir(&transcript, &pc.q);
    let sc_zr = (&rp + &beta * &delta_r) % &pc.q;

    Ok(ZkpNNProof {
        cm,
        bits,
        bit_cms,
        bit_pfs,
        sc_C0,
        sc_zr,
    })
}

/// Verify a non-negativity proof.
#[allow(non_snake_case)]
pub fn zkpnn_verify(pc: &PedersenCommitment, proof: &ZkpNNProof) -> bool {
    let bits = proof.bits as usize;

    if bits == 0 || proof.bit_cms.len() != bits || proof.bit_pfs.len() != bits {
        return false;
    }
    if !pc.is_valid_element(&proof.cm) || !pc.is_valid_element(&proof.sc_C0) {
        return false;
    }

    // Verify each bit commitment
    for i in 0..bits {
        if !or_bit_verify(pc, &proof.bit_cms[i], &proof.bit_pfs[i]) {
            return false;
        }
    }

    // product = prod(cmi^(2^i) mod P)
    let mut product = BigUint::one();
    for i in 0..bits {
        let exp = BigUint::one() << i;
        let cm_pow = proof.bit_cms[i].modpow(&exp, &pc.p);
        product = (&product * &cm_pow) % &pc.p;
    }

    // ratio = product · cm^(-1) mod P
    let cm_inv = pc.modinv_p(&proof.cm);
    let ratio = (&product * &cm_inv) % &pc.p;

    // Verify Schnorr-like proof
    let mut transcript: Vec<&BigUint> = Vec::with_capacity(3 + proof.bit_cms.len());
    transcript.push(&proof.cm);
    transcript.push(&product);
    transcript.push(&proof.sc_C0);
    for bcm in &proof.bit_cms {
        transcript.push(bcm);
    }
    let beta = fiat_shamir(&transcript, &pc.q);
    let lhs = pc.h.modpow(&proof.sc_zr, &pc.p);
    let rhs = (&proof.sc_C0 * ratio.modpow(&beta, &pc.p)) % &pc.p;

    lhs == rhs
}

// ═══════════════════════════════════════════════════════════════════════════════
// ZkpSum — proof that committed values sum to a public total
// ═══════════════════════════════════════════════════════════════════════════════

/// Proof that committed values sum to a publicly revealed total.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkpSumProof {
    #[serde(with = "vec_biguint_serde")]
    pub cms: Vec<BigUint>,
    #[serde(with = "biguint_serde")]
    pub total: BigUint,
    #[serde(with = "biguint_serde")]
    pub combined: BigUint,
    #[serde(with = "biguint_serde")]
    pub C0: BigUint,
    #[serde(with = "biguint_serde")]
    pub zr: BigUint,
}

/// Prove that the sum of `values` equals `total`, given their commitments.
/// Returns Err if values and rs have different lengths or are empty.
#[allow(non_snake_case)]
pub fn zkpsum_prove(
    pc: &PedersenCommitment,
    values: &[BigUint],
    rs: &[BigUint],
) -> Result<ZkpSumProof, String> {
    if values.is_empty() {
        return Err("zkpsum_prove: values must not be empty".to_string());
    }
    if values.len() != rs.len() {
        return Err(format!(
            "zkpsum_prove: values.len() ({}) != rs.len() ({})",
            values.len(),
            rs.len()
        ));
    }

    // Compute individual commitments and their product
    let mut cms = Vec::with_capacity(values.len());
    let mut combined = BigUint::one();
    for i in 0..values.len() {
        let cmi = pc.commit(&values[i], &rs[i]);
        combined = (&combined * &cmi) % &pc.p;
        cms.push(cmi);
    }

    // total = sum of values
    let total: BigUint = values.iter().fold(BigUint::zero(), |acc, v| acc + v);

    // r_total = sum of rs mod Q
    let r_total: BigUint = rs.iter().fold(BigUint::zero(), |acc, ri| (acc + ri) % &pc.q);

    // Schnorr-like proof
    let rp = pc.rand_zq();
    let C0 = pc.h.modpow(&rp, &pc.p);
    let beta = fiat_shamir(&[&combined, &C0, &total], &pc.q);
    let zr = (&rp + &beta * &r_total) % &pc.q;

    Ok(ZkpSumProof {
        cms,
        total,
        combined,
        C0,
        zr,
    })
}

/// Verify a sum proof.
#[allow(non_snake_case)]
pub fn zkpsum_verify(pc: &PedersenCommitment, proof: &ZkpSumProof) -> bool {
    if proof.cms.is_empty()
        || !pc.is_valid_element(&proof.combined)
        || !pc.is_valid_element(&proof.C0)
    {
        return false;
    }
    // Recompute combined from individual commitments after validating subgroup membership
    let mut recomputed = BigUint::one();
    for cmi in &proof.cms {
        if !pc.is_valid_element(cmi) {
            return false;
        }
        recomputed = (&recomputed * cmi) % &pc.p;
    }
    if recomputed != proof.combined {
        return false;
    }

    let beta = fiat_shamir(&[&proof.combined, &proof.C0, &proof.total], &pc.q);

    // lhs = G^(beta*total) · H^zr mod P
    let bt = (&beta * &proof.total) % &pc.q;
    let lhs = pc.commit(&bt, &proof.zr);

    // rhs = C0 · combined^beta mod P
    let comb_beta = proof.combined.modpow(&beta, &pc.p);
    let rhs = (&proof.C0 * &comb_beta) % &pc.p;

    lhs == rhs
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    // ── ZkpCm tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_zkpcm_valid() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(42u32);
        let r = pc.rand_zq();
        let proof = zkpcm_prove(&pc, &x, &r);
        assert!(zkpcm_verify(&pc, &proof), "valid proof must verify");
    }

    #[test]
    fn test_zkpcm_tamper_zx() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(42u32);
        let r = pc.rand_zq();
        let mut proof = zkpcm_prove(&pc, &x, &r);
        proof.zx = (&proof.zx + BigUint::one()) % &pc.q;
        assert!(!zkpcm_verify(&pc, &proof), "tampered zx must fail");
    }

    #[test]
    fn test_zkpcm_tamper_zr() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(42u32);
        let r = pc.rand_zq();
        let mut proof = zkpcm_prove(&pc, &x, &r);
        proof.zr = (&proof.zr + BigUint::one()) % &pc.q;
        assert!(!zkpcm_verify(&pc, &proof), "tampered zr must fail");
    }

    #[test]
    fn test_zkpcm_serde_roundtrip() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(42u32);
        let r = pc.rand_zq();
        let proof = zkpcm_prove(&pc, &x, &r);
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: ZkpCmProof = serde_json::from_str(&json).expect("deserialize");
        assert!(zkpcm_verify(&pc, &proof2), "roundtripped proof must verify");
    }

    // ── OR-bit tests ────────────────────────────────────────────────────────

    #[test]
    fn test_or_bit_zero() {
        let pc = PedersenCommitment::new();
        let r = pc.rand_zq();
        let cm = pc.commit(&BigUint::zero(), &r);
        let proof = or_bit_prove(&pc, 0, &r, &cm).expect("prove b=0");
        assert!(or_bit_verify(&pc, &cm, &proof), "b=0 proof must verify");
    }

    #[test]
    fn test_or_bit_one() {
        let pc = PedersenCommitment::new();
        let r = pc.rand_zq();
        let cm = pc.commit(&BigUint::one(), &r);
        let proof = or_bit_prove(&pc, 1, &r, &cm).expect("prove b=1");
        assert!(or_bit_verify(&pc, &cm, &proof), "b=1 proof must verify");
    }

    #[test]
    fn test_or_bit_invalid_value() {
        let pc = PedersenCommitment::new();
        let r = pc.rand_zq();
        let cm = pc.commit(&BigUint::from(2u32), &r);
        let result = or_bit_prove(&pc, 2, &r, &cm);
        assert!(result.is_err(), "b=2 must return Err");
    }

    #[test]
    fn test_or_bit_tamper_zr0() {
        let pc = PedersenCommitment::new();
        let r = pc.rand_zq();
        let cm = pc.commit(&BigUint::zero(), &r);
        let mut proof = or_bit_prove(&pc, 0, &r, &cm).expect("prove");
        proof.zr0 = (&proof.zr0 + BigUint::one()) % &pc.q;
        assert!(!or_bit_verify(&pc, &cm, &proof), "tampered zr0 must fail");
    }

    #[test]
    fn test_or_bit_tamper_zr1() {
        let pc = PedersenCommitment::new();
        let r = pc.rand_zq();
        let cm = pc.commit(&BigUint::one(), &r);
        let mut proof = or_bit_prove(&pc, 1, &r, &cm).expect("prove");
        proof.zr1 = (&proof.zr1 + BigUint::one()) % &pc.q;
        assert!(!or_bit_verify(&pc, &cm, &proof), "tampered zr1 must fail");
    }

    #[test]
    fn test_or_bit_wrong_cm() {
        let pc = PedersenCommitment::new();
        let r = pc.rand_zq();
        let cm = pc.commit(&BigUint::zero(), &r);
        let proof = or_bit_prove(&pc, 0, &r, &cm).expect("prove");
        // Verify against a different commitment
        let r2 = pc.rand_zq();
        let cm2 = pc.commit(&BigUint::one(), &r2);
        assert!(
            !or_bit_verify(&pc, &cm2, &proof),
            "wrong cm must fail verification"
        );
    }

    // ── ZkpNN tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_zkpnn_typical() {
        // x = 30000 fits within 16 bits (max 65535)
        let pc = PedersenCommitment::new();
        let x = BigUint::from(30000u32);
        let r = pc.rand_zq();
        let proof = zkpnn_prove(&pc, &x, &r, 16).expect("prove");
        assert!(zkpnn_verify(&pc, &proof), "typical value must verify");
    }

    #[test]
    fn test_zkpnn_zero() {
        // Zero is non-negative; valid within 20 bits
        let pc = PedersenCommitment::new();
        let x = BigUint::zero();
        let r = pc.rand_zq();
        let proof = zkpnn_prove(&pc, &x, &r, 20).expect("prove");
        assert!(zkpnn_verify(&pc, &proof), "zero must verify");
    }

    #[test]
    fn test_zkpnn_max() {
        // Maximum value for 20 bits: 2^20 - 1 = 1_048_575
        let pc = PedersenCommitment::new();
        let x = (BigUint::one() << 20usize) - BigUint::one();
        let r = pc.rand_zq();
        let proof = zkpnn_prove(&pc, &x, &r, 20).expect("prove");
        assert!(zkpnn_verify(&pc, &proof), "max 20-bit value must verify");
    }

    #[test]
    fn test_zkpnn_overflow() {
        // x = 2^20 does not fit in 20 bits → Err
        let pc = PedersenCommitment::new();
        let x = BigUint::one() << 20usize;
        let r = pc.rand_zq();
        let result = zkpnn_prove(&pc, &x, &r, 20);
        assert!(result.is_err(), "overflow must return Err");
    }

    #[test]
    fn test_zkpnn_tamper_sc_zr() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(500u32);
        let r = pc.rand_zq();
        let mut proof = zkpnn_prove(&pc, &x, &r, 16).expect("prove");
        proof.sc_zr = (&proof.sc_zr + BigUint::one()) % &pc.q;
        assert!(!zkpnn_verify(&pc, &proof), "tampered sc_zr must fail");
    }

    #[test]
    fn test_zkpnn_tamper_bit_cm() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(500u32);
        let r = pc.rand_zq();
        let mut proof = zkpnn_prove(&pc, &x, &r, 16).expect("prove");
        // Tamper with the first bit commitment
        proof.bit_cms[0] = (&proof.bit_cms[0] + BigUint::one()) % &pc.p;
        assert!(!zkpnn_verify(&pc, &proof), "tampered bit_cm must fail");
    }

    #[test]
    fn test_zkpnn_serde_roundtrip() {
        let pc = PedersenCommitment::new();
        let x = BigUint::from(12345u32);
        let r = pc.rand_zq();
        let proof = zkpnn_prove(&pc, &x, &r, 16).expect("prove");
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: ZkpNNProof = serde_json::from_str(&json).expect("deserialize");
        assert!(zkpnn_verify(&pc, &proof2), "roundtripped proof must verify");
    }

    // ── ZkpSum tests ────────────────────────────────────────────────────────

    #[test]
    fn test_zkpsum_three_values() {
        let pc = PedersenCommitment::new();
        let values = vec![
            BigUint::from(10000u32),
            BigUint::from(20000u32),
            BigUint::from(30000u32),
        ];
        let rs: Vec<BigUint> = (0..3).map(|_| pc.rand_zq()).collect();
        let proof = zkpsum_prove(&pc, &values, &rs).expect("prove");
        assert_eq!(proof.total, BigUint::from(60000u32));
        assert!(zkpsum_verify(&pc, &proof), "three-value sum must verify");
    }

    #[test]
    fn test_zkpsum_single_value() {
        let pc = PedersenCommitment::new();
        let values = vec![BigUint::from(50000u32)];
        let rs = vec![pc.rand_zq()];
        let proof = zkpsum_prove(&pc, &values, &rs).expect("prove");
        assert_eq!(proof.total, BigUint::from(50000u32));
        assert!(zkpsum_verify(&pc, &proof), "single-value sum must verify");
    }

    #[test]
    fn test_zkpsum_empty() {
        let pc = PedersenCommitment::new();
        let values: Vec<BigUint> = vec![];
        let rs: Vec<BigUint> = vec![];
        let result = zkpsum_prove(&pc, &values, &rs);
        assert!(result.is_err(), "empty values must return Err");
    }

    #[test]
    fn test_zkpsum_tamper_zr() {
        let pc = PedersenCommitment::new();
        let values = vec![BigUint::from(100u32), BigUint::from(200u32)];
        let rs: Vec<BigUint> = (0..2).map(|_| pc.rand_zq()).collect();
        let mut proof = zkpsum_prove(&pc, &values, &rs).expect("prove");
        proof.zr = (&proof.zr + BigUint::one()) % &pc.q;
        assert!(!zkpsum_verify(&pc, &proof), "tampered zr must fail");
    }

    #[test]
    fn test_zkpsum_tamper_total() {
        let pc = PedersenCommitment::new();
        let values = vec![BigUint::from(100u32), BigUint::from(200u32)];
        let rs: Vec<BigUint> = (0..2).map(|_| pc.rand_zq()).collect();
        let mut proof = zkpsum_prove(&pc, &values, &rs).expect("prove");
        proof.total = &proof.total + BigUint::one();
        assert!(!zkpsum_verify(&pc, &proof), "tampered total must fail");
    }

    #[test]
    fn test_zkpsum_serde_roundtrip() {
        let pc = PedersenCommitment::new();
        let values = vec![BigUint::from(1000u32), BigUint::from(2000u32)];
        let rs: Vec<BigUint> = (0..2).map(|_| pc.rand_zq()).collect();
        let proof = zkpsum_prove(&pc, &values, &rs).expect("prove");
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: ZkpSumProof = serde_json::from_str(&json).expect("deserialize");
        assert!(
            zkpsum_verify(&pc, &proof2),
            "roundtripped proof must verify"
        );
    }
}
