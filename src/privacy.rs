//! V2V privacy layer — consumer/provider commitment packages,
//! sufficiency proofs, and profit margin proofs.
//!
//! Hardened properties:
//! - Rejects negative / non-finite f64 inputs before scaling to u64
//! - Verifiers cross-check top-level cm_* == pf_*.cm and pf_*.bits == NN_BITS (20)
//! - Homomorphic commitment links:
//!     * Consumer: cm_req * cm_deficit == cm_cap (mod P)
//!     * Provider: cm_above_min * G^(min_price_scaled) == cm_price (mod P)
//!     * Linked Sufficiency: cm_surplus == cm_avail * cm_req^(-1) (mod P)
//! - Zero plaintext private witnesses serialized inside SufficiencyProof

use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};

use crate::group::PedersenCommitment;
use crate::proofs::{
    zkpcm_prove, zkpcm_verify, zkpnn_prove, zkpnn_verify, ZkpCmProof, ZkpNNProof,
};

/// Scaling factor: kWh → Wh (integer).
pub const SCALE_E: u64 = 1000;

/// Scaling factor: cents → centi-cents (integer).
pub const SCALE_P: u64 = 100;

/// Number of bits for non-negativity proofs. Covers 0..1,048,575.
pub const NN_BITS: u8 = 20;

fn scale_non_negative(val: f64, scale: u64, field: &str) -> Result<u64, String> {
    if !val.is_finite() || val < 0.0 {
        return Err(format!("{} ({}) must be finite and non-negative", field, val));
    }
    let scaled = (val * scale as f64).round();
    let max_val = (1u64 << NN_BITS) as f64;
    if scaled >= max_val {
        return Err(format!(
            "{} scaled ({}) exceeds {}-bit range",
            field, scaled, NN_BITS
        ));
    }
    Ok(scaled as u64)
}

fn parse_cm(s: &str) -> Option<BigUint> {
    BigUint::from_str_radix(s, 10).ok()
}

fn verify_nn_bound(pc: &PedersenCommitment, expected_cm: &str, pf: &ZkpNNProof) -> bool {
    pf.bits == NN_BITS && pf.cm.to_str_radix(10) == expected_cm && zkpnn_verify(pc, pf)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Consumer commitment package — PATCH-2 integration
// ═══════════════════════════════════════════════════════════════════════════════

/// Privacy-preserving commitment of a consumer's private data.
///
/// Proves 0 <= req < 2^20, 0 <= soc < 2^20, 0 <= deficit < 2^20, and
/// homomorphically binds cm_req · cm_deficit == cm_cap (mod P) so the
/// verifier knows req + deficit == cap without learning req or cap.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConsumerProofPackage {
    pub cid: u64,
    pub cm_req: String,
    pub cm_soc: String,
    pub cm_deficit: String,
    pub cm_cap: String,
    pub pf_req_nn: ZkpNNProof,
    pub pf_deficit_nn: ZkpNNProof,
    pub pf_soc_nn: ZkpNNProof,
}

pub fn consumer_commit(
    pc: &PedersenCommitment,
    cid: u64,
    req_kwh: f64,
    soc_kwh: f64,
    cap_kwh: f64,
) -> Result<ConsumerProofPackage, String> {
    let req = scale_non_negative(req_kwh, SCALE_E, "req_kwh")?;
    let soc = scale_non_negative(soc_kwh, SCALE_E, "soc_kwh")?;
    let cap = scale_non_negative(cap_kwh, SCALE_E, "cap_kwh")?;
    let deficit = cap
        .checked_sub(req)
        .ok_or_else(|| "req_kwh exceeds cap_kwh".to_string())?;

    let req_bu = BigUint::from(req);
    let soc_bu = BigUint::from(soc);
    let deficit_bu = BigUint::from(deficit);

    let (cm_req_val, r_req) = pc.commit_with_random(&req_bu);
    let (cm_soc_val, r_soc) = pc.commit_with_random(&soc_bu);
    let (cm_deficit_val, r_deficit) = pc.commit_with_random(&deficit_bu);
    // Homomorphically derive cm_cap = cm_req * cm_deficit mod P = Cm(req + deficit, r_req + r_deficit)
    let cm_cap_val = pc.mul(&cm_req_val, &cm_deficit_val);

    let pf_req_nn = zkpnn_prove(pc, &req_bu, &r_req, NN_BITS)?;
    let pf_soc_nn = zkpnn_prove(pc, &soc_bu, &r_soc, NN_BITS)?;
    let pf_deficit_nn = zkpnn_prove(pc, &deficit_bu, &r_deficit, NN_BITS)?;

    Ok(ConsumerProofPackage {
        cid,
        cm_req: cm_req_val.to_str_radix(10),
        cm_soc: cm_soc_val.to_str_radix(10),
        cm_deficit: cm_deficit_val.to_str_radix(10),
        cm_cap: cm_cap_val.to_str_radix(10),
        pf_req_nn,
        pf_deficit_nn,
        pf_soc_nn,
    })
}

/// Verify a consumer's commitment package:
/// 1. All 3 ZkpNN proofs pass with NN_BITS == 20 and matching top-level cm_* fields
/// 2. Homomorphic conservation: cm_req * cm_deficit == cm_cap (mod P)
pub fn verify_consumer_commitment(
    pc: &PedersenCommitment,
    pkg: &ConsumerProofPackage,
) -> bool {
    if !verify_nn_bound(pc, &pkg.cm_req, &pkg.pf_req_nn)
        || !verify_nn_bound(pc, &pkg.cm_deficit, &pkg.pf_deficit_nn)
        || !verify_nn_bound(pc, &pkg.cm_soc, &pkg.pf_soc_nn)
    {
        return false;
    }

    let cm_cap = match parse_cm(&pkg.cm_cap) {
        Some(v) if pc.is_valid_element(&v) => v,
        _ => return false,
    };
    pc.mul(&pkg.pf_req_nn.cm, &pkg.pf_deficit_nn.cm) == cm_cap
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider commitment package — PATCH-3 integration
// ═══════════════════════════════════════════════════════════════════════════════

/// Privacy-preserving commitment of a provider's private data.
///
/// Proves avail >= 0, price >= min_price (grid floor Po), knowledge of price opening,
/// and homomorphically binds cm_above_min * G^(min_price_scaled) == cm_price (mod P).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProviderProofPackage {
    pub pid: u64,
    pub min_price_cents: f64,
    pub cm_avail: String,
    pub cm_price: String,
    pub cm_above_min: String,
    pub pf_avail_nn: ZkpNNProof,
    pub pf_above_min_nn: ZkpNNProof,
    pub pf_price_cm: ZkpCmProof,
}

pub fn provider_commit(
    pc: &PedersenCommitment,
    pid: u64,
    avail_kwh: f64,
    price_cents: f64,
    min_price_cents: f64,
) -> Result<ProviderProofPackage, String> {
    let avail = scale_non_negative(avail_kwh, SCALE_E, "avail_kwh")?;
    let price = scale_non_negative(price_cents, SCALE_P, "price_cents")?;
    let min_price = scale_non_negative(min_price_cents, SCALE_P, "min_price_cents")?;
    let above_min = price
        .checked_sub(min_price)
        .ok_or_else(|| format!("price_cents ({}) < min_price_cents ({})", price_cents, min_price_cents))?;

    let avail_bu = BigUint::from(avail);
    let price_bu = BigUint::from(price);
    let above_min_bu = BigUint::from(above_min);

    let (cm_avail_val, r_avail) = pc.commit_with_random(&avail_bu);
    // Reuse r_price for cm_above_min so cm_above_min * G^(min_price) == cm_price (mod P)
    let (cm_price_val, r_price) = pc.commit_with_random(&price_bu);
    let cm_above_min_val = pc.commit(&above_min_bu, &r_price);

    let pf_avail_nn = zkpnn_prove(pc, &avail_bu, &r_avail, NN_BITS)?;
    let pf_above_min_nn = zkpnn_prove(pc, &above_min_bu, &r_price, NN_BITS)?;
    let pf_price_cm = zkpcm_prove(pc, &price_bu, &r_price);

    Ok(ProviderProofPackage {
        pid,
        min_price_cents,
        cm_avail: cm_avail_val.to_str_radix(10),
        cm_price: cm_price_val.to_str_radix(10),
        cm_above_min: cm_above_min_val.to_str_radix(10),
        pf_avail_nn,
        pf_above_min_nn,
        pf_price_cm,
    })
}

/// Verify a provider's commitment package:
/// 1. ZkpNN proofs pass with NN_BITS == 20 and matching cm_* fields
/// 2. ZkpCm opening proof matches cm_price
/// 3. Homomorphic link: cm_above_min * G^(min_price_scaled) == cm_price (mod P)
pub fn verify_provider_commitment(
    pc: &PedersenCommitment,
    pkg: &ProviderProofPackage,
) -> bool {
    if !verify_nn_bound(pc, &pkg.cm_avail, &pkg.pf_avail_nn)
        || !verify_nn_bound(pc, &pkg.cm_above_min, &pkg.pf_above_min_nn)
    {
        return false;
    }
    if pkg.pf_price_cm.cm.to_str_radix(10) != pkg.cm_price
        || !zkpcm_verify(pc, &pkg.pf_price_cm)
    {
        return false;
    }

    let min_price = match scale_non_negative(pkg.min_price_cents, SCALE_P, "min_price_cents") {
        Ok(v) => BigUint::from(v),
        Err(_) => return false,
    };
    let g_min = pc.g.modpow(&min_price, &pc.p);
    pc.mul(&pkg.pf_above_min_nn.cm, &g_min) == pkg.pf_price_cm.cm
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sufficiency proof — PATCH-5 integration
// ═══════════════════════════════════════════════════════════════════════════════

/// Proof that a provider has sufficient energy for a matched consumer (avail - req >= 0)
/// without exposing either `avail` or `req` in plaintext.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SufficiencyProof {
    pub pid: u64,
    pub cid: u64,
    pub cm_surplus: String,
    pub pf_surplus_nn: ZkpNNProof,
}

/// Standalone sufficiency proof (used by stateless CLI invocations).
pub fn prove_sufficient_energy(
    pc: &PedersenCommitment,
    pid: u64,
    cid: u64,
    avail_kwh: f64,
    req_kwh: f64,
) -> Option<SufficiencyProof> {
    let avail = scale_non_negative(avail_kwh, SCALE_E, "avail_kwh").ok()?;
    let req = scale_non_negative(req_kwh, SCALE_E, "req_kwh").ok()?;
    let surplus = avail.checked_sub(req)?;

    let surplus_bu = BigUint::from(surplus);
    let (cm_surplus_val, r_surplus) = pc.commit_with_random(&surplus_bu);
    let pf_surplus_nn = zkpnn_prove(pc, &surplus_bu, &r_surplus, NN_BITS).ok()?;

    Some(SufficiencyProof {
        pid,
        cid,
        cm_surplus: cm_surplus_val.to_str_radix(10),
        pf_surplus_nn,
    })
}

/// Cross-stage homomorphically linked sufficiency proof:
/// Derives r_surplus = (r_avail - r_req) mod Q so that
///   cm_surplus == cm_avail · cm_req^(-1) (mod P)
/// mathematically binding Stage 5 directly to Stage 1 & Stage 2 commitments.
pub fn prove_sufficient_energy_linked(
    pc: &PedersenCommitment,
    pid: u64,
    cid: u64,
    avail_kwh: f64,
    r_avail: &BigUint,
    req_kwh: f64,
    r_req: &BigUint,
) -> Option<SufficiencyProof> {
    let avail = scale_non_negative(avail_kwh, SCALE_E, "avail_kwh").ok()?;
    let req = scale_non_negative(req_kwh, SCALE_E, "req_kwh").ok()?;
    let surplus = avail.checked_sub(req)?;

    let a_mod = r_avail % &pc.q;
    let b_mod = r_req % &pc.q;
    let r_surplus = if a_mod >= b_mod {
        (&a_mod - &b_mod) % &pc.q
    } else {
        (&pc.q + &a_mod - &b_mod) % &pc.q
    };

    let surplus_bu = BigUint::from(surplus);
    let cm_surplus_val = pc.commit(&surplus_bu, &r_surplus);
    let pf_surplus_nn = zkpnn_prove(pc, &surplus_bu, &r_surplus, NN_BITS).ok()?;

    Some(SufficiencyProof {
        pid,
        cid,
        cm_surplus: cm_surplus_val.to_str_radix(10),
        pf_surplus_nn,
    })
}

/// Verify a standalone sufficiency proof.
pub fn verify_sufficiency(pc: &PedersenCommitment, proof: &SufficiencyProof) -> bool {
    verify_nn_bound(pc, &proof.cm_surplus, &proof.pf_surplus_nn)
}

/// Verify a cross-stage linked sufficiency proof against previously registered
/// Stage 2 `cm_avail` and Stage 1 `cm_req` commitments.
pub fn verify_sufficiency_linked(
    pc: &PedersenCommitment,
    proof: &SufficiencyProof,
    cm_avail: &BigUint,
    cm_req: &BigUint,
) -> bool {
    if !pc.is_valid_element(cm_avail) || !pc.is_valid_element(cm_req) {
        return false;
    }
    let expected_surplus = pc.mul(cm_avail, &pc.modinv_p(cm_req));
    proof.pf_surplus_nn.cm == expected_surplus && verify_sufficiency(pc, proof)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Profit margin proof — PATCH-4 integration
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfitProof {
    pub pid: u64,
    pub cid: u64,
    pub cm_excess: String,
    pub pf_above_margin: ZkpNNProof,
}

pub fn prove_profit_above_margin(
    pc: &PedersenCommitment,
    pid: u64,
    cid: u64,
    profit_cents: f64,
    margin_cents: f64,
) -> Option<ProfitProof> {
    let profit = scale_non_negative(profit_cents, SCALE_P, "profit_cents").ok()?;
    let margin = scale_non_negative(margin_cents, SCALE_P, "margin_cents").ok()?;
    let excess = profit.checked_sub(margin)?;

    let excess_bu = BigUint::from(excess);
    let (cm_excess_val, r_excess) = pc.commit_with_random(&excess_bu);
    let pf_above_margin = zkpnn_prove(pc, &excess_bu, &r_excess, NN_BITS).ok()?;

    Some(ProfitProof {
        pid,
        cid,
        cm_excess: cm_excess_val.to_str_radix(10),
        pf_above_margin,
    })
}

pub fn verify_profit(pc: &PedersenCommitment, proof: &ProfitProof) -> bool {
    verify_nn_bound(pc, &proof.cm_excess, &proof.pf_above_margin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumer_typical_valid() {
        let pc = PedersenCommitment::new();
        let pkg = consumer_commit(&pc, 1, 30.0, 15.0, 75.0).expect("commit");
        assert!(verify_consumer_commitment(&pc, &pkg));
        assert_eq!(pkg.cid, 1);
    }

    #[test]
    fn test_consumer_req_exceeds_cap() {
        let pc = PedersenCommitment::new();
        assert!(consumer_commit(&pc, 1, 80.0, 15.0, 75.0).is_err());
    }

    #[test]
    fn test_consumer_rejects_negative_inputs() {
        let pc = PedersenCommitment::new();
        assert!(consumer_commit(&pc, 1, -5.0, 15.0, 75.0).is_err());
        assert!(consumer_commit(&pc, 1, 10.0, -1.0, 75.0).is_err());
        assert!(consumer_commit(&pc, 1, f64::NAN, 10.0, 75.0).is_err());
    }

    #[test]
    fn test_consumer_rejects_swapped_cm_or_bad_cap_link() {
        let pc = PedersenCommitment::new();
        let mut pkg = consumer_commit(&pc, 1, 30.0, 15.0, 75.0).expect("commit");
        pkg.cm_cap = "12345".to_string();
        assert!(!verify_consumer_commitment(&pc, &pkg));
    }

    #[test]
    fn test_consumer_zero_req() {
        let pc = PedersenCommitment::new();
        let pkg = consumer_commit(&pc, 2, 0.0, 10.0, 75.0).expect("commit");
        assert!(verify_consumer_commitment(&pc, &pkg));
    }

    #[test]
    fn test_consumer_serde_roundtrip() {
        let pc = PedersenCommitment::new();
        let pkg = consumer_commit(&pc, 3, 25.0, 12.0, 60.0).expect("commit");
        let json = serde_json::to_string(&pkg).expect("serialize");
        let pkg2: ConsumerProofPackage = serde_json::from_str(&json).expect("deserialize");
        assert!(verify_consumer_commitment(&pc, &pkg2));
    }

    #[test]
    fn test_provider_typical_valid() {
        let pc = PedersenCommitment::new();
        let pkg = provider_commit(&pc, 10, 50.0, 15.0, 8.0).expect("commit");
        assert!(verify_provider_commitment(&pc, &pkg));
        assert_eq!(pkg.pid, 10);
    }

    #[test]
    fn test_provider_price_below_min() {
        let pc = PedersenCommitment::new();
        assert!(provider_commit(&pc, 10, 50.0, 5.0, 8.0).is_err());
    }

    #[test]
    fn test_provider_rejects_broken_price_link() {
        let pc = PedersenCommitment::new();
        let mut pkg = provider_commit(&pc, 10, 50.0, 15.0, 8.0).expect("commit");
        pkg.min_price_cents = 10.0; // breaks cm_above_min * G^min == cm_price
        assert!(!verify_provider_commitment(&pc, &pkg));
    }

    #[test]
    fn test_provider_serde_roundtrip() {
        let pc = PedersenCommitment::new();
        let pkg = provider_commit(&pc, 11, 40.0, 12.0, 8.0).expect("commit");
        let json = serde_json::to_string(&pkg).expect("serialize");
        let pkg2: ProviderProofPackage = serde_json::from_str(&json).expect("deserialize");
        assert!(verify_provider_commitment(&pc, &pkg2));
    }

    #[test]
    fn test_sufficient_enough() {
        let pc = PedersenCommitment::new();
        let proof = prove_sufficient_energy(&pc, 10, 1, 50.0, 30.0).expect("some");
        assert!(verify_sufficiency(&pc, &proof));
    }

    #[test]
    fn test_sufficient_not_enough() {
        let pc = PedersenCommitment::new();
        assert!(prove_sufficient_energy(&pc, 10, 1, 20.0, 30.0).is_none());
    }

    #[test]
    fn test_sufficient_exact_zero_surplus() {
        let pc = PedersenCommitment::new();
        let proof = prove_sufficient_energy(&pc, 10, 1, 30.0, 30.0).expect("some");
        assert!(verify_sufficiency(&pc, &proof));
    }

    #[test]
    fn test_sufficient_linked_cross_stage() {
        let pc = PedersenCommitment::new();
        let (cm_avail, r_avail) = pc.commit_with_random(&BigUint::from(50_000u64));
        let (cm_req, r_req) = pc.commit_with_random(&BigUint::from(30_000u64));
        let proof = prove_sufficient_energy_linked(&pc, 10, 1, 50.0, &r_avail, 30.0, &r_req)
            .expect("linked proof");
        assert!(verify_sufficiency_linked(&pc, &proof, &cm_avail, &cm_req));

        // Different commitment must fail homomorphic link check
        let (other_cm, _) = pc.commit_with_random(&BigUint::from(10_000u64));
        assert!(!verify_sufficiency_linked(&pc, &proof, &other_cm, &cm_req));
    }

    #[test]
    fn test_sufficient_serde_roundtrip() {
        let pc = PedersenCommitment::new();
        let proof = prove_sufficient_energy(&pc, 10, 1, 50.0, 25.0).expect("prove");
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: SufficiencyProof = serde_json::from_str(&json).expect("deserialize");
        assert!(verify_sufficiency(&pc, &proof2));
    }

    #[test]
    fn test_profit_above() {
        let pc = PedersenCommitment::new();
        let proof = prove_profit_above_margin(&pc, 10, 1, 85.0, 30.0).expect("some");
        assert!(verify_profit(&pc, &proof));
    }

    #[test]
    fn test_profit_below() {
        let pc = PedersenCommitment::new();
        assert!(prove_profit_above_margin(&pc, 10, 1, 10.0, 30.0).is_none());
    }

    #[test]
    fn test_profit_serde_roundtrip() {
        let pc = PedersenCommitment::new();
        let proof = prove_profit_above_margin(&pc, 10, 1, 100.0, 30.0).expect("prove");
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: ProfitProof = serde_json::from_str(&json).expect("deserialize");
        assert!(verify_profit(&pc, &proof2));
    }
}
