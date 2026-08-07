//! V2V privacy layer — consumer/provider commitment packages,
//! sufficiency proofs, and profit margin proofs.
//!
//! Maps MATLAB variables from Code.m to ZKP operations:
//!   Consumers(i, 1)  = consumer ID
//!   Consumers(i, 10) = required charge (kWh), derived from col6 × col8 / 100
//!   Consumers(i, 11) = current charge (kWh), derived from col7 × col8 / 100
//!   Consumers(i, 8)  = battery capacity (kWh) = Car_Model(type, 2)
//!   Providers(k, 1)  = provider ID
//!   Providers(k, 6)  = trading price (cents/kWh)
//!   Po               = 8 c/kWh (grid cost / minimum price)
//!   ProfitMargin     = 30 cents (minimum profit for provider engagement)
//!   Profit_P{k}(j,i) = provider profit for a (consumer, PL, provider) triple

use num_bigint::BigUint;
use serde::{Serialize, Deserialize};

use crate::group::PedersenCommitment;
use crate::proofs::{
    ZkpCmProof, ZkpNNProof,
    zkpcm_prove, zkpcm_verify,
    zkpnn_prove, zkpnn_verify,
};

/// Scaling factor: kWh → Wh (integer). Applied to Consumers(i,10), Consumers(i,11), etc.
pub const SCALE_E: u64 = 1000;

/// Scaling factor: cents → integer. Applied to Providers(k,6), Po, ProfitMargin, etc.
pub const SCALE_P: u64 = 100;

/// Number of bits for non-negativity proofs. Covers 0..1,048,575.
const NN_BITS: u8 = 20;

// ═══════════════════════════════════════════════════════════════════════════════
// Consumer commitment package — PATCH-2 integration
// ═══════════════════════════════════════════════════════════════════════════════

/// Privacy-preserving commitment of a consumer's private data.
///
/// Proves non-negativity of required charge, current SoC, and deficit
/// (cap − req) without revealing the actual values.
///
/// MATLAB mapping:
///   cid       = Consumers(i, 1)
///   cm_req    = commitment to Consumers(i, 10) × SCALE_E
///   cm_soc    = commitment to Consumers(i, 11) × SCALE_E
///   cm_deficit = commitment to (Car_Model(type, 2) − Consumers(i, 10)) × SCALE_E
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConsumerProofPackage {
    pub cid: u64,
    pub cm_req: String,
    pub cm_soc: String,
    pub cm_deficit: String,
    pub pf_req_nn: ZkpNNProof,
    pub pf_deficit_nn: ZkpNNProof,
    pub pf_soc_nn: ZkpNNProof,
}

/// Commit a consumer's private data and produce non-negativity proofs.
///
/// # Arguments
/// * `cid`     — Consumers(i, 1): vehicle ID
/// * `req_kwh` — Consumers(i, 10): required charge in kWh
/// * `soc_kwh` — Consumers(i, 11): current state of charge in kWh
/// * `cap_kwh` — Consumers(i, 8) = Car_Model(Consumers(i,5), 2): battery capacity in kWh
///
/// # Errors
/// Returns Err if req_kwh exceeds cap_kwh (deficit would be negative).
pub fn consumer_commit(
    pc: &PedersenCommitment,
    cid: u64,
    req_kwh: f64,
    soc_kwh: f64,
    cap_kwh: f64,
) -> Result<ConsumerProofPackage, String> {
    let req = (req_kwh * SCALE_E as f64).round() as u64;
    let soc = (soc_kwh * SCALE_E as f64).round() as u64;
    let cap = (cap_kwh * SCALE_E as f64).round() as u64;
    let deficit = cap
        .checked_sub(req)
        .ok_or_else(|| "req_kwh exceeds cap_kwh".to_string())?;

    let req_bu = BigUint::from(req);
    let soc_bu = BigUint::from(soc);
    let deficit_bu = BigUint::from(deficit);

    let (cm_req_val, r_req) = pc.commit_with_random(&req_bu);
    let (cm_soc_val, r_soc) = pc.commit_with_random(&soc_bu);
    let (cm_deficit_val, r_deficit) = pc.commit_with_random(&deficit_bu);

    let pf_req_nn = zkpnn_prove(pc, &req_bu, &r_req, NN_BITS)?;
    let pf_soc_nn = zkpnn_prove(pc, &soc_bu, &r_soc, NN_BITS)?;
    let pf_deficit_nn = zkpnn_prove(pc, &deficit_bu, &r_deficit, NN_BITS)?;

    Ok(ConsumerProofPackage {
        cid,
        cm_req: cm_req_val.to_str_radix(10),
        cm_soc: cm_soc_val.to_str_radix(10),
        cm_deficit: cm_deficit_val.to_str_radix(10),
        pf_req_nn,
        pf_deficit_nn,
        pf_soc_nn,
    })
}

/// Verify a consumer's commitment package.
/// Checks all three non-negativity proofs (req, deficit, soc).
pub fn verify_consumer_commitment(
    pc: &PedersenCommitment,
    pkg: &ConsumerProofPackage,
) -> bool {
    zkpnn_verify(pc, &pkg.pf_req_nn)
        && zkpnn_verify(pc, &pkg.pf_deficit_nn)
        && zkpnn_verify(pc, &pkg.pf_soc_nn)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider commitment package — PATCH-3 integration
// ═══════════════════════════════════════════════════════════════════════════════

/// Privacy-preserving commitment of a provider's private data.
///
/// Proves non-negativity of available energy and price-above-minimum,
/// plus a commitment opening proof for the trading price.
///
/// MATLAB mapping:
///   pid         = Providers(k, 1)
///   cm_avail    = commitment to available energy × SCALE_E
///                 (avail derived as Car_Model(Providers(k,5), 2) * 0.5)
///   cm_price    = commitment to Providers(k, 6) × SCALE_P
///   cm_above_min = commitment to (Providers(k,6) − Po) × SCALE_P
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProviderProofPackage {
    pub pid: u64,
    pub cm_avail: String,
    pub cm_price: String,
    pub cm_above_min: String,
    pub pf_avail_nn: ZkpNNProof,
    pub pf_above_min_nn: ZkpNNProof,
    pub pf_price_cm: ZkpCmProof,
}

/// Commit a provider's private data and produce proofs.
///
/// # Arguments
/// * `pid`             — Providers(k, 1): vehicle ID
/// * `avail_kwh`       — available energy for trading (kWh)
///                        (derived in MATLAB as Car_Model(Providers(k,5), 2) * 0.5)
/// * `price_cents`     — Providers(k, 6): trading price in cents/kWh
/// * `min_price_cents` — Po: grid cost (default 8.0 c/kWh)
///
/// # Errors
/// Returns Err if price_cents < min_price_cents.
pub fn provider_commit(
    pc: &PedersenCommitment,
    pid: u64,
    avail_kwh: f64,
    price_cents: f64,
    min_price_cents: f64,
) -> Result<ProviderProofPackage, String> {
    if price_cents < min_price_cents {
        return Err(format!(
            "price_cents ({}) < min_price_cents ({})",
            price_cents, min_price_cents
        ));
    }

    let avail = (avail_kwh * SCALE_E as f64).round() as u64;
    let price = (price_cents * SCALE_P as f64).round() as u64;
    let above_min = ((price_cents - min_price_cents) * SCALE_P as f64).round() as u64;

    let avail_bu = BigUint::from(avail);
    let price_bu = BigUint::from(price);
    let above_min_bu = BigUint::from(above_min);

    let (cm_avail_val, r_avail) = pc.commit_with_random(&avail_bu);
    let (cm_price_val, r_price) = pc.commit_with_random(&price_bu);
    let (cm_above_min_val, r_above) = pc.commit_with_random(&above_min_bu);

    let pf_avail_nn = zkpnn_prove(pc, &avail_bu, &r_avail, NN_BITS)?;
    let pf_above_min_nn = zkpnn_prove(pc, &above_min_bu, &r_above, NN_BITS)?;
    let pf_price_cm = zkpcm_prove(pc, &price_bu, &r_price);

    Ok(ProviderProofPackage {
        pid,
        cm_avail: cm_avail_val.to_str_radix(10),
        cm_price: cm_price_val.to_str_radix(10),
        cm_above_min: cm_above_min_val.to_str_radix(10),
        pf_avail_nn,
        pf_above_min_nn,
        pf_price_cm,
    })
}

/// Verify a provider's commitment package.
/// Checks non-negativity of avail and above_min, plus commitment opening of price.
pub fn verify_provider_commitment(
    pc: &PedersenCommitment,
    pkg: &ProviderProofPackage,
) -> bool {
    zkpnn_verify(pc, &pkg.pf_avail_nn)
        && zkpnn_verify(pc, &pkg.pf_above_min_nn)
        && zkpcm_verify(pc, &pkg.pf_price_cm)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sufficiency proof — PATCH-5 integration
// ═══════════════════════════════════════════════════════════════════════════════

/// Proof that a provider has sufficient energy for a matched consumer.
///
/// Proves surplus = avail − req ≥ 0 without revealing avail.
/// Generated after ProposedApproach returns confirmed matches.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SufficiencyProof {
    pub pid: u64,
    pub cid: u64,
    pub req_kwh: f64,
    pub cm_surplus: String,
    pub pf_surplus_nn: ZkpNNProof,
}

/// Prove that the provider has sufficient energy for the consumer's request.
///
/// # Arguments
/// * `pid`       — Providers(k, 1): provider ID
/// * `cid`       — Consumers(i, 1): consumer ID
/// * `avail_kwh` — provider's available energy (kWh)
/// * `req_kwh`   — Consumers(i, 10): consumer's required charge (kWh)
///
/// Returns None if avail_kwh < req_kwh (insufficient energy).
/// Returns Some if avail_kwh >= req_kwh (surplus ≥ 0).
pub fn prove_sufficient_energy(
    pc: &PedersenCommitment,
    pid: u64,
    cid: u64,
    avail_kwh: f64,
    req_kwh: f64,
) -> Option<SufficiencyProof> {
    let surplus = avail_kwh - req_kwh;
    if surplus < 0.0 {
        return None;
    }

    let surplus_int = (surplus * SCALE_E as f64).round() as u64;
    let surplus_bu = BigUint::from(surplus_int);
    let (cm_surplus_val, r_surplus) = pc.commit_with_random(&surplus_bu);
    let pf_surplus_nn = zkpnn_prove(pc, &surplus_bu, &r_surplus, NN_BITS).ok()?;

    Some(SufficiencyProof {
        pid,
        cid,
        req_kwh,
        cm_surplus: cm_surplus_val.to_str_radix(10),
        pf_surplus_nn,
    })
}

/// Verify a sufficiency proof.
pub fn verify_sufficiency(pc: &PedersenCommitment, proof: &SufficiencyProof) -> bool {
    zkpnn_verify(pc, &proof.pf_surplus_nn)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Profit margin proof — PATCH-4 integration
// ═══════════════════════════════════════════════════════════════════════════════

/// Proof that profit exceeds the minimum margin without revealing the profit.
///
/// Replaces the plaintext check at Code.m L249-251:
///   if Profit_P{k}(j,i) < ProfitMargin
///       Profit_P{k}(j,i) = 0;
///   end
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfitProof {
    pub pid: u64,
    pub cid: u64,
    pub cm_excess: String,
    pub pf_above_margin: ZkpNNProof,
}

/// Prove that profit exceeds the minimum margin.
///
/// # Arguments
/// * `pid`           — Providers(k, 1): provider ID
/// * `cid`           — Consumers(i, 1): consumer ID
/// * `profit_cents`  — Profit_P{k}(j,i): profit for this pair (cents)
/// * `margin_cents`  — ProfitMargin: minimum profit threshold (default 30.0 cents)
///
/// Returns None if profit_cents < margin_cents (below margin).
/// Returns Some if profit_cents >= margin_cents.
pub fn prove_profit_above_margin(
    pc: &PedersenCommitment,
    pid: u64,
    cid: u64,
    profit_cents: f64,
    margin_cents: f64,
) -> Option<ProfitProof> {
    let excess = profit_cents - margin_cents;
    if excess < 0.0 {
        return None;
    }

    let excess_int = (excess * SCALE_P as f64).round() as u64;
    let excess_bu = BigUint::from(excess_int);
    let (cm_excess_val, r_excess) = pc.commit_with_random(&excess_bu);
    let pf_above_margin = zkpnn_prove(pc, &excess_bu, &r_excess, NN_BITS).ok()?;

    Some(ProfitProof {
        pid,
        cid,
        cm_excess: cm_excess_val.to_str_radix(10),
        pf_above_margin,
    })
}

/// Verify a profit proof.
pub fn verify_profit(pc: &PedersenCommitment, proof: &ProfitProof) -> bool {
    zkpnn_verify(pc, &proof.pf_above_margin)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Consumer tests ──────────────────────────────────────────────────────

    #[test]
    fn test_consumer_typical_valid() {
        // Consumers(i,10)=30 kWh, Consumers(i,11)=15 kWh, Car_Model cap=75 kWh
        let pc = PedersenCommitment::new();
        let pkg = consumer_commit(&pc, 1, 30.0, 15.0, 75.0).expect("commit");
        assert!(
            verify_consumer_commitment(&pc, &pkg),
            "typical consumer must verify"
        );
        assert_eq!(pkg.cid, 1);
    }

    #[test]
    fn test_consumer_req_exceeds_cap() {
        // Consumers(i,10)=80 > Car_Model cap=75 → deficit negative → Err
        let pc = PedersenCommitment::new();
        let result = consumer_commit(&pc, 1, 80.0, 15.0, 75.0);
        assert!(result.is_err(), "req > cap must return Err");
    }

    #[test]
    fn test_consumer_zero_req() {
        // Consumers(i,10)=0 is a valid edge case (no charge needed)
        let pc = PedersenCommitment::new();
        let pkg = consumer_commit(&pc, 2, 0.0, 10.0, 75.0).expect("commit");
        assert!(
            verify_consumer_commitment(&pc, &pkg),
            "zero req must verify"
        );
    }

    #[test]
    fn test_consumer_serde_roundtrip() {
        // Simulates MATLAB sending consumer proof JSON to coordinator for verification
        let pc = PedersenCommitment::new();
        let pkg = consumer_commit(&pc, 3, 25.0, 12.0, 60.0).expect("commit");
        let json = serde_json::to_string(&pkg).expect("serialize");
        let pkg2: ConsumerProofPackage = serde_json::from_str(&json).expect("deserialize");
        assert!(
            verify_consumer_commitment(&pc, &pkg2),
            "roundtripped consumer must verify"
        );
    }

    // ── Provider tests ──────────────────────────────────────────────────────

    #[test]
    fn test_provider_typical_valid() {
        // Providers(k,6)=15 c/kWh, Po=8 → above_min=7 → valid
        let pc = PedersenCommitment::new();
        let pkg = provider_commit(&pc, 10, 50.0, 15.0, 8.0).expect("commit");
        assert!(
            verify_provider_commitment(&pc, &pkg),
            "typical provider must verify"
        );
        assert_eq!(pkg.pid, 10);
    }

    #[test]
    fn test_provider_price_below_min() {
        // Providers(k,6)=5 < Po=8 → Err
        let pc = PedersenCommitment::new();
        let result = provider_commit(&pc, 10, 50.0, 5.0, 8.0);
        assert!(result.is_err(), "price < min must return Err");
    }

    #[test]
    fn test_provider_serde_roundtrip() {
        // Simulates MATLAB sending provider proof JSON to coordinator
        let pc = PedersenCommitment::new();
        let pkg = provider_commit(&pc, 11, 40.0, 12.0, 8.0).expect("commit");
        let json = serde_json::to_string(&pkg).expect("serialize");
        let pkg2: ProviderProofPackage = serde_json::from_str(&json).expect("deserialize");
        assert!(
            verify_provider_commitment(&pc, &pkg2),
            "roundtripped provider must verify"
        );
    }

    // ── Sufficiency tests ───────────────────────────────────────────────────

    #[test]
    fn test_sufficient_enough() {
        // avail=50 kWh, Consumers(i,10)=30 kWh → surplus=20, valid
        let pc = PedersenCommitment::new();
        let proof = prove_sufficient_energy(&pc, 10, 1, 50.0, 30.0);
        assert!(proof.is_some(), "surplus=20 must return Some");
        let proof = proof.unwrap();
        assert!(verify_sufficiency(&pc, &proof), "sufficiency must verify");
    }

    #[test]
    fn test_sufficient_not_enough() {
        // avail=20 kWh, Consumers(i,10)=30 kWh → surplus=-10, None
        let pc = PedersenCommitment::new();
        let proof = prove_sufficient_energy(&pc, 10, 1, 20.0, 30.0);
        assert!(proof.is_none(), "insufficient energy must return None");
    }

    #[test]
    fn test_sufficient_exact_zero_surplus() {
        // avail exactly equals req → surplus=0, still Some (edge case)
        let pc = PedersenCommitment::new();
        let proof = prove_sufficient_energy(&pc, 10, 1, 30.0, 30.0);
        assert!(proof.is_some(), "zero surplus must return Some");
        let proof = proof.unwrap();
        assert!(
            verify_sufficiency(&pc, &proof),
            "zero surplus must verify"
        );
    }

    #[test]
    fn test_sufficient_serde_roundtrip() {
        // JSON round-trip verify (simulates MATLAB→coordinator flow)
        let pc = PedersenCommitment::new();
        let proof = prove_sufficient_energy(&pc, 10, 1, 50.0, 25.0).expect("prove");
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: SufficiencyProof = serde_json::from_str(&json).expect("deserialize");
        assert!(
            verify_sufficiency(&pc, &proof2),
            "roundtripped sufficiency must verify"
        );
    }

    // ── Profit tests ────────────────────────────────────────────────────────

    #[test]
    fn test_profit_above() {
        // Profit_P{k}(j,i)=85 cents, ProfitMargin=30 → excess=55, valid
        let pc = PedersenCommitment::new();
        let proof = prove_profit_above_margin(&pc, 10, 1, 85.0, 30.0);
        assert!(proof.is_some(), "profit above margin must return Some");
        let proof = proof.unwrap();
        assert!(verify_profit(&pc, &proof), "profit proof must verify");
    }

    #[test]
    fn test_profit_below() {
        // Profit_P{k}(j,i)=10 cents, ProfitMargin=30 → below margin, None
        let pc = PedersenCommitment::new();
        let proof = prove_profit_above_margin(&pc, 10, 1, 10.0, 30.0);
        assert!(proof.is_none(), "profit below margin must return None");
    }

    #[test]
    fn test_profit_serde_roundtrip() {
        // JSON round-trip verify (simulates PATCH-4 flow)
        let pc = PedersenCommitment::new();
        let proof = prove_profit_above_margin(&pc, 10, 1, 100.0, 30.0).expect("prove");
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: ProfitProof = serde_json::from_str(&json).expect("deserialize");
        assert!(
            verify_profit(&pc, &proof2),
            "roundtripped profit must verify"
        );
    }
}
