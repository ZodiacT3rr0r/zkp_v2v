//! Integration tests exercising the full V2V ZKP pipeline.
//!
//! These tests use the library API directly (not the CLI binary)
//! to validate end-to-end flows: commit → verify → ledger.

use zkp_v2v::group::PedersenCommitment;
use zkp_v2v::ledger::AuditLedger;
use zkp_v2v::privacy::{
    consumer_commit, provider_commit, prove_profit_above_margin, prove_sufficient_energy,
    verify_consumer_commitment, verify_provider_commitment, verify_profit, verify_sufficiency,
};

/// End-to-end consumer flow:
/// consumer_commit → JSON roundtrip → verify → log to ledger → retrieve
#[test]
fn test_end_to_end_consumer_flow() {
    let pc = PedersenCommitment::new();
    let ledger = AuditLedger::new(":memory:").expect("open ledger");

    // Consumers(i,10)=30 kWh, Consumers(i,11)=15 kWh, Car_Model cap=75 kWh
    let pkg = consumer_commit(&pc, 1, 30.0, 15.0, 75.0).expect("commit");
    let json = serde_json::to_string(&pkg).expect("serialize");

    // Simulate MATLAB → coordinator JSON transfer
    let pkg2: zkp_v2v::privacy::ConsumerProofPackage =
        serde_json::from_str(&json).expect("deserialize");
    assert!(
        verify_consumer_commitment(&pc, &pkg2),
        "consumer proof must verify after roundtrip"
    );

    // Log to audit ledger
    ledger
        .log_proof("consumer_1", "commit_consumer", &json)
        .expect("log");
    let entries = ledger
        .get_proofs_by_actor("consumer_1")
        .expect("query");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "commit_consumer");
}

/// End-to-end provider flow:
/// provider_commit → JSON roundtrip → verify → log to ledger
#[test]
fn test_end_to_end_provider_flow() {
    let pc = PedersenCommitment::new();
    let ledger = AuditLedger::new(":memory:").expect("open ledger");

    // Providers(k,6)=15 c/kWh, Po=8, avail=50 kWh
    let pkg = provider_commit(&pc, 10, 50.0, 15.0, 8.0).expect("commit");
    let json = serde_json::to_string(&pkg).expect("serialize");

    let pkg2: zkp_v2v::privacy::ProviderProofPackage =
        serde_json::from_str(&json).expect("deserialize");
    assert!(
        verify_provider_commitment(&pc, &pkg2),
        "provider proof must verify after roundtrip"
    );

    ledger
        .log_proof("provider_10", "commit_provider", &json)
        .expect("log");
    let entries = ledger
        .get_proofs_by_actor("provider_10")
        .expect("query");
    assert_eq!(entries.len(), 1);
}

/// End-to-end matching flow simulating the Code.m pipeline:
/// 1. Consumer commits (PATCH-2)
/// 2. Provider commits (PATCH-3)
/// 3. Profit proof (PATCH-4)
/// 4. Sufficiency proof (PATCH-5)
/// 5. All proofs verified and logged
#[test]
fn test_end_to_end_matching_flow() {
    let pc = PedersenCommitment::new();
    let ledger = AuditLedger::new(":memory:").expect("open ledger");

    // PATCH-2: Consumer commits
    let cpkg = consumer_commit(&pc, 1, 30.0, 15.0, 75.0).expect("consumer commit");
    assert!(verify_consumer_commitment(&pc, &cpkg));

    // PATCH-3: Provider commits
    let ppkg = provider_commit(&pc, 10, 50.0, 15.0, 8.0).expect("provider commit");
    assert!(verify_provider_commitment(&pc, &ppkg));

    // PATCH-4: Profit proof (Profit_P{10}(j,1) = 85 cents, ProfitMargin = 30)
    let profit_pf = prove_profit_above_margin(&pc, 10, 1, 85.0, 30.0);
    assert!(profit_pf.is_some(), "profit >= margin → Some");
    let profit_pf = profit_pf.expect("profit proof");
    assert!(verify_profit(&pc, &profit_pf));

    // PATCH-5: Sufficiency proof (avail=50, req=30 → surplus=20)
    let suff_pf = prove_sufficient_energy(&pc, 10, 1, 50.0, 30.0);
    assert!(suff_pf.is_some(), "sufficient energy → Some");
    let suff_pf = suff_pf.expect("sufficiency proof");
    assert!(verify_sufficiency(&pc, &suff_pf));

    // Log all proofs
    ledger
        .log_proof(
            "consumer_1",
            "commit_consumer",
            &serde_json::to_string(&cpkg).expect("json"),
        )
        .expect("log");
    ledger
        .log_proof(
            "provider_10",
            "commit_provider",
            &serde_json::to_string(&ppkg).expect("json"),
        )
        .expect("log");
    ledger
        .log_proof(
            "provider_10",
            "prove_profit",
            &serde_json::to_string(&profit_pf).expect("json"),
        )
        .expect("log");
    ledger
        .log_proof(
            "provider_10",
            "prove_sufficiency",
            &serde_json::to_string(&suff_pf).expect("json"),
        )
        .expect("log");

    // Verify ledger contents
    let all = ledger.get_all_proofs().expect("get_all");
    assert_eq!(all.len(), 4, "4 proofs logged");

    let p10 = ledger
        .get_proofs_by_actor("provider_10")
        .expect("by_actor");
    assert_eq!(p10.len(), 3, "provider_10 has 3 entries");

    let c1 = ledger
        .get_proofs_by_actor("consumer_1")
        .expect("by_actor");
    assert_eq!(c1.len(), 1, "consumer_1 has 1 entry");
}
