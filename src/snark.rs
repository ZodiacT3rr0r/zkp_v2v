//! zkSNARK comparison proofs via Groth16.
//!
//! Proves utility_a > utility_b (both private) using the Circom comparison
//! circuit compiled by `setup/trusted_setup.sh`.
//!
//! This module requires the circuit build artifacts to be present at runtime:
//!   - comparison.r1cs
//!   - comparison_js/comparison.wasm
//!   - comparison_final.zkey
//!
//! These are generated once by running `bash setup/trusted_setup.sh`.
//! All tests in this module are marked `#[ignore]` because they require
//! these generated files.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{prepare_verifying_key, Groth16, Proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A Groth16 proof that utility_a > utility_b, with both values private.
///
/// Maps to Gale-Shapley preference ordering in ProposedApproach.m:
/// a vehicle proves it ranked one match above another without revealing
/// the actual utility values (Utility_C{i}(j,k) or Profit_P{k}(j,i)).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComparisonProof {
    pub pid: u64,
    pub cid: u64,
    pub utility_a: u64,
    pub utility_b: u64,
    pub proof_hex: String,
}

/// Loads Circom circuit artifacts and generates/verifies Groth16 proofs.
pub struct SnarkProver {
    r1cs_path: PathBuf,
    wasm_path: PathBuf,
    zkey_path: PathBuf,
}

impl SnarkProver {
    /// Create a new SnarkProver from the circuit build directory.
    ///
    /// Expects in `circuit_dir`:
    ///   - `comparison.r1cs`
    ///   - `comparison_js/comparison.wasm`
    ///   - `comparison_final.zkey`
    ///
    /// Returns Err with the filename if any file is missing.
    pub fn new(circuit_dir: &Path) -> Result<Self, String> {
        let r1cs_path = circuit_dir.join("comparison.r1cs");
        let wasm_path = circuit_dir
            .join("comparison_js")
            .join("comparison.wasm");
        let zkey_path = circuit_dir.join("comparison_final.zkey");

        if !r1cs_path.exists() {
            return Err(format!("missing: {}", r1cs_path.display()));
        }
        if !wasm_path.exists() {
            return Err(format!("missing: {}", wasm_path.display()));
        }
        if !zkey_path.exists() {
            return Err(format!("missing: {}", zkey_path.display()));
        }

        Ok(Self {
            r1cs_path,
            wasm_path,
            zkey_path,
        })
    }

    /// Generate a Groth16 proof that utility_a > utility_b.
    ///
    /// Returns Err if utility_a <= utility_b (circuit constraint would fail).
    pub fn prove_comparison(
        &self,
        pid: u64,
        cid: u64,
        utility_a: u64,
        utility_b: u64,
    ) -> Result<ComparisonProof, String> {
        if utility_a <= utility_b {
            return Err(
                "utility_a must be strictly greater than utility_b".to_string(),
            );
        }

        // Load circuit configuration (R1CS + WASM witness generator)
        let cfg = CircomConfig::<Fr>::new(&self.wasm_path, &self.r1cs_path)
            .map_err(|e| format!("CircomConfig error: {}", e))?;

        // Build circuit with private inputs
        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("utility_a", utility_a);
        builder.push_input("utility_b", utility_b);
        let circuit = builder
            .build()
            .map_err(|e| format!("circuit build error: {}", e))?;

        // Load proving key from zkey file
        let zkey_file = File::open(&self.zkey_path)
            .map_err(|e| format!("zkey open error: {}", e))?;
        let (pk, _) = ark_circom::read_zkey(&mut BufReader::new(zkey_file))
            .map_err(|e| format!("zkey read error: {}", e))?;

        // Generate Groth16 proof using CircomReduction (matches snarkjs zkey format)
        let proof =
            Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
                circuit, &pk, &mut OsRng,
            )
            .map_err(|e| format!("proof generation error: {}", e))?;

        // Serialize proof to hex
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| format!("proof serialization error: {}", e))?;

        Ok(ComparisonProof {
            pid,
            cid,
            utility_a,
            utility_b,
            proof_hex: hex::encode(proof_bytes),
        })
    }

    /// Verify a comparison proof.
    ///
    /// Returns Ok(true) if the proof is valid, Ok(false) if invalid.
    pub fn verify_comparison(&self, proof: &ComparisonProof) -> Result<bool, String> {
        // Decode proof from hex
        let proof_bytes =
            hex::decode(&proof.proof_hex).map_err(|e| format!("hex decode error: {}", e))?;
        let groth_proof = Proof::<Bn254>::deserialize_compressed(&proof_bytes[..])
            .map_err(|e| format!("proof deserialization error: {}", e))?;

        // Load verification key from zkey
        let zkey_file = File::open(&self.zkey_path)
            .map_err(|e| format!("zkey open error: {}", e))?;
        let (pk, _) = ark_circom::read_zkey(&mut BufReader::new(zkey_file))
            .map_err(|e| format!("zkey read error: {}", e))?;
        let pvk = prepare_verifying_key(&pk.vk);

        // Public output: result = 1 (the circuit enforces utility_a > utility_b)
        let public_inputs = vec![Fr::from(1u64)];

        let valid = Groth16::<Bn254>::verify_proof(&pvk, &groth_proof, &public_inputs)
            .map_err(|e| format!("verification error: {}", e))?;

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Path to circuit build artifacts (created by setup/trusted_setup.sh).
    const CIRCUIT_DIR: &str = "circuits/build";

    #[test]
    #[ignore] // Requires: bash setup/trusted_setup.sh
    fn test_snark_valid() {
        let prover = SnarkProver::new(Path::new(CIRCUIT_DIR)).expect("load circuit");
        let proof = prover
            .prove_comparison(1, 2, 1000, 800)
            .expect("prove");
        let valid = prover.verify_comparison(&proof).expect("verify");
        assert!(valid, "valid comparison proof must verify");
    }

    #[test]
    #[ignore] // Requires: bash setup/trusted_setup.sh
    fn test_snark_equal() {
        let prover = SnarkProver::new(Path::new(CIRCUIT_DIR)).expect("load circuit");
        let result = prover.prove_comparison(1, 2, 1000, 1000);
        assert!(result.is_err(), "equal utilities must return Err");
    }

    #[test]
    #[ignore] // Requires: bash setup/trusted_setup.sh
    fn test_snark_less() {
        let prover = SnarkProver::new(Path::new(CIRCUIT_DIR)).expect("load circuit");
        let result = prover.prove_comparison(1, 2, 800, 1000);
        assert!(result.is_err(), "utility_a < utility_b must return Err");
    }

    #[test]
    #[ignore] // Requires: bash setup/trusted_setup.sh
    fn test_snark_tamper() {
        let prover = SnarkProver::new(Path::new(CIRCUIT_DIR)).expect("load circuit");
        let mut proof = prover
            .prove_comparison(1, 2, 1000, 800)
            .expect("prove");
        // Tamper: flip first byte of proof hex
        let mut bytes = hex::decode(&proof.proof_hex).expect("decode");
        bytes[0] ^= 0xFF;
        proof.proof_hex = hex::encode(bytes);
        // Either verify returns Ok(false) or Err — both acceptable
        match prover.verify_comparison(&proof) {
            Ok(valid) => assert!(!valid, "tampered proof must not verify"),
            Err(_) => {} // deserialization error is also acceptable
        }
    }

    #[test]
    fn test_snark_missing_circuit() {
        let result = SnarkProver::new(Path::new("nonexistent/"));
        assert!(result.is_err(), "missing circuit dir must return Err");
    }

    #[test]
    #[ignore] // Requires: bash setup/trusted_setup.sh
    fn test_snark_serde_roundtrip() {
        let prover = SnarkProver::new(Path::new(CIRCUIT_DIR)).expect("load circuit");
        let proof = prover
            .prove_comparison(1, 2, 1000, 800)
            .expect("prove");
        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: ComparisonProof =
            serde_json::from_str(&json).expect("deserialize");
        let valid = prover.verify_comparison(&proof2).expect("verify");
        assert!(valid, "roundtripped proof must verify");
    }
}
