# zkp_v2v

📄 **[Project Report](https://drive.google.com/file/d/1lYkKiEHiWKHmddE38YAt9aOG1eKRrIaN/view?usp=drive_link)**

## Overview
`zkp_v2v` is a high-performance cryptographic backend designed to augment Vehicle-to-Vehicle (V2V) energy sharing frameworks with robust privacy guarantees. 

This project operates as a **Privacy Layer** atop the original MATLAB-based V2V energy sharing simulation proposed by Shurrab et al. (IEEE TITS, 2022). The original simulation implements a Gale-Shapley stable matching algorithm to pair EVs with surplus energy (providers) to EVs needing charge (consumers). 

While the original framework requires participants to disclose sensitive data—such as battery State of Charge (SoC), location, and profit margins—to a central coordinator, `zkp_v2v` enables participants to prove their eligibility and compute optimal matching strictly using **Zero-Knowledge Proofs (ZKPs)**.

## Core Features
- **Dual-Paradigm ZKP Architecture**:
  - **Sigma Protocols**: Utilizes Pedersen Commitments over the RFC 2409 IKE Group 2 safe prime for fast, algebraic property proofs (non-negativity, sum correctness, profit margins).
  - **zkSNARKs**: Utilizes Groth16 (via `circom` and `arkworks`) to securely execute the non-algebraic Gale-Shapley strict utility comparisons natively.
- **Immutable Audit Ledger**: All generated proofs are automatically hashed and chained into a local SQLite Merkle tree, ensuring post-hoc accountability without exposing private values.
- **MATLAB Interoperability**: Provides a streamlined CLI tool (`zkp_cli`) that the MATLAB simulation invokes via synchronous system calls to execute cryptographic proofs in real-time.

## Prerequisites
- **Rust**: Minimum version `1.70+`
- **Circom**: Version `2.1.0+`
- **Node.js / npm**: (Optional, for `snarkjs` if running manual trusted setups)
- **MATLAB**: R2021a or later (for running the parent simulation)

## Build Instructions

1. **Install Dependencies**
   Ensure you have Rust and Cargo installed.
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Trusted Setup (One-Time)**
   Generate the Groth16 Proving and Verification keys for the comparison circuit.
   ```bash
   cd setup
   bash trusted_setup.sh
   ```

3. **Build the CLI**
   Compile the release binary for maximum performance.
   ```bash
   cargo build --release
   ```

## Usage
The primary interaction with this library is handled automatically by the `zkp_interface.m` wrapper inside the MATLAB simulation. However, you can manually interact with the CLI:

```bash
# Generate a consumer commitment and range proof
./target/release/zkp_cli prove --type consumer --value 4500

# Verify a Groth16 utility comparison proof
./target/release/zkp_cli verify --type comparison --proof comparison_proof.json
```

## Testing
Run the comprehensive cryptographic test suite, which includes property-based testing and SNARK verification testing:
```bash
cargo test --features snark -- --include-ignored
```

## References
This architecture serves as the cryptographic privacy layer for the Gale-Shapley V2V framework simulation.
- **Original Framework**: Based on the [MATLAB V2V Energy Sharing model by M. Shurrab et al.](https://github.com/mohammed-shurrab/V2V_Energy_Sharing_Framework)
- **SNARK Ecosystem**: Built utilizing [arkworks-rs](https://github.com/arkworks-rs) and [Circom](https://github.com/iden3/circom).
