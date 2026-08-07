#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# One-time trusted setup for the V2V ZKP comparison circuit.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Run this ONCE, OFFLINE. Commit circuits/build/ to the repository.
# The generated files are used by src/snark.rs at runtime for proof
# generation and verification.
#
# Prerequisites:
#   - circom  (https://docs.circom.io/getting-started/installation/)
#   - snarkjs (npm install -g snarkjs)
#   - circomlib (npm install circomlib) in the project root or globally
#
# Output (circuits/build/):
#   comparison.r1cs              — R1CS constraint system
#   comparison_js/comparison.wasm — WASM witness generator
#   comparison_final.zkey         — Groth16 proving key (includes VK)
#   comparison_vk.json            — Verification key (JSON, for reference)
#
# Security note:
#   This script uses a single-contributor ceremony for simplicity.
#   For production, use a multi-party computation ceremony.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -e

CIRCUIT=circuits/comparison
OUT=circuits/build
mkdir -p $OUT

echo "=== Step 1: Compile circuit → R1CS + WASM ==="
# --r1cs: emit the R1CS constraint system
# --wasm: emit the WASM witness generator
# --sym:  emit the symbol table (for debugging)
circom $CIRCUIT.circom --r1cs --wasm --sym -l node_modules -o $OUT

echo ""
echo "=== Step 2: Powers of Tau (universal, not circuit-specific) ==="
# 2^12 = 4096 constraints max; UtilityComparison(64) uses ~192 constraints.
# This is sufficient and keeps setup fast.
snarkjs powersoftau new bn128 12 $OUT/pot12_0000.ptau -v
snarkjs powersoftau contribute $OUT/pot12_0000.ptau $OUT/pot12_0001.ptau \
  --name="V2V Phase1" -e="$(date +%s%N)"
snarkjs powersoftau prepare phase2 $OUT/pot12_0001.ptau $OUT/pot12_final.ptau -v

echo ""
echo "=== Step 3: Groth16 circuit-specific setup ==="
snarkjs groth16 setup $OUT/comparison.r1cs $OUT/pot12_final.ptau \
  $OUT/comparison_0000.zkey
snarkjs zkey contribute $OUT/comparison_0000.zkey $OUT/comparison_final.zkey \
  --name="V2V Phase2" -e="$(date +%s%N)"

echo ""
echo "=== Step 4: Export verification key ==="
snarkjs zkey export verificationkey \
  $OUT/comparison_final.zkey $OUT/comparison_vk.json

echo ""
echo "=== Setup complete ==="
echo "Files written to $OUT/"
echo ""
echo "Commit these files to the repository:"
echo "  $OUT/comparison.r1cs"
echo "  $OUT/comparison_js/"
echo "  $OUT/comparison_final.zkey"
echo ""
echo "To run the ignored SNARK tests:"
echo "  cargo test -- --ignored"
