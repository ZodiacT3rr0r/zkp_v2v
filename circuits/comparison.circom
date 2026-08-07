// Circom comparison circuit for V2V ZKP utility ordering proofs.
//
// PURPOSE:
//   Proves that utility_a > utility_b, where both are private witnesses.
//   This maps to the Gale-Shapley preference ordering in ProposedApproach.m:
//   a consumer/provider can prove they correctly ranked one match above another
//   without revealing the actual utility values (Utility_C{i}(j,k) or Profit_P{k}(j,i)).
//
// BIT WIDTH:
//   n = 64 supports utility scores up to 2^64 - 1 ≈ 1.8 × 10^19.
//   MATLAB utility values are sums of travel cost, energy price, time cost, etc.,
//   typically ranging from hundreds to tens of thousands of cents — well within 64 bits.
//
// SIGNALS:
//   utility_a (private) — utility for the preferred match
//   utility_b (private) — utility for the alternative
//   result    (public output) — must equal 1 for a valid proof

pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

template UtilityComparison(n) {
    signal input utility_a;   // private witness
    signal input utility_b;   // private witness
    signal output result;     // public output, must equal 1

    component gt = GreaterThan(n);
    gt.in[0] <== utility_a;
    gt.in[1] <== utility_b;
    result <== gt.out;
    result === 1;             // proof only valid when a > b
}

component main = UtilityComparison(64);
