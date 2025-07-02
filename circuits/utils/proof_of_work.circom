pragma circom 2.2.2;

include "./hasher.circom";
include "./assert.circom";

// Proof-of-Work: Assert MiMC(burnKey, 2) < 2 ^ maxBits
//
// Reviewers:
//   Keyvan: OK
//
template ProofOfWorkChecker(powMaxAllowedBits) {
    signal input burnKey;
    signal hash <== Hasher()(burnKey, 2);
    AssertBits(powMaxAllowedBits)(hash);
}