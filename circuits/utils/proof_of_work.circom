pragma circom 2.2.2;

include "./keccak.circom";
include "./assert.circom";

// Proof-of-Work: Assert keccak(burnKey) < 2 ^ (256 - 8 * powMinimumZeroBytes)
//
// Reviewers:
//   Keyvan: OK
//
template ProofOfWorkChecker(powMinimumZeroBytes) {
    signal input burnKey;
    signal burnKeyBytes[32] <== Num2BytesBigEndian()(burnKey);
    signal burnKeyBlock[136] <== Fit(32, 136)(burnKeyBytes);
    signal burnKeyKeccak[32] <== KeccakBytes(1)(burnKeyBlock, 32);

    assert(powMinimumZeroBytes <= 32);

    // Assert the first powMinimumZeroBytes bytes of keccak is zero
    for(var i = 0; i < powMinimumZeroBytes; i++) {
        burnKeyKeccak[i] === 0;
    }
}