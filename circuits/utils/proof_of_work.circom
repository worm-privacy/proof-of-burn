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
    signal burnKeyBits[256] <== FieldToBigEndianBits()(burnKey);
    signal burnKeyBlock[136 * 8] <== Fit(256, 136 * 8)(burnKeyBits);
    signal burnKeyKeccak[256] <== KeccakBits(1)(burnKeyBlock, 256);

    assert(powMinimumZeroBytes <= 32);

    // Assert the first powMinimumZeroBytes of keccak is zero
    for(var i = 0; i < powMinimumZeroBytes; i++) {
        for(var j = 0; j < 8; j++) {
            burnKeyKeccak[i * 8 + j] === 0;
        }
    }
}