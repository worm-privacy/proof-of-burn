pragma circom 2.2.2;

include "./keccak.circom";
include "./assert.circom";

// Proof-of-Work: Assert keccak(burnKey + 'EIP-7503') < 2 ^ (256 - 8 * minimumZeroBytes)
//
// Reviewers:
//   Keyvan: OK
//
template ProofOfWorkChecker() {
    signal input burnKey;
    signal input minimumZeroBytes;

    signal burnKeyBytes[32] <== Num2BytesBigEndian(32)(burnKey);

    signal burnKeyBytesPostfixed[40];
    for(var i = 0; i < 32; i++) {
        burnKeyBytesPostfixed[i] <== burnKeyBytes[i];
    }

    // Postfix the burn-key with string "EIP-7503" to prevent rainbow tables
    burnKeyBytesPostfixed[32] <== 69; // 'E'
    burnKeyBytesPostfixed[33] <== 73; // 'I'
    burnKeyBytesPostfixed[34] <== 80; // 'P'
    burnKeyBytesPostfixed[35] <== 45; // '-'
    burnKeyBytesPostfixed[36] <== 55; // '7'
    burnKeyBytesPostfixed[37] <== 53; // '5'
    burnKeyBytesPostfixed[38] <== 48; // '0'
    burnKeyBytesPostfixed[39] <== 51; // '3'

    signal burnKeyBlock[136] <== Fit(40, 136)(burnKeyBytesPostfixed);
    signal burnKeyKeccak[32] <== KeccakBytes(1)(burnKeyBlock, 40);

    signal shouldBeZero[32] <== Filter(32)(minimumZeroBytes);

    // Assert the first powMinimumZeroBytes bytes of keccak is zero
    for(var i = 0; i < 32; i++) {
        // If shouldBeZero[i] is 1, then burnKeyKeccak[i] should be zero
        // Otherwise it can obtain any value
        burnKeyKeccak[i] * shouldBeZero[i] === 0;
    }
}