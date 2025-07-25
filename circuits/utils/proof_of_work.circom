pragma circom 2.2.2;

include "./keccak.circom";
include "./assert.circom";

// Proof-of-Work: Assert keccak(burnKey | receiverAddress | 'EIP-7503') < 2 ^ (256 - 8 * minimumZeroBytes)
//
// Reviewers:
//   Keyvan: OK
//
template ProofOfWorkChecker() {
    signal input burnKey;
    signal input receiverAddress;
    signal input minimumZeroBytes;

    signal burnKeyBytes[32] <== Num2BigEndianBytes(32)(burnKey);
    signal addressBytes[20] <== Num2BigEndianBytes(20)(receiverAddress);

    signal hasherInput[60]; // 32 (burnKeyBytes) + 20 (addressBytes) + 8 (EIP-7503 postfix)
    for(var i = 0; i < 32; i++) {
        hasherInput[i] <== burnKeyBytes[i];
    }
    for(var i = 0; i < 20; i++) {
        hasherInput[32 + i] <== addressBytes[i];
    }

    // Postfix the burn-key with string "EIP-7503" to prevent rainbow tables
    hasherInput[52] <== 69; // 'E'
    hasherInput[53] <== 73; // 'I'
    hasherInput[54] <== 80; // 'P'
    hasherInput[55] <== 45; // '-'
    hasherInput[56] <== 55; // '7'
    hasherInput[57] <== 53; // '5'
    hasherInput[58] <== 48; // '0'
    hasherInput[59] <== 51; // '3'

    signal burnKeyBlock[136] <== Fit(60, 136)(hasherInput);
    signal burnKeyKeccak[32] <== KeccakBytes(1)(burnKeyBlock, 60);

    signal shouldBeZero[32] <== Filter(32)(minimumZeroBytes);

    // Assert the first powMinimumZeroBytes bytes of keccak is zero
    for(var i = 0; i < 32; i++) {
        // If shouldBeZero[i] is 1, then burnKeyKeccak[i] should be zero
        // Otherwise it can obtain any value
        burnKeyKeccak[i] * shouldBeZero[i] === 0;
    }
}