pragma circom 2.2.2;

include "./keccak.circom";
include "./assert.circom";

// Proof-of-Work: Assert keccak(burnKey | receiverAddress | fee | 'EIP-7503') < 2 ^ (256 - 8 * minimumZeroBytes)
//
// Reviewers:
//   Keyvan: OK
//
template ProofOfWorkChecker() {
    signal input burnKey;
    signal input receiverAddress;
    signal input fee;
    signal input minimumZeroBytes;

    signal burnKeyBytes[32] <== Num2BigEndianBytes(32)(burnKey);
    signal addressBytes[20] <== Num2BigEndianBytes(20)(receiverAddress);
    signal feeBytes[32] <== Num2BigEndianBytes(32)(fee);

    signal hasherInput[92]; // 32 (burnKeyBytes) + 20 (addressBytes) + 32 (feeBytes) + 8 (EIP-7503 postfix)
    for(var i = 0; i < 32; i++) {
        hasherInput[i] <== burnKeyBytes[i];
    }
    for(var i = 0; i < 20; i++) {
        hasherInput[32 + i] <== addressBytes[i];
    }
    for(var i = 0; i < 32; i++) {
        hasherInput[32 + 20 + i] <== feeBytes[i];
    }

    // Postfix the burn-key with string "EIP-7503" to prevent rainbow tables
    hasherInput[84] <== 69; // 'E'
    hasherInput[85] <== 73; // 'I'
    hasherInput[86] <== 80; // 'P'
    hasherInput[87] <== 45; // '-'
    hasherInput[88] <== 55; // '7'
    hasherInput[89] <== 53; // '5'
    hasherInput[90] <== 48; // '0'
    hasherInput[91] <== 51; // '3'

    signal burnKeyBlock[136] <== Fit(92, 136)(hasherInput);
    signal burnKeyKeccak[32] <== KeccakBytes(1)(burnKeyBlock, 92);

    signal shouldBeZero[32] <== Filter(32)(minimumZeroBytes);

    // Assert the first powMinimumZeroBytes bytes of keccak is zero
    for(var i = 0; i < 32; i++) {
        // If shouldBeZero[i] is 1, then burnKeyKeccak[i] should be zero
        // Otherwise it can obtain any value
        burnKeyKeccak[i] * shouldBeZero[i] === 0;
    }
}