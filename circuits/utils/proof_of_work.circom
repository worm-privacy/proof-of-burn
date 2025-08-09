pragma circom 2.2.2;

include "./keccak.circom";
include "./assert.circom";

// The "EIP-7503" string
//
// Reviewers:
//   Keyvan: OK
//
template EIP7503() {
    signal output out[8];
    out[0] <== 69; // 'E'
    out[1] <== 73; // 'I'
    out[2] <== 80; // 'P'
    out[3] <== 45; // '-'
    out[4] <== 55; // '7'
    out[5] <== 53; // '5'
    out[6] <== 48; // '0'
    out[7] <== 51; // '3'
}

// Concat 4 fixed-size strings
//
// Reviewers:
//   Keyvan: OK
//
template ConcatFixed4(A, B, C, D) {
    signal input a[A];
    signal input b[B];
    signal input c[C];
    signal input d[D];
    signal output out[A + B + C + D];

    for(var i = 0; i < A; i++) {
        out[i] <== a[i];
    }
    for(var i = 0; i < B; i++) {
        out[i + A] <== b[i];
    }
    for(var i = 0; i < C; i++) {
        out[i + A + B] <== c[i];
    }
    for(var i = 0; i < D; i++) {
        out[i + A + B + C] <== d[i];
    }
}

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
    signal receiverAddressBytes[20] <== Num2BigEndianBytes(20)(receiverAddress);
    signal feeBytes[32] <== Num2BigEndianBytes(32)(fee);
    signal eip7503[8] <== EIP7503()();

    var hasherInputLen = 92; // 32 + 20 + 32 + 8
    signal hasherInput[hasherInputLen] <== ConcatFixed4(32, 20, 32, 8)(
        burnKeyBytes, receiverAddressBytes, feeBytes, eip7503
    );

    signal burnKeyBlock[136] <== Fit(hasherInputLen, 136)(hasherInput);
    signal burnKeyKeccak[32] <== KeccakBytes(1)(burnKeyBlock, hasherInputLen);

    signal shouldBeZero[32] <== Filter(32)(minimumZeroBytes);

    // Assert the first powMinimumZeroBytes bytes of keccak is zero
    for(var i = 0; i < 32; i++) {
        // If shouldBeZero[i] is 1, then burnKeyKeccak[i] should be zero
        // Otherwise it can obtain any value
        burnKeyKeccak[i] * shouldBeZero[i] === 0;
    }
}