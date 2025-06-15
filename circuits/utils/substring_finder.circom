pragma circom 2.2.2;

include "./keccak/keccak.circom";
include "./keccak/utils.circom";
include "./utils.circom";
include "./assert.circom";


// Checks whether the array `subInput` is a contiguous substring of `mainInput`.
//
// Example:
//   mainInput: [1, 2, 3, 4, 5, 6, 7, 0, 0, 0]
//   mainLen:   7
//   subInput:  [3, 4, 5]
//   out:       1
template SubstringCheck(maxMainLen, subLen) {
    signal input mainInput[maxMainLen];
    signal input mainLen;
    signal input subInput[subLen];
    signal output out;

    AssertLessEqThan(16)(mainLen, maxMainLen);
    AssertLessEqThan(16)(subLen, mainLen);

    // A = 2^0 subInput[0] + 2^1 subInput[1] + ... + 2^255 subInput[255]
    signal A[subLen + 1];
    A[0] <== 0;
    for (var i = 0; i < subLen; i++) {
        A[i+1] <== subInput[i] * (2**i) + A[i];
    }

    signal B[maxMainLen + 1];
    B[0] <== 0;
    for (var i = 0; i < maxMainLen; i++) {
        B[i+1] <== mainInput[i] * (2**i) + B[i];
    }

    signal eq[maxMainLen - subLen + 1];
    signal endCheckers[maxMainLen - subLen + 1];
    signal allowed[maxMainLen - subLen + 2];
    allowed[0] <== 1;
    signal sums[maxMainLen - subLen + 2];
    sums[0] <== 0;
    for (var i = 0; i < maxMainLen - subLen + 1; i++) {
        eq[i] <== IsEqual()([A[subLen] * (2 ** i), B[i + subLen] - B[i]]);
        endCheckers[i] <== IsEqual()([i, mainLen - subLen + 1]);
        allowed[i+1] <== allowed[i] * (1 - endCheckers[i]);
        sums[i+1] <== sums[i] + allowed[i+1] * eq[i];
    }

    signal isz <== IsZero()(sums[maxMainLen - subLen + 1]);
    out <== 1 - isz;
}