pragma circom 2.2.2;

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

    // A = 2^0*subInput[0] + 2^1*subInput[1] + ... + 2^(subLen - 1) subInput[subLen - 1]
    signal A[subLen + 1];
    A[0] <== 0;
    for (var i = 0; i < subLen; i++) {
        A[i + 1] <== subInput[i] * (2 ** i) + A[i];
    }

    // B = 2^0*mainInput[0] + 2^1*mainInput[1] + ... + 2^(maxMainLen - 1) mainInput[maxMainLen - 1]
    signal B[maxMainLen + 1];
    B[0] <== 0;
    for (var i = 0; i < maxMainLen; i++) {
        B[i + 1] <== mainInput[i] * (2 ** i) + B[i];
    }

    // Substring exists if there is `i` where:
    // 2 ^ i * A[subLen] == B[i] - B[i - subLen]

    // Existence flags. When exists[i] is 1 it means that:
    // mainInput[i..i + subLen] == subInput
    signal exists[maxMainLen - subLen + 1];

    // Used for creating an `allowed` filter: [1, 1, ..., 1, 1, 0, 0, ..., 0, 0]
    // Where the first `mainLen - subLen` elements are 1, indicating the existence
    // flags that should be considered.
    signal isLastIndex[maxMainLen - subLen + 1];
    signal allowed[maxMainLen - subLen + 2];
    allowed[0] <== 1;

    // For summing up all the *allowed* existence flags.
    signal sums[maxMainLen - subLen + 2];
    sums[0] <== 0;

    for (var i = 0; i < maxMainLen - subLen + 1; i++) {
        // Building the `allowed` filter
        isLastIndex[i] <== IsEqual()([i, mainLen - subLen + 1]);
        allowed[i + 1] <== allowed[i] * (1 - isLastIndex[i]);

        // Existence check
        exists[i] <== IsEqual()([A[subLen] * (2 ** i), B[i + subLen] - B[i]]);

        // Existence flag is accumulated in the sum only when we are in the allowed region
        sums[i + 1] <== sums[i] + allowed[i + 1] * exists[i];
    }

    // Substring exists only when there has been a 1 while summing up the existence flags
    signal doesNotExist <== IsZero()(sums[maxMainLen - subLen + 1]);
    out <== 1 - doesNotExist;
}