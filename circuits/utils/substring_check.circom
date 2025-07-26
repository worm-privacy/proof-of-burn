pragma circom 2.2.2;

include "./utils.circom";
include "./assert.circom";


// Checks whether the byte-string `subInput` is a contiguous substring of `mainInput`.
//
// Example:
//   mainInput: [12, 23, 34, 45, 56, 67, 78, 89, 98, 87]
//   mainLen:   6
//   subInput:  [56, 67, 78]
//   out:       0
//
// Example:
//   mainInput: [12, 23, 34, 45, 56, 67, 78, 89, 98, 87]
//   mainLen:   7
//   subInput:  [56, 67, 78]
//   out:       1
//
// Reviewers:
//   Keyvan: OK
//
template SubstringCheck(maxMainLen, subLen) {
    signal input mainInput[maxMainLen];
    signal input mainLen;
    signal input subInput[subLen];
    signal output out;

    assert(subLen <= 31); // So that subInput fits in a field element

    // Substring-checker works with byte-string inputs
    AssertByteString(subLen)(subInput);
    AssertByteString(maxMainLen)(mainInput);

    AssertLessEqThan(16)(mainLen, maxMainLen);
    AssertLessEqThan(16)(subLen, mainLen);

    // Convert the sub-input into a field-element
    signal subInputNum <== LittleEndianBytes2Num(subLen)(subInput);

    // M[i] = Number representation of the first i bytes
    // If i = 0 --> M[i] = 0
    // If i > 0 --> M[i] = 256^0*mainInput[0] + 256^1*mainInput[1] + ... + 256^(i-1)*mainInput[i-1]
    signal M[maxMainLen + 1];
    M[0] <== 0;
    for (var i = 0; i < maxMainLen; i++) {
        M[i + 1] <== mainInput[i] * (256 ** i) + M[i];
    }
    // M[i + N] - M[i] = 256^i.mainInput[i] + ... + 256^(i+N-1).mainInput[i+N-1]
    //                 = 256^i.(256^0.mainInput[i] + ... + 256^(N-1).mainInput[i+N-1])
    //                 = 256^i.(Number representation of M[i..i + N])
    //
    // Substring-ness Equation: Substring exists if there is `i` where:
    // (256 ^ i) * subInputNum == M[i + subLen] - M[i]
    //
    // Reasons this is safe:
    // 1. If this holds:
    //      (256 ^ i) * subInputNum == M[i + subLen] - M[i]
    //    Then:
    //      (256 ^ i) * subInputNum == 256^i.(256^0.mainInput[i] + ... + 256^(N-1).mainInput[i+N-1])
    //    Which means:
    //      subInputNum == 256^0.mainInput[i] + ... + 256^(N-1).mainInput[i+N-1]
    //    That's because in a prime-field, when `ab == ac`, then we can conclude that `b == c`
    //    Thus, all the bytes in M[i..i + subLen] has to be equal with subInput
    // 2. Also subInput's length is limited to 31 bytes, so subInputNum will not overflow
    //    and we won't have unexpected/fancy bugs here.

    
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
        exists[i] <== IsEqual()([subInputNum * (256 ** i), M[i + subLen] - M[i]]);

        // Existence flag is accumulated in the sum only when we are in the allowed region
        sums[i + 1] <== sums[i] + allowed[i + 1] * exists[i];
    }

    // Substring exists only when there has been a 1 while summing up the existence flags
    signal doesNotExist <== IsZero()(sums[maxMainLen - subLen + 1]);
    out <== 1 - doesNotExist;
}