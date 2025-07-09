pragma circom 2.2.2;

include "./utils.circom";
include "./assert.circom";

// Outputs an array where only the first `ind` elements of `in` are kept,
// and the rest are zeroed out.
//
// Example:
//   in:  [1, 2, 3, 4, 5], ind: 3
//   out: [1, 2, 3, 0, 0]
//
// Reviewers:
//   Keyvan: OK
//
template Mask(n) {
    signal input in[n];
    signal input count;
    signal output out[n];

    // Generate filter: [1, 1, ..., 1, 1, 0, 0, ..., 0, 0]
    signal filter[n] <== Filter(n)(count);

    // Apply filter
    for(var i = 0; i < n; i++) {
        out[i] <== in[i] * filter[i];
    }
}

// Shifts the input array `in` to the right by `count` positions,
// filling the leftmost `count` positions with zeros.
//
// Example:
//   in:    [1, 2, 3, 4, 5, 6, 7, 8], count: 3
//   output:[0, 0, 0, 1, 2, 3, 4, 5]
//
// Reviewers:
//   Keyvan: OK
//
template ShiftRight(n, maxShift) {
    signal input in[n];
    signal input count;
    signal output out[n + maxShift];

    AssertLessEqThan(16)(count, maxShift);

    var outVars[n + maxShift];

    // Shift by `i` only when `i == count`
    // out[i + j] <== (i == count) * in[j]
    // I.e out[i + j] <== in[j] when `i == count`
    signal isEq[maxShift + 1];
    signal temps[maxShift + 1][n];
    for(var i = 0; i <= maxShift; i++) {
        isEq[i] <== IsEqual()([i, count]);
        for(var j = 0; j < n; j++) {
            temps[i][j] <== isEq[i] * in[j];
            outVars[i + j] += temps[i][j];
        }
    }

    for(var i = 0; i < n + maxShift; i++) {
        out[i] <== outVars[i];
    }
}


// Concatenates arrays `a` and `b` up to lengths `aLen` and `bLen`
// Output is length `outLen`
// Elements beyond the concatenated length are zero-padded
//
// Example:
//   a:      [1, 2, 3, 4, 5], aLen: 3
//   b:      [10, 20, 30, 40, 50], bLen: 2
//   outLen: 5
//   out: [1, 2, 3, 10, 20, 0, 0, 0, 0, 0]
//
// Reviewers:
//   Keyvan: OK
//
template Concat(maxLenA, maxLenB) {
    signal input a[maxLenA];
    signal input aLen;

    signal input b[maxLenB];
    signal input bLen;

    signal output out[maxLenA + maxLenB];
    signal output outLen;

    AssertLessEqThan(16)(aLen, maxLenA);
    AssertLessEqThan(16)(bLen, maxLenB);

    // Example:
    // a: [1, 2, 3, 4, 5] aLen: 3
    // b: [10, 20, 30, 40, 50] bLen: 2

    // maskedA: [1, 2, 3, 0, 0]
    signal maskedA[maxLenA] <== Mask(maxLenA)(a, aLen);

    // maskedB: [10, 20, 0, 0, 0]
    signal maskedB[maxLenB] <== Mask(maxLenB)(b, bLen);

    // shiftedB: [0, 0, 0, 10, 20, 0, 0, 0]
    signal shiftedB[maxLenA + maxLenB] <== ShiftRight(maxLenB, maxLenA)(maskedB, aLen);
    
    // out = maskedA + shiftedB
    // out: [1, 2, 3, 10, 20, 0, 0, 0, 0, 0]
    for(var i = 0; i < maxLenA + maxLenB; i++) {
        if(i < maxLenA) {
            out[i] <== maskedA[i] + shiftedB[i];
        } else {
            out[i] <== shiftedB[i];
        }
    }

    outLen <== aLen + bLen;
}