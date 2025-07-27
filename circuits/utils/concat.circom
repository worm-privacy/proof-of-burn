pragma circom 2.2.2;

include "./array.circom";
include "./shift.circom";

// Outputs an array where only the first `ind` elements of `in` are kept,
// and the rest are zeroed out.
//
// Example:
//   in:  [1, 2, 3, 4, 5], ind: 3
//   out: [1, 2, 3, 0, 0]
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//   Sarah: OK
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
//   Sarah: OK
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

    // shiftedB: [0, 0, 0, 10, 20, 0, 0, 0, 0, 0]
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