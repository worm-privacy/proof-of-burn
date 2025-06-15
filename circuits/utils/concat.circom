pragma circom 2.2.2;

include "./utils.circom";
include "./assert.circom";

// Outputs an array where only the first `ind` elements of `in` are kept,
// and the rest are zeroed out.
//
// Example:
//   in:  [1, 2, 3, 4, 5], ind: 3
//   out: [1, 2, 3, 0, 0]
template Mask(n) {
    signal input in[n];
    signal input count;
    signal output out[n];

    signal eqs[n+1];
    eqs[0] <== 1;
    signal eqcomps[n];
    for(var i = 0; i < n; i++) {
        eqcomps[i] <== IsEqual()([i, count]);
        eqs[i+1] <== eqs[i] * (1 - eqcomps[i]);
        out[i] <== in[i] * eqs[i + 1];
    }
}

// Shifts the input array `in` to the right by `count` positions,
// filling the leftmost `count` positions with zeros.
//
// Example:
//   in:    [1, 2, 3, 4, 5, 6, 7, 8], count: 3
//   output:[0, 0, 0, 1, 2, 3, 4, 5]
template Shift(n, maxShift) {
    signal input in[n];
    signal input count;
    signal output out[n + maxShift];

    AssertLessEqThan(16)(count, maxShift);

    var outsum[n + maxShift];

    component eqcomps[maxShift + 1];
    signal temps[maxShift + 1][n];
    for(var i = 0; i <= maxShift; i++) {
        eqcomps[i] = IsEqual();
        eqcomps[i].in[0] <== i;
        eqcomps[i].in[1] <== count;
        for(var j = 0; j < n; j++) {
            temps[i][j] <== eqcomps[i].out * in[j];
            outsum[i + j] += temps[i][j];
        }
    }

    for(var i = 0; i < n + maxShift; i++) {
        out[i] <== outsum[i];
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
template Concat(maxLenA, maxLenB) {
    signal input a[maxLenA];
    signal input aLen;

    signal input b[maxLenB];
    signal input bLen;

    signal output out[maxLenA + maxLenB];
    signal output outLen;

    AssertLessEqThan(16)(aLen, maxLenA);
    AssertLessEqThan(16)(bLen, maxLenB);

    signal maskedA[maxLenA] <== Mask(maxLenA)(a, aLen);
    signal maskedB[maxLenB] <== Mask(maxLenB)(b, bLen);
    signal shiftedB[maxLenA + maxLenB] <== Shift(maxLenB, maxLenA)(maskedB, aLen);
    
    for(var i = 0; i < maxLenA + maxLenB; i++) {
        if(i < maxLenA) {
            out[i] <== maskedA[i] + shiftedB[i];
        } else {
            out[i] <== shiftedB[i];
        }
    }

    outLen <== aLen + bLen;
}