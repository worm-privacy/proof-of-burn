pragma circom 2.2.2;

include "../circomlib/circuits/comparators.circom";
include "./assert.circom";

// Shifts the `in` array to the left by the given `count` times, filling the end with zeros.
//
// Example:
//   in:    [1, 2, 3, 4, 5]
//   count: 2
//   out:   [3, 4, 5, 0, 0]
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//
template ShiftLeft(n) {
    signal input in[n];
    signal input count;
    signal output out[n];

    AssertLessEqThan(16)(count, n);

    var outVars[n];
    signal isEq[n][n];
    signal temp[n][n];
    // out[i] <== sum_j(in[j] * (i == j - count))
    for(var i = 0; i < n; i++) {
        for(var j = 0; j < n; j++) {
            isEq[i][j] <== IsEqual()([i, j - count]) ;
            temp[i][j] <== isEq[i][j] * in[j];
            outVars[i] += temp[i][j];
        }
        out[i] <== outVars[i];
    }
}

// Shifts the input array `in` to the right by `count` positions,
// filling the leftmost `count` positions with zeros.
//
// Example:
//   maxShift: 5 
//   count:    3
//   in:       [1, 2, 3, 4, 5, 6, 7, 8]
//   output:   [0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0]
//
// Reviewers:
//   Keyvan: OK
//   Sarah: OK
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