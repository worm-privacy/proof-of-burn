pragma circom 2.2.2;

include "./assert.circom";


// Selects the element at the given index `select` from the input array `vals`.
//
// Example:
// vals:   [10, 20, 30, 40]
// select: 2
// out:    30
template Selector (n) {
    signal input vals[n];
    signal input select;
    signal output out;

    AssertLessThan(16)(select, n);

    signal eqs[n];
    signal sum[n+1];
    sum[0] <== 0;
    for(var i = 0; i < n; i++) {
        eqs[i] <== IsEqual()([select, i]);
        sum[i + 1] <== sum[i] + eqs[i] * vals[i];
    }

    out <== sum[n];
}
