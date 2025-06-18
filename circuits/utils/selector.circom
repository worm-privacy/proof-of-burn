pragma circom 2.2.2;

include "./assert.circom";


// Selects the element at the given index `select` from the input array `vals`.
//
// Example:
// vals:   [10, 20, 30, 40]
// select: 2
// out:    30
template Selector(n) {
    signal input vals[n];
    signal input select;
    signal output out;

    AssertLessThan(16)(select, n);

    // isEq is the filter: [0, ..., 0, 1, 0, ..., 0]
    // Where the ith index is 1 and the rest are 0
    signal isEq[n];

    signal sum[n + 1];
    sum[0] <== 0;
    for(var i = 0; i < n; i++) {
        isEq[i] <== IsEqual()([select, i]);

        // Keep the vals[i] only when i == select
        sum[i + 1] <== sum[i] + isEq[i] * vals[i];
    }

    out <== sum[n];
}
