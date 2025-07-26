pragma circom 2.2.2;

include "./assert.circom";


// Selects the element at the given index `select` from the input array `vals`.
//
// Example:
// vals:   [10, 20, 30, 40]
// select: 2
// out:    30
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: The circuit is OK but why not use Decoder() from `multiplexer` in circomlib? I mean, for the sake of fewer lines of code. Also, why not use `var sum` instead of [n+1] signals?
//      - Keyvan's response: Can't accumulate them inside a `var sum` because it makes it non-quadratic. Also I thought the current version is easier to understand than using Decoder gadgets.
//
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


// Selects the 1D-array at the given index `select` from an MxN array of 1D-arrays `arrays`.
//
// Example:
// arrays: [[11, 21, 31, 41],
//          [12, 22, 32, 42],
//          [13, 23, 33, 43],
//          [14, 24, 34, 44]]
// select: 2
// out:    [13, 23, 33, 43]
//
// Reviewers:
//   Keyvan: OK
//
template SelectorArray1D(m, n) {
    signal input arrays[m][n];
    signal input select;
    signal output out[n];

    signal arraysT[n][m]; // Transposed
    for(var i = 0; i < m; i++) {
        for(var j = 0; j < n; j++) {
            arraysT[j][i] <== arrays[i][j];
        }
    }

    for(var i = 0; i < n; i++) {
        out[i] <== Selector(m)(arraysT[i], select);
    }
}

// Selects the 2D-array at the given index `select` from an MxPxQ array of 2D-arrays `arrays`.
//
// Example:
// arrays: [[[1, 2],[3, 4]],
//          [[2, 4],[6, 8]],
//          [[3, 6],[9, 12]]]
// select: 1
// out:    [[2, 4],[6, 8]]
//
// Reviewers:
//   Keyvan: OK
//
template SelectorArray2D(m, p, q) {
    signal input arrays[m][p][q];
    signal input select;
    signal output out[p][q];

    signal arraysT[p][q][m]; // Transposed
    for(var i = 0; i < m; i++) {
        for(var j = 0; j < p; j++) {
            for(var k = 0; k < q; k++) {
                arraysT[j][k][i] <== arrays[i][j][k];
            }
        }
    }

    for(var i = 0; i < p; i++) {
        for(var j = 0; j < q; j++) {
            out[i][j] <== Selector(m)(arraysT[i][j], select);
        }
    }
}

