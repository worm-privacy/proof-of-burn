
pragma circom 2.2.2;

include "../circomlib/circuits/comparators.circom";
include "./assert.circom";

// Generates an array where first `in` elements are one and the rest are zero
//
// Example Filter(5):
//   in:  0
//   out: [0, 0, 0, 0, 0]
//
//   in:  1
//   out: [1, 0, 0, 0, 0]
//
//   in:  3
//   out: [1, 1, 1, 0, 0]
//
//   in:  10
//   out: [1, 1, 1, 1, 1]
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//
template Filter(N) {
    signal input in;
    signal output out[N];

    signal isEq[N];
    for(var i = 0; i < N; i++) {
        isEq[i] <== IsEqual()([i, in]);
        if(i > 0) {
            out[i] <== out[i - 1] * (1 - isEq[i]);
        }
        else {
            out[i] <== (1 - isEq[i]);
        }
    }
}

// Fits a M-element array in a N-element block
//
// Reviewers:
//   Keyvan: OK
//
template Fit(M, N) {
    signal input in[M];
    signal output out[N];
    for(var i = 0; i < N; i++) {
        if(i < M) {
            out[i] <== in[i];
        } else {
            out[i] <== 0;
        }
    }
}

// Flattens a 2D array into a 1D array
//
// Reviewers:
//   Keyvan: OK
//
template Flatten(M, N) {
    signal input in[M][N];
    signal output out[M * N];
    for(var i = 0; i < M; i++) {
        for(var j = 0; j < N; j++) {
            out[i * N + j] <== in[i][j];
        }
    }
}

// Reshapes a 1D array into a 2D array
//
// Reviewers:
//   Keyvan: OK
//
template Reshape(M, N) {
    signal input in[M * N];
    signal output out[M][N];
    for(var i = 0; i < M; i++) {
        for(var j = 0; j < N; j++) {
            out[i][j] <== in[i * N + j];
        }
    }
}

// Reverses the input array
//
// Reviewers:
//   Keyvan: OK
//
template Reverse(N) {
    signal input in[N];
    signal output out[N];
    for(var i = 0; i < N; i++) {
        out[i] <== in[N - 1 - i];
    }
}