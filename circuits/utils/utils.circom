
pragma circom 2.2.2;

include "./assert.circom";

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

// Fits a M-element array in a N-element block
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

// Computes the quotient and remainder for the division of a by b:
// a === out * b + rem
//
// Example:
//   a:   10
//   b:   3
//   out: 3
//   rem: 1
//
// Reviewers:
//   Keyvan: OK
//
template Divide(N) {
    signal input a;
    signal input b;
    signal output out;
    signal output rem;

    out <-- a \ b;
    rem <-- a % b;

    // Check if `rem` and `b` are at most N-bits long and `rem < b`
    AssertLessThan(N)(rem, b);

    // Check if `out` and `a` are at most N-bits long and `out < a`
    AssertLessEqThan(N)(out, a);

    out * b + rem === a;
}

// Accepts N bytes (As 8xN bits) and outputs N bytes (As 8xN bits) where bytes are reversed
//
// Reviewers:
//   Keyvan: OK
//
template ReverseBytes(N) {
    signal input in[N * 8];
    signal output out[N * 8];
    for(var i = 0; i < N; i++) {
        for(var j = 0; j < 8; j++) {
            out[8 * i + j] <== in[8 * (N - 1 - i) + j];
        }
    }
}

// Convert a field element to 256-bits
//
// Reviewers:
//   Keyvan: OK
//
template FieldToBigEndianBits() {
    signal input in;
    signal output out[256];

    signal bitsStrict[254] <== Num2Bits_strict()(in);
    signal bits[256] <== Fit(254, 256)(bitsStrict); // Set the 2 remaining bytes to zero
    out <== ReverseBytes(32)(bits);
}