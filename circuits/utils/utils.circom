
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

// Converts an array of binary bits into a number in big-endian format.
//
// Reviewers:
//   Keyvan: OK
//
template Bits2NumBigEndian(numBytes) {
    signal input in[numBytes * 8];
    signal output out;

    assert(numBytes <= 31); // Avoid overflows

    var result = 0;
    var step = 1;

    // Big-endian (Byte-level)
    for (var i = numBytes - 1; i >= 0; i--) {
        // Little-endian (Bit-level)
        for (var j = 0; j < 8; j++) {
            result += in[i * 8 + j] * step;
            step *= 2;
        }
    }

    out <== result;
}