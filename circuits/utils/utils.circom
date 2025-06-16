
pragma circom 2.2.2;

include "./assert.circom";

// Computes the quotient and remainder for the division of a by b:
// a === out * b + rem
//
// Example:
//   a:   10
//   b:   3
//   out: 3
//   rem: 1
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

// Bits2NumBigEndian Template:
// Converts an array of binary bits into a number in big-endian format.
template Bits2NumBigEndian(numBytes) {
    signal input in[numBytes * 8];
    signal output out;
    var number = 0;
    var step1 = 1;

    for (var i = numBytes - 1; i >= 0; i--) {
        var step2 = 1;
        var tmp_number = 0;
        for (var j = 0; j < 8; j++) {
            tmp_number += in[i * 8 + j] * step2;
            step2 *= 2;
        }
        number += tmp_number * step1;
        step1 *= 256;
    }

    number ==> out;
}