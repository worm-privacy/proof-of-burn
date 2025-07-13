pragma circom 2.2.2;

include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/bitify.circom";

// Assert the input number is less than 2^B 
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//
template AssertBits(B) {
    signal input in;
    assert(B < 254); // For bit-length of 254 Num2Bits_strict() should be used
    signal bits[B] <== Num2Bits(B)(in);
}

// Assert all N inputs are bytes
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//
template AssertByteString(N) {
    signal input in[N];
    for(var i = 0; i < N; i++) {
        AssertBits(8)(in[i]);
    }
}

// Assert a < b (Where a and b are at most B bits long)
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//
template AssertLessThan(B) {
    signal input a;
    signal input b;
    AssertBits(B)(a);
    AssertBits(B)(b);
    signal out <== LessThan(B)([a, b]);
    out === 1;
}

// Assert a <= b (Where a and b are at most B bits long)
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//
template AssertLessEqThan(B) {
    signal input a;
    signal input b;
    AssertBits(B)(a);
    AssertBits(B)(b);
    signal out <== LessEqThan(B)([a, b]);
    out === 1;
}

// Assert a >= b (Where a and b are at most B bits long)
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//
template AssertGreaterEqThan(B) {
    signal input a;
    signal input b;
    AssertBits(B)(a);
    AssertBits(B)(b);
    signal out <== GreaterEqThan(B)([a, b]);
    out === 1;
}