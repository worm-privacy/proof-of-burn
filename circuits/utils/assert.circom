pragma circom 2.2.2;

include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/bitify.circom";

// Check if all N inputs are binary
template AssertBinary(N) {
    signal input in[N];
    for(var i = 0; i < N; i++) {
        in[i] * (1 - in[i]) === 0;
    }
}

template AssertBits(B) {
    signal input a;
    signal bits[B] <== Num2Bits(B)(a);
}

template AssertLessThan(B) {
    signal input a;
    signal input b;
    AssertBits(B)(a);
    AssertBits(B)(b);
    signal out <== LessThan(B)([a, b]);
    out === 1;
}

template AssertLessEqThan(B) {
    signal input a;
    signal input b;
    AssertBits(B)(a);
    AssertBits(B)(b);
    signal out <== LessEqThan(B)([a, b]);
    out === 1;
}

template AssertGreaterEqThan(B) {
    signal input a;
    signal input b;
    AssertBits(B)(a);
    AssertBits(B)(b);
    signal out <== GreaterEqThan(B)([a, b]);
    out === 1;
}