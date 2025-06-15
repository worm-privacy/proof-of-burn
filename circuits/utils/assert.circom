pragma circom 2.2.2;

include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/bitify.circom";

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