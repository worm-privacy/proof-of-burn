pragma circom 2.2.2;

include "../circomlib/circuits/comparators.circom";

template AssertLessThan(B) {
    signal input a;
    signal input b;
    signal out <== LessThan(B)([a, b]);
    out === 1;
}


template AssertLessEqThan(B) {
    signal input a;
    signal input b;
    signal out <== LessEqThan(B)([a, b]);
    out === 1;
}