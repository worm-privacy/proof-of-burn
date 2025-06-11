pragma circom 2.1.5;

include "./keccak/keccak.circom";
include "./keccak/utils.circom";
include "./utils.circom";


 template SubstringCheck(maxMainLen, subLen) {
    signal input mainInput[maxMainLen];
    signal input mainLen;
    signal input subInput[subLen];
    signal output out;

    component lteThanMax = LessEqThan(16);
    lteThanMax.in[0] <== mainLen;
    lteThanMax.in[1] <== maxMainLen;
    lteThanMax.out === 1;
    component gteThanSub = GreaterEqThan(16);
    gteThanSub.in[0] <== mainLen;
    gteThanSub.in[1] <== subLen;
    gteThanSub.out === 1;

    // A = 2^0 subInput[0] + 2^1 subInput[1] + ... + 2^255 subInput[255]
    signal A[subLen + 1];
    A[0] <== 0;
    for (var i = 0; i < subLen; i++) {
        A[i+1] <== subInput[i] * (2**i) + A[i];
    }

    signal B[maxMainLen + 1];
    B[0] <== 0;
    for (var i = 0; i < maxMainLen; i++) {
        B[i+1] <== mainInput[i] * (2**i) + B[i];
    }
    
    component eq[maxMainLen - subLen + 1];
    component endCheckers[maxMainLen - subLen + 1];
    signal allowed[maxMainLen - subLen + 2];
    allowed[0] <== 1;
    signal sums[maxMainLen - subLen + 2];
    sums[0] <== 0;
    for (var i = 0; i < maxMainLen - subLen + 1; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== A[subLen] * (2 ** i);
        eq[i].in[1] <== B[i+subLen] - B[i];

        endCheckers[i] = IsEqual();
        endCheckers[i].in[0] <== i;
        endCheckers[i].in[1] <== mainLen - subLen + 1;
        allowed[i+1] <== allowed[i] * (1 - endCheckers[i].out);

        sums[i+1] <== sums[i] + allowed[i+1] * eq[i].out;
    }

    component isz = IsZero();
    isz.in <== sums[maxMainLen - subLen + 1];
    out <== 1 - isz.out;
 }