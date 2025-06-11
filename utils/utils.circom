
pragma circom 2.1.5;

template Divide(N) {
    signal input a;
    signal input b;
    signal output out;
    signal output rem;

    out <-- a \ b;
    rem <-- a % b;
    component lessThan = LessThan(N);
    lessThan.in[0] <== rem;
    lessThan.in[1] <== b;
    lessThan.out === 1;
    out * b + rem === a;
}

template ByteDecompose(N) { 
    signal input num;
    signal output bytes[N];
    var pow = 1;
    var total = 0;
    component bd[N];
    for (var i = 0; i < N; i++) {
        bytes[i] <-- (num >> (8 * i)) & 0xFF;
        total += pow * bytes[i];
        pow = pow * 256; 
    }

    total === num; 
}

template GetRealByteLength(N) {
    signal input bytes[N];
    signal output len;

    component isZero[N];

    signal isZeroResult[N+1];
    isZeroResult[0] <== 1;

    for (var i = 0; i < N; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== bytes[N-i-1];
        isZeroResult[i+1] <== isZero[i].out * isZeroResult[i];
    }
    
    var total = 0;
    
    for (var j = 1; j < N + 1; j++) {
        total = total + isZeroResult[j];
    }

    len <== N - total;
}

template IfThenElse() {
    signal input condition; 
    signal input ifTrue;
    signal input ifFalse;
    signal output out;


    signal intermediateTrue;
    signal intermediateFalse;

    intermediateTrue <== condition * ifTrue;
    intermediateFalse <== (1 - condition) * ifFalse;

    out <== intermediateTrue + intermediateFalse;
}

template Bits2NumBigendian(n) {
    signal input in[n];
    signal output out;
    var number = 0;
    var step1 = 1;

    for (var i = n / 8 - 1; i >= 0; i--) {
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

template ShiftLeft(n) {
    signal input in[n];
    signal input count;
    signal output out[n];

    signal outsum[n][n+1];
    for(var i = 0; i < n; i++) {
        outsum[i][0] <== 0;
    }
    component eqs[n][n];
    for(var i = 0; i < n; i++) {
        for(var j = 0; j < n; j++) {
            eqs[i][j] = IsEqual();
            eqs[i][j].in[0] <== i;
            eqs[i][j].in[1] <== j - count;
            outsum[i][j+1] <== outsum[i][j] + eqs[i][j].out * in[j];
        }
        out[i] <== outsum[i][n];
    }
}

template TermCalc(N) {
    signal input address[N];
    signal input count;
    signal output out[N+2];
    signal output outLen;

    component div = Divide(16);
    div.a <== count;
    div.b <== 2;

    component shifted = ShiftLeft(N);
    shifted.in <== address;
    shifted.count <== count;
    signal temp[N - 1];
    for(var i = 0; i < N; i++) {
        if(i == N - 1) {
            out[i+2] <== (1 - div.rem) * shifted.out[i];
        } else {
            temp[i] <== div.rem * shifted.out[i+1];
            out[i+2] <== (1 - div.rem) * shifted.out[i] + temp[i];
        }
    }
    out[0] <== 2 + div.rem;
    out[1] <== div.rem * shifted.out[0];
    outLen <== N + 2 - count - div.rem;
}