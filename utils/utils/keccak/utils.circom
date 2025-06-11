// Keccak256 hash function (ethereum version).
// For LICENSE check https://github.com/vocdoni/keccak256-circom/blob/master/LICENSE

pragma circom 2.1.5;

include "./gates.circom";
include "./xor3.circom";
include "./shift.circom"; // contains ShiftRight

template Xor5(n) {
    signal input a[n];
    signal input b[n];
    signal input c[n];
    signal input d[n];
    signal input e[n];
    signal output out[n];
    var i;
    
    component xor3 = Xor3(n);
    for (i=0; i<n; i++) {
        xor3.a[i] <== a[i];
        xor3.b[i] <== b[i];
        xor3.c[i] <== c[i];
    }
    component xor4 = XorArray(n);
    for (i=0; i<n; i++) {
        xor4.a[i] <== xor3.out[i];
        xor4.b[i] <== d[i];
    }
    component xor5 = XorArray(n);
    for (i=0; i<n; i++) {
        xor5.a[i] <== xor4.out[i];
        xor5.b[i] <== e[i];
    }
    for (i=0; i<n; i++) {
        out[i] <== xor5.out[i];
    }
}

template XorArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];
    var i;

    component aux[n];
    for (i=0; i<n; i++) {
        aux[i] = XOR();
        aux[i].a <== a[i];
        aux[i].b <== b[i];
    }
    for (i=0; i<n; i++) {
        out[i] <== aux[i].out;
    }
}

template XorArraySingle(n) {
    signal input a[n];
    signal output out[n];
    var i;

    component aux[n];
    for (i=0; i<n; i++) {
        aux[i] = XOR();
        aux[i].a <== a[i];
        aux[i].b <== 1;
    }
    for (i=0; i<n; i++) {
        out[i] <== aux[i].out;
    }
}

template OrArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];
    var i;

    component aux[n];
    for (i=0; i<n; i++) {
        aux[i] = OR();
        aux[i].a <== a[i];
        aux[i].b <== b[i];
    }
    for (i=0; i<n; i++) {
        out[i] <== aux[i].out;
    }
}

template AndArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];
    var i;

    component aux[n];
    for (i=0; i<n; i++) {
        aux[i] = AND();
        aux[i].a <== a[i];
        aux[i].b <== b[i];
    }
    for (i=0; i<n; i++) {
        out[i] <== aux[i].out;
    }
}

template ShL(n, r) {
    signal input in[n];
    signal output out[n];

    for (var i=0; i<n; i++) {
        if (i < r) {
            out[i] <== 0;
        } else {
            out[i] <== in[ i-r ];
        }
    }
}

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}


template CompConstant(ct) {
    signal input in[254];
    signal output out;

    signal parts[127];
    signal sout;

    var clsb;
    var cmsb;
    var slsb;
    var smsb;

    var sum=0;

    var b = (1 << 128) -1;
    var a = 1;
    var e = 1;
    var i;

    for (i=0;i<127; i++) {
        clsb = (ct >> (i*2)) & 1;
        cmsb = (ct >> (i*2+1)) & 1;
        slsb = in[i*2];
        smsb = in[i*2+1];

        if ((cmsb==0)&&(clsb==0)) {
            parts[i] <== -b*smsb*slsb + b*smsb + b*slsb;
        } else if ((cmsb==0)&&(clsb==1)) {
            parts[i] <== a*smsb*slsb - a*slsb + b*smsb - a*smsb + a;
        } else if ((cmsb==1)&&(clsb==0)) {
            parts[i] <== b*smsb*slsb - a*smsb + a;
        } else {
            parts[i] <== -a*smsb*slsb + a;
        }

        sum = sum + parts[i];

        b = b -e;
        a = a +e;
        e = e*2;
    }

    sout <== sum;

    component num2bits = Num2Bits(135);

    num2bits.in <== sout;

    out <== num2bits.out[127];
}

template AliasCheck() {

    signal input in[254];

    component  compConstant = CompConstant(-1);

    for (var i=0; i<254; i++) in[i] ==> compConstant.in[i];

    compConstant.out === 0;
}

template Num2Bits_strict() {
    signal input in;
    signal output out[254];

    component aliasCheck = AliasCheck();
    component n2b = Num2Bits(254);
    in ==> n2b.in;

    for (var i=0; i<254; i++) {
        n2b.out[i] ==> out[i];
        n2b.out[i] ==> aliasCheck.in[i];
    }
}