// Keccak256 hash function (ethereum version).
// For LICENSE check https://github.com/vocdoni/keccak256-circom/blob/master/LICENSE

pragma circom 2.2.2;

include "../../circomlib/circuits/gates.circom";

// Keyvan: OK
// Example:
// in: [1, 2, 3, 4, 5], n: 3
// out: [4, 5, 0, 0, 0]
template ShR(n, r) {
    signal input in[n];
    signal output out[n];

    for (var i=0; i<n; i++) {
        if (i+r >= n) {
            out[i] <== 0;
        } else {
            out[i] <== in[ i+r ];
        }
    }
}


// Keyvan: OK
// Example:
// in: [1, 2, 3, 4, 5], n: 3
// out: [0, 0, 0, 1, 2]
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

/* Xor3 function for sha256

a ^ b = a + b - 2ab
(a ^ b) ^ c = (a + b - 2ab) + c - 2(a + b - 2ab)c = a + b + c - 2ab - 2ac - 2bc + 4abc

out = a ^ b ^ c  =>

out = a+b+c - 2*a*b - 2*a*c - 2*b*c + 4*a*b*c   =>

out = a*( 1 - 2*b - 2*c + 4*b*c ) + b + c - 2*b*c =>

mid = b*c
out = a*( 1 - 2*b -2*c + 4*mid ) + b + c - 2 * mid
    = a - 2ab - 2ac + 4abc + b + c - 2bc = a + b + c - 2ab - 2ac -2bc + 4abc

*/
// Keyvan: OK
template Xor3(n) {
    signal input a[n];
    signal input b[n];
    signal input c[n];
    signal output out[n];
    signal mid[n];

    for (var k=0; k<n; k++) {
        mid[k] <== b[k]*c[k];
        out[k] <== a[k] * (1 -2*b[k]  -2*c[k] +4*mid[k]) + b[k] + c[k] -2*mid[k];
    }
}

// Keyvan: OK
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
    component xor3_2 = Xor3(n);
    for (i=0; i<n; i++) {
        xor3_2.a[i] <== xor3.out[i];
        xor3_2.b[i] <== d[i];
        xor3_2.c[i] <== e[i];
    }
    for (i=0; i<n; i++) {
        out[i] <== xor3_2.out[i];
    }
}

// Keyvan: OK
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

// Keyvan: OK
template NotArray(n) {
    signal input a[n];
    signal output out[n];
    var i;
    for (i=0; i<n; i++) {
        out[i] <== 1 - a[i];
    }
}

// Keyvan: OK
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

// Keyvan: OK
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