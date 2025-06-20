// Keccak256 hash function (ethereum version).
// For LICENSE check https://github.com/vocdoni/keccak256-circom/blob/master/LICENSE

pragma circom 2.2.2;

include "../../circomlib/circuits/gates.circom";
include "./utils.circom";

template Pick(N, C) {
    signal input in[N];
    signal output out[C];
    for(var i = 0; i < C; i++) {
        out[i] <== in[i];
    }
}

// Theta

template D(n, shl, shr) {
    // d = b ^ (a<<shl | a>>shr)
    signal input a[n];
    signal input b[n];
    signal output out[n];

    signal a64[64] <== Pick(n, 64)(a);
    signal b64[64] <== Pick(n, 64)(b);
    signal aux0[64] <== ShR(64, shr)(a);
    signal aux1[64] <== ShL(64, shl)(a);
    signal aux2[64] <== OrArray(64)(aux0, aux1);
    out <== XorArray(64)(b, aux2);
}

template Theta() {
    signal input in[25][64];
    signal output out[25][64];

    signal c[5][64];
    for(var i = 0; i < 5; i++) {
        c[i] <== Xor5(64)(in[i], in[5 + i], in[10 + i], in[15 + i], in[20 + i]);
    }

    signal d[5][64];
    for(var i = 0; i < 5; i++) {
        d[i] <== D(64, 1, 64 - 1)(c[(i + 1) % 5], c[(i + 4) % 5]);
    }

    for(var i = 0; i < 5; i++) {
        for(var j = 0; j < 5; j++) {
            out[i + j * 5] <== XorArray(64)(in[i + j * 5], d[i]);
        }
    }
}

// RhoPi

template stepRhoPi(shl, shr) {
    // out = a<<shl|a>>shr
    signal input a[64];
    signal output out[64];

    signal aux0[64] <== ShR(64, shr)(a);
    signal aux1[64] <== ShL(64, shl)(a);
    out <== OrArray(64)(aux0, aux1);
}
template RhoPi() {
    signal input in[25][64];
    signal output out[25][64];

    var rot[25] = [1, 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

    out[0] <== in[0];
    for(var i = 0; i < 24; i++) {
        var shl = ((i + 1) * (i + 2) \ 2) % 64;
        out[rot[i + 1]] <== stepRhoPi(shl, 64 - shl)(in[rot[i]]);
    }
}


// Chi

template stepChi() {
    // out = a ^ (^b) & c
    signal input a[64];
    signal input b[64];
    signal input c[64];
    signal output out[64];

    // ^b
    signal bXor[64] <== NotArray(64)(b);
    // (^b)&c
    signal bc[64] <== AndArray(64)(bXor, c);
    // a^(^b)&c
    out <== XorArray(64)(a, bc);
}

template Chi() {
    signal input in[25][64];
    signal output out[25][64];

    for(var i = 0; i < 25; i++) {
        if(i % 5 == 3) {
            out[i] <== stepChi()(in[i], in[i + 1], in[i - 3]);
        } else if(i % 5 == 4) {
            out[i] <== stepChi()(in[i], in[i - 4], in[i - 3]);
        } else {
            out[i] <== stepChi()(in[i], in[i + 1], in[i + 2]);
        }
    }
}

// Iota

template RC(r) {
    signal output out[64];
    var rc[24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ];
    for (var i = 0; i < 64; i++) {
        out[i] <== (rc[r] >> i) & 1;
    }
}

template Iota(r) {
    signal input in[25][64];
    signal output out[25][64];

    component rc = RC(r);

    out[0] <== XorArray(64)(in[0], rc.out);
    for (var i = 1; i < 25; i++) {
        out[i] <== in[i];
    }
}
