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
    signal input in[25 * 64];
    signal output out[25 * 64];

    signal chunkedIn[25][64];
    for (var i = 0; i < 25; i++) {
        for (var j = 0; j < 64; j++) {
            chunkedIn[i][j] <== in[i * 64 + j];
        }
    }

    signal c0[64] <== Xor5(64)(chunkedIn[0], chunkedIn[5], chunkedIn[10], chunkedIn[15], chunkedIn[20]);
    signal c1[64] <== Xor5(64)(chunkedIn[1], chunkedIn[6], chunkedIn[11], chunkedIn[16], chunkedIn[21]);
    signal c2[64] <== Xor5(64)(chunkedIn[2], chunkedIn[7], chunkedIn[12], chunkedIn[17], chunkedIn[22]);
    signal c3[64] <== Xor5(64)(chunkedIn[3], chunkedIn[8], chunkedIn[13], chunkedIn[18], chunkedIn[23]);
    signal c4[64] <== Xor5(64)(chunkedIn[4], chunkedIn[9], chunkedIn[14], chunkedIn[19], chunkedIn[24]);

    signal d0[64] <== D(64, 1, 64 - 1)(c1, c4); // d = c4 ^ (c1<<1 | c1>>(64 - 1))
    signal r0[64] <== XorArray(64)(chunkedIn[0], d0); // r[0] = a[0] ^ d
    signal r5[64] <== XorArray(64)(chunkedIn[5], d0); // r[5] = a[5] ^ d
    signal r10[64] <== XorArray(64)(chunkedIn[10], d0); // r[10] = a[10] ^ d
    signal r15[64] <== XorArray(64)(chunkedIn[15], d0); // r[15] = a[15] ^ d
    signal r20[64] <== XorArray(64)(chunkedIn[20], d0); // r[20] = a[20] ^ d
    signal d1[64] <== D(64, 1, 64 - 1)(c2, c0); // d = c0 ^ (c2<<1 | c2>>(64 - 1))
    signal r1[64] <== XorArray(64)(chunkedIn[1], d1); // r[1] = a[1] ^ d
    signal r6[64] <== XorArray(64)(chunkedIn[6], d1); // r[6] = a[6] ^ d
    signal r11[64] <== XorArray(64)(chunkedIn[11], d1); // r[11] = a[11] ^ d
    signal r16[64] <== XorArray(64)(chunkedIn[16], d1); // r[16] = a[16] ^ d
    signal r21[64] <== XorArray(64)(chunkedIn[21], d1); // r[21] = a[21] ^ d
    signal d2[64] <== D(64, 1, 64 - 1)(c3, c1); // d = c1 ^ (c3<<1 | c3>>(64 - 1))
    signal r2[64] <== XorArray(64)(chunkedIn[2], d2); // r[2] = a[2] ^ d
    signal r7[64] <== XorArray(64)(chunkedIn[7], d2); // r[7] = a[7] ^ d
    signal r12[64] <== XorArray(64)(chunkedIn[12], d2); // r[12] = a[12] ^ d
    signal r17[64] <== XorArray(64)(chunkedIn[17], d2); // r[17] = a[17] ^ d
    signal r22[64] <== XorArray(64)(chunkedIn[22], d2); // r[22] = a[22] ^ d
    signal d3[64] <== D(64, 1, 64 - 1)(c4, c2); // d = c2 ^ (c4<<1 | c4>>(64 - 1))
    signal r3[64] <== XorArray(64)(chunkedIn[3], d3); // r[3] = a[3] ^ d
    signal r8[64] <== XorArray(64)(chunkedIn[8], d3); // r[8] = a[8] ^ d
    signal r13[64] <== XorArray(64)(chunkedIn[13], d3); // r[13] = a[13] ^ d
    signal r18[64] <== XorArray(64)(chunkedIn[18], d3); // r[18] = a[18] ^ d
    signal r23[64] <== XorArray(64)(chunkedIn[23], d3); // r[23] = a[23] ^ d
    signal d4[64] <== D(64, 1, 64 - 1)(c0, c3); // d = c3 ^ (c0<<1 | c0>>(64 - 1))
    signal r4[64] <== XorArray(64)(chunkedIn[4], d4); // r[4] = a[4] ^ d
    signal r9[64] <== XorArray(64)(chunkedIn[9], d4); // r[9] = a[9] ^ d
    signal r14[64] <== XorArray(64)(chunkedIn[14], d4); // r[14] = a[14] ^ d
    signal r19[64] <== XorArray(64)(chunkedIn[19], d4); // r[19] = a[19] ^ d
    signal r24[64] <== XorArray(64)(chunkedIn[24], d4); // r[24] = a[24] ^ d
    for (var i = 0; i < 64; i++) {
        out[i] <== r0[i];
        out[5 * 64 + i] <== r5[i];
        out[10 * 64 + i] <== r10[i];
        out[15 * 64 + i] <== r15[i];
        out[20 * 64 + i] <== r20[i];
        out[1 * 64 + i] <== r1[i];
        out[6 * 64 + i] <== r6[i];
        out[11 * 64 + i] <== r11[i];
        out[16 * 64 + i] <== r16[i];
        out[21 * 64 + i] <== r21[i];
        out[2 * 64 + i] <== r2[i];
        out[7 * 64 + i] <== r7[i];
        out[12 * 64 + i] <== r12[i];
        out[17 * 64 + i] <== r17[i];
        out[22 * 64 + i] <== r22[i];
        out[3 * 64 + i] <== r3[i];
        out[8 * 64 + i] <== r8[i];
        out[13 * 64 + i] <== r13[i];
        out[18 * 64 + i] <== r18[i];
        out[23 * 64 + i] <== r23[i];
        out[4 * 64 + i] <== r4[i];
        out[9 * 64 + i] <== r9[i];
        out[14 * 64 + i] <== r14[i];
        out[19 * 64 + i] <== r19[i];
        out[24 * 64 + i] <== r24[i];
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
    signal input in[25 * 64];
    signal output out[25 * 64];

    signal chunkedIn[25][64];
    for (var i = 0; i < 25; i++) {
        for (var j = 0; j < 64; j++) {
            chunkedIn[i][j] <== in[i * 64 + j];
        }
    }

    
    signal s10[64] <== stepRhoPi(1, 64 - 1)(chunkedIn[1]); // r[10] = a[1]<<1|a[1]>>(64 - 1)
    signal s7[64] <== stepRhoPi(3, 64 - 3)(chunkedIn[10]); // r[7] = a[10]<<3|a[10]>>(64 - 3)
    signal s11[64] <== stepRhoPi(6, 64 - 6)(chunkedIn[7]); // // r[11] = a[7]<<6|a[7]>>(64 - 6)
    signal s17[64] <== stepRhoPi(10, 64 - 10)(chunkedIn[11]); // r[17] = a[11]<<10|a[11]>>(64 - 10)
    signal s18[64] <== stepRhoPi(15, 64 - 15)(chunkedIn[17]); // r[18] = a[17]<<15|a[17]>>(64 - 15)
    signal s3[64] <== stepRhoPi(21, 64 - 21)(chunkedIn[18]); // r[3] = a[18]<<21|a[18]>>(64 - 21)
    signal s5[64] <== stepRhoPi(28, 64 - 28)(chunkedIn[3]); // r[5] = a[3]<<28|a[3]>>(64 - 28)
    signal s16[64] <== stepRhoPi(36, 64 - 36)(chunkedIn[5]); // r[16] = a[5]<<36|a[5]>>(64 - 36)
    signal s8[64] <== stepRhoPi(45, 64 - 45)(chunkedIn[16]); // r[8] = a[16]<<45|a[16]>>(64 - 45)
    signal s21[64] <== stepRhoPi(55, 64 - 55)(chunkedIn[8]); // r[21] = a[8]<<55|a[8]>>(64 - 55)
    signal s24[64] <== stepRhoPi(2, 64 - 2)(chunkedIn[21]); // r[24] = a[21]<<2|a[21]>>(64 - 2)
    signal s4[64] <== stepRhoPi(14, 64 - 14)(chunkedIn[24]); // r[4] = a[24]<<14|a[24]>>(64 - 14)
    signal s15[64] <== stepRhoPi(27, 64 - 27)(chunkedIn[4]); // r[15] = a[4]<<27|a[4]>>(64 - 27)
    signal s23[64] <== stepRhoPi(41, 64 - 41)(chunkedIn[15]); // r[23] = a[15]<<41|a[15]>>(64 - 41)
    signal s19[64] <== stepRhoPi(56, 64 - 56)(chunkedIn[23]); // r[19] = a[23]<<56|a[23]>>(64 - 56)
    signal s13[64] <== stepRhoPi(8, 64 - 8)(chunkedIn[19]); // r[13] = a[19]<<8|a[19]>>(64 - 8)
    signal s12[64] <== stepRhoPi(25, 64 - 25)(chunkedIn[13]); // r[12] = a[13]<<25|a[13]>>(64 - 25)
    signal s2[64] <== stepRhoPi(43, 64 - 43)(chunkedIn[12]); // r[2] = a[12]<<43|a[12]>>(64 - 43)
    signal s20[64] <== stepRhoPi(62, 64 - 62)(chunkedIn[2]); // r[20] = a[2]<<62|a[2]>>(64 - 62)
    signal s14[64] <== stepRhoPi(18, 64 - 18)(chunkedIn[20]); // r[14] = a[20]<<18|a[20]>>(64 - 18)
    signal s22[64] <== stepRhoPi(39, 64 - 39)(chunkedIn[14]); // r[22] = a[14]<<39|a[14]>>(64 - 39)
    signal s9[64] <== stepRhoPi(61, 64 - 61)(chunkedIn[22]); // r[9] = a[22]<<61|a[22]>>(64 - 61)
    signal s6[64] <== stepRhoPi(20, 64 - 20)(chunkedIn[9]); // r[6] = a[9]<<20|a[9]>>(64 - 20)
    signal s1[64] <== stepRhoPi(44, 64 - 44)(chunkedIn[6]); // r[1] = a[6]<<44|a[6]>>(64 - 44)

    for (var i = 0; i < 64; i++) {
        out[i] <== in[i];
        out[10 * 64 + i] <== s10[i];
        out[7 * 64 + i] <== s7[i];
        out[11 * 64 + i] <== s11[i];
        out[17 * 64 + i] <== s17[i];
        out[18 * 64 + i] <== s18[i];
        out[3 * 64 + i] <== s3[i];
        out[5 * 64 + i] <== s5[i];
        out[16 * 64 + i] <== s16[i];
        out[8 * 64 + i] <== s8[i];
        out[21 * 64 + i] <== s21[i];
        out[24 * 64 + i] <== s24[i];
        out[4 * 64 + i] <== s4[i];
        out[15 * 64 + i] <== s15[i];
        out[23 * 64 + i] <== s23[i];
        out[19 * 64 + i] <== s19[i];
        out[13 * 64 + i] <== s13[i];
        out[12 * 64 + i] <== s12[i];
        out[2 * 64 + i] <== s2[i];
        out[20 * 64 + i] <== s20[i];
        out[14 * 64 + i] <== s14[i];
        out[22 * 64 + i] <== s22[i];
        out[9 * 64 + i] <== s9[i];
        out[6 * 64 + i] <== s6[i];
        out[1 * 64 + i] <== s1[i];
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
    signal input in[25 * 64];
    signal output out[25 * 64];

    signal chunkedIn[25][64];
    for (var i = 0; i < 25; i++) {
        for (var j = 0; j < 64; j++) {
            chunkedIn[i][j] <== in[i * 64 + j];
        }
    }

    signal r0[64] <== stepChi()(chunkedIn[0], chunkedIn[1], chunkedIn[2]);
    signal r1[64] <== stepChi()(chunkedIn[1], chunkedIn[2], chunkedIn[3]);
    signal r2[64] <== stepChi()(chunkedIn[2], chunkedIn[3], chunkedIn[4]);
    signal r3[64] <== stepChi()(chunkedIn[3], chunkedIn[4], chunkedIn[0]);
    signal r4[64] <== stepChi()(chunkedIn[4], chunkedIn[0], chunkedIn[1]);
    signal r5[64] <== stepChi()(chunkedIn[5], chunkedIn[6], chunkedIn[7]);
    signal r6[64] <== stepChi()(chunkedIn[6], chunkedIn[7], chunkedIn[8]);
    signal r7[64] <== stepChi()(chunkedIn[7], chunkedIn[8], chunkedIn[9]);
    signal r8[64] <== stepChi()(chunkedIn[8], chunkedIn[9], chunkedIn[5]);
    signal r9[64] <== stepChi()(chunkedIn[9], chunkedIn[5], chunkedIn[6]);
    signal r10[64] <== stepChi()(chunkedIn[10], chunkedIn[11], chunkedIn[12]);
    signal r11[64] <== stepChi()(chunkedIn[11], chunkedIn[12], chunkedIn[13]);
    signal r12[64] <== stepChi()(chunkedIn[12], chunkedIn[13], chunkedIn[14]);
    signal r13[64] <== stepChi()(chunkedIn[13], chunkedIn[14], chunkedIn[10]);
    signal r14[64] <== stepChi()(chunkedIn[14], chunkedIn[10], chunkedIn[11]);
    signal r15[64] <== stepChi()(chunkedIn[15], chunkedIn[16], chunkedIn[17]);
    signal r16[64] <== stepChi()(chunkedIn[16], chunkedIn[17], chunkedIn[18]);
    signal r17[64] <== stepChi()(chunkedIn[17], chunkedIn[18], chunkedIn[19]);
    signal r18[64] <== stepChi()(chunkedIn[18], chunkedIn[19], chunkedIn[15]);
    signal r19[64] <== stepChi()(chunkedIn[19], chunkedIn[15], chunkedIn[16]);
    signal r20[64] <== stepChi()(chunkedIn[20], chunkedIn[21], chunkedIn[22]);
    signal r21[64] <== stepChi()(chunkedIn[21], chunkedIn[22], chunkedIn[23]);
    signal r22[64] <== stepChi()(chunkedIn[22], chunkedIn[23], chunkedIn[24]);
    signal r23[64] <== stepChi()(chunkedIn[23], chunkedIn[24], chunkedIn[20]);
    signal r24[64] <== stepChi()(chunkedIn[24], chunkedIn[20], chunkedIn[21]);

    for (var i = 0; i < 64; i++) {
        out[i] <== r0[i];
        out[1 * 64 + i] <== r1[i];
        out[2 * 64 + i] <== r2[i];
        out[3 * 64 + i] <== r3[i];
        out[4 * 64 + i] <== r4[i];
        out[5 * 64 + i] <== r5[i];
        out[6 * 64 + i] <== r6[i];
        out[7 * 64 + i] <== r7[i];
        out[8 * 64 + i] <== r8[i];
        out[9 * 64 + i] <== r9[i];
        out[10 * 64 + i] <== r10[i];
        out[11 * 64 + i] <== r11[i];
        out[12 * 64 + i] <== r12[i];
        out[13 * 64 + i] <== r13[i];
        out[14 * 64 + i] <== r14[i];
        out[15 * 64 + i] <== r15[i];
        out[16 * 64 + i] <== r16[i];
        out[17 * 64 + i] <== r17[i];
        out[18 * 64 + i] <== r18[i];
        out[19 * 64 + i] <== r19[i];
        out[20 * 64 + i] <== r20[i];
        out[21 * 64 + i] <== r21[i];
        out[22 * 64 + i] <== r22[i];
        out[23 * 64 + i] <== r23[i];
        out[24 * 64 + i] <== r24[i];
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
    signal input in[25 * 64];
    signal output out[25 * 64];

    component rc = RC(r);

    component iota = XorArray(64);
    for (var i = 0; i < 64; i++) {
        iota.a[i] <== in[i];
        iota.b[i] <== rc.out[i];
    }
    for (var i = 0; i < 64; i++) {
        out[i] <== iota.out[i];
    }
    for (var i = 64; i < 25 * 64; i++) {
        out[i] <== in[i];
    }
}
