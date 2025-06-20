// Keccak256 hash function (ethereum version).
// For LICENSE check https://github.com/vocdoni/keccak256-circom/blob/master/LICENSE

pragma circom 2.2.2;

include "../circomlib/circuits/gates.circom";
include "selector.circom";

// Keyvan: OK
// Example:
// in: [1, 2, 3, 4, 5], n: 3
// out: [4, 5, 0, 0, 0]
template ShR(n, r) {
    signal input in[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        if (i + r >= n) {
            out[i] <== 0;
        } else {
            out[i] <== in[i + r];
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

    for (var i = 0; i < n; i++) {
        if (i < r) {
            out[i] <== 0;
        } else {
            out[i] <== in[i - r];
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

    for (var k = 0; k < n; k++) {
        mid[k] <== b[k] * c[k];
        out[k] <== a[k] * (1 - 2 * b[k] - 2 * c[k] + 4 * mid[k]) + b[k] + c[k] - 2 * mid[k];
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
    
    signal xor_abc[n] <== Xor3(n)(a, b, c);
    out <== Xor3(n)(xor_abc, d, e);
}

// Keyvan: OK
template XorArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== XOR()(a[i], b[i]);
    }
}

// Keyvan: OK
template NotArray(n) {
    signal input a[n];
    signal output out[n];
    for (var i = 0; i < n; i++) {
        out[i] <== NOT()(a[i]);
    }
}

// Keyvan: OK
template OrArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== OR()(a[i], b[i]);
    }
}

// Keyvan: OK
template AndArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== AND()(a[i], b[i]);
    }
}

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

template KeccakfRound(r) {
    signal input in[25][64];
    signal output out[25][64];
    signal theta[25][64] <== Theta()(in);
    signal rhopi[25][64] <== RhoPi()(theta);
    signal chi[25][64] <== Chi()(rhopi);
    out <== Iota(r)(chi);
}

template Absorb() {
    var blockSizeBytes = 136;

    signal input s[25 * 64];
    signal input block[blockSizeBytes * 8];
    signal output out[25 * 64];

    component aux[blockSizeBytes / 8];
    component newS = Keccakf();

    for (var i = 0; i < blockSizeBytes / 8; i++) {
        aux[i] = XorArray(64);
        for (var j = 0; j < 64; j++) {
            aux[i].a[j] <== s[i * 64 + j];
            aux[i].b[j] <== block[i * 64 + j];
        }
        for (var j = 0; j < 64; j++) {
            newS.in[i][j] <== aux[i].out[j];
        }
    }
    // fill the missing s that was not covered by the loop over
    // blockSizeBytes/8
    for (var i=(blockSizeBytes / 8); i < 25; i++) {
        for(var j = 0; j < 64; j++) {
            newS.in[i][j] <== s[i * 64 + j];
        }
    }
    for (var i = 0; i < 25; i++) {
        for(var j = 0; j < 64; j++) {
            out[i * 64 + j] <== newS.out[i][j];
        }
    }
}

template Final(nBlocksIn) {
    signal input in[nBlocksIn * 136 * 8];
    signal input blocks;
    signal output out[25 * 64];
    var blockSize = 136 * 8;

    component abs[nBlocksIn];

    for (var b = 0; b < nBlocksIn; b++) {
        abs[b] = Absorb();
        if (b == 0) {
            for (var i = 0; i < 25 * 64; i++) {
                abs[b].s[i] <== 0;
            }
        } else {
            for (var i = 0; i < 25 * 64; i++) {
                abs[b].s[i] <== abs[b - 1].out[i];
            }
        }
        for (var i = 0; i < blockSize; i++) {
            abs[b].block[i] <== in[b * 136 * 8 + i];
        }
    }

    component selectors[25 * 64];

    for (var i = 0; i < 25 * 64; i++) {
        selectors[i] = Selector(nBlocksIn);
        selectors[i].select <== blocks - 1;
        for(var j = 0; j < nBlocksIn; j++) {
            selectors[i].vals[j] <== abs[j].out[i];
        }
        out[i] <== selectors[i].out;
    }
}

template Squeeze(nBits) {
    signal input s[25 * 64];
    signal output out[nBits];

    for (var i = 0; i < 25; i++) {
        for (var j = 0; j < 64; j++) {
            if (i * 64 + j < nBits) {
                out[i * 64 + j] <== s[i * 64 + j];
            }
        }
    }
}

template Keccakf() {
    signal input in[25][64];
    signal output out[25][64];

    // 24 rounds
    component round[24];
    signal midRound[24][25][64];
    for (var i = 0; i < 24; i++) {
        round[i] = KeccakfRound(i);
        if (i == 0) {
            midRound[0] <== in;
        }
        round[i].in <== midRound[i];
        if (i < 23) {
            midRound[i + 1] <== round[i].out;
        }
    }

    out <== round[23].out;
}

template Keccak(nBlocksIn) {
    signal input in[nBlocksIn * 136 * 8];
    signal input blocks;
    signal output out[32 * 8];

    signal fin[25 * 64] <== Final(nBlocksIn)(in, blocks);
    out <== Squeeze(32 * 8)(fin);
}


template BitPad(maxBlocks, blockSize) {
    var maxBits = maxBlocks * blockSize;
    signal input in[maxBits];
    signal input ind;

    signal output out[maxBits];
    signal output numBlocks;

    signal (div, rem) <== Divide(16)(ind + 1, blockSize);
    numBlocks <== div + 1;

    AssertLessThan(16)(div, maxBlocks);

    signal eqs[maxBits + 1];
    eqs[0] <== 1;
    signal eqcomps[maxBits];
    for(var i = 0; i < maxBits; i++) {
        eqcomps[i] <== IsEqual()([i, ind]);
        eqs[i + 1] <== eqs[i] * (1 - eqcomps[i]);
    }

    signal isLast[maxBits];
    for(var i = 0; i < maxBits; i++) {
        isLast[i] <== IsEqual()([i, numBlocks * blockSize - 1]);
        out[i] <== in[i] * eqs[i + 1] + eqcomps[i] + isLast[i];
    }
}


template KeccakBits(maxBlocks) {
    signal input inBits[maxBlocks * 136 * 8];
    signal input inBitsLen;
    signal output out[256];

    // Make sure inBitsLen is divisible by 8.
    signal rem;
    (_, rem) <== Divide(16)(inBitsLen, 8);
    rem === 0;

    // Give some space for padding
    AssertLessEqThan(16)(inBitsLen, maxBlocks * 136 * 8 - 8);

    signal (
        padded[maxBlocks * 136 * 8], numBlocks
    ) <== BitPad(maxBlocks, 136 * 8)(inBits, inBitsLen);
    out <== Keccak(maxBlocks)(padded, numBlocks);
}