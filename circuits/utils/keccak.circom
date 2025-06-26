// Keccak256 hash function (ethereum version).
// For LICENSE check https://github.com/vocdoni/keccak256-circom/blob/master/LICENSE

pragma circom 2.2.2;

include "../circomlib/circuits/gates.circom";
include "selector.circom";

// Example:
//   in: [1, 2, 3, 4, 5], n: 3
//   out: [4, 5, 0, 0, 0]
//
// Reviewers:
//   Keyvan: OK
//
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


// Example:
// in: [1, 2, 3, 4, 5], n: 3
// out: [0, 0, 0, 1, 2]
//
// Reviewers:
//   Keyvan: OK
//
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

// Xor3 function for sha256
// Proof:
//   a ^ b = a + b - 2ab
//   (a ^ b) ^ c = (a + b - 2ab) + c - 2(a + b - 2ab)c = a + b + c - 2ab - 2ac - 2bc + 4abc
//   out = a ^ b ^ c  =>
//   out = a+b+c - 2*a*b - 2*a*c - 2*b*c + 4*a*b*c   =>
//   out = a*( 1 - 2*b - 2*c + 4*b*c ) + b + c - 2*b*c =>
//   mid = b*c
//   out = a*( 1 - 2*b -2*c + 4*mid ) + b + c - 2 * mid
//       = a - 2ab - 2ac + 4abc + b + c - 2bc = a + b + c - 2ab - 2ac -2bc + 4abc
//
// Reviewers:
//   Keyvan: OK
//
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

// Xor5 using two Xor3s
//
// Reviewers:
//   Keyvan: OK
//
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

// Array of XORs
//
// Reviewers:
//   Keyvan: OK
//
template XorArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== XOR()(a[i], b[i]);
    }
}

// Array of NOTs
//
// Reviewers:
//   Keyvan: OK
//
template NotArray(n) {
    signal input a[n];
    signal output out[n];
    for (var i = 0; i < n; i++) {
        out[i] <== NOT()(a[i]);
    }
}

// Array of ORs
//
// Reviewers:
//   Keyvan: OK
//
template OrArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== OR()(a[i], b[i]);
    }
}

// Array of ANDs
//
// Reviewers:
//   Keyvan: OK
//
template AndArray(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== AND()(a[i], b[i]);
    }
}

// Pick first C elements of a N element array
//
// Reviewers:
//   Keyvan: OK
//
template Pick(N, C) {
    assert(C <= N);
    signal input in[N];
    signal output out[C];
    for(var i = 0; i < C; i++) {
        out[i] <== in[i];
    }
}

// d = b[0..64] ^ (a[:64]<<shl | a[0..64]>>shr)
//
// Reviewers:
//   Keyvan: OK
//
template D(n, shl, shr) {
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

// Theta
//
// Reviewers:
//   Keyvan: OK
//
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

// out = a<<shl|a>>shr
//
// Reviewers:
//   Keyvan: OK
//
template stepRhoPi(shl, shr) {
    signal input a[64];
    signal output out[64];

    signal aux0[64] <== ShR(64, shr)(a);
    signal aux1[64] <== ShL(64, shl)(a);
    out <== OrArray(64)(aux0, aux1);
}

// RhoPi
//
// Reviewers:
//   Keyvan: OK
//
template RhoPi() {
    signal input in[25][64];
    signal output out[25][64];

    var rot[25] = [1, 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

    out[0] <== in[0];
    for(var i = 0; i < 24; i++) {
        // 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, ...
        var shl = ((i + 1) * (i + 2) \ 2) % 64;

        out[rot[i + 1]] <== stepRhoPi(shl, 64 - shl)(in[rot[i]]);
    }
}


// out = a ^ (^b) & c
//
// Reviewers:
//   Keyvan: OK
//
template stepChi() {
    signal input a[64];
    signal input b[64];
    signal input c[64];
    signal output out[64];

    signal bXor[64] <== NotArray(64)(b); // ^b
    signal bc[64] <== AndArray(64)(bXor, c); // (^b)&c
    out <== XorArray(64)(a, bc); // a^(^b)&c
}

// Chi
//
// Reviewers:
//   Keyvan: OK
//
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

// RC constants
//
// Reviewers:
//   Keyvan: OK
//
template RC(r) {
    signal output out[64];

    assert(r < 24);
    // 24 * (8 byte = 64-bit) numbers
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

// Iota
//
// Reviewers:
//   Keyvan: OK
//
template Iota(r) {
    signal input in[25][64];
    signal output out[25][64];

    component rc = RC(r);

    out[0] <== XorArray(64)(in[0], rc.out);
    for (var i = 1; i < 25; i++) {
        out[i] <== in[i];
    }
}

// Apply Theta -> Rhopi -> Chi -> Iota
//
// Reviewers:
//   Keyvan: OK
//
template KeccakfRound(r) {
    signal input in[25][64];
    signal output out[25][64];
    signal theta[25][64] <== Theta()(in);
    signal rhopi[25][64] <== RhoPi()(theta);
    signal chi[25][64] <== Chi()(rhopi);
    out <== Iota(r)(chi);
}

// Absorb phase
//
// Reviewers:
//   Keyvan: OK
//
template Absorb() {
    var blockSizeBytes = 136;
    var blockSize64BitChunks = blockSizeBytes / 8; // 17

    signal input s[25][64];
    signal input block[blockSize64BitChunks][64];
    signal output out[25][64];

    signal aux[25][64];

    for (var i = 0; i < 25; i++) {
        if(i < blockSize64BitChunks) {
            aux[i] <== XorArray(64)(s[i], block[i]);
        } else {
            aux[i] <== s[i];
        }
    }
    out <== Keccakf()(aux);
}

// Final phase
//
// Reviewers:
//   Keyvan: OK
//
template Final(nBlocksIn) {
    signal input in[nBlocksIn][17][64];
    signal input blocks;
    signal output out[25][64];
    var blockSize = 136 * 8;

    signal s[nBlocksIn + 1][25][64];
    for(var i = 0; i < 25; i++) {
        for(var j = 0; j < 64; j++) {
            s[0][i][j] <== 0;
        }
    }
    
    for (var b = 0; b < nBlocksIn; b++) {
        s[b + 1] <== Absorb()(s[b], in[b]);
    }

    out <== Array2DSelector(nBlocksIn + 1, 25, 64)(s, blocks);
}

// Apply 24 rounds of KeccakfRound
//
// Reviewers:
//   Keyvan: OK
//
template Keccakf() {
    signal input in[25][64];
    signal output out[25][64];

    signal midRound[25][25][64];
    midRound[0] <== in;
    for (var i = 0; i < 24; i++) {
        midRound[i + 1] <== KeccakfRound(i)(midRound[i]);
    }

    out <== midRound[24];
}

// Keccak of prepared input
//
// Reviewers:
//   Keyvan: OK
//
template Keccak(nBlocksIn) {
    signal input in[nBlocksIn][17][64];
    signal input blocks;
    signal output out[32 * 8];

    signal finalState[25][64] <== Final(nBlocksIn)(in, blocks);

    // Squeeze
    for(var i = 0; i < 32 * 8; i++) {
        out[i] <== finalState[i \ 64][i % 64];
    }
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

    signal paddedBlocks[maxBlocks][17][64];
    for(var i = 0; i < maxBlocks; i++) {
        for(var j = 0; j < 17; j++) {
            for(var k = 0; k < 64; k++) {
                paddedBlocks[i][j][k] <== padded[i * 17 * 64 + j * 64 + k];
            }
        }
    }

    out <== Keccak(maxBlocks)(paddedBlocks, numBlocks);
}