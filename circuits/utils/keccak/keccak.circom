// Keccak256 hash function (ethereum version).
// For LICENSE check https://github.com/vocdoni/keccak256-circom/blob/master/LICENSE

pragma circom 2.2.2;

include "./utils.circom";
include "../selector.circom";
include "./permutations.circom";

template KeccakfRound(r) {
    signal input in[25 * 64];
    signal output out[25 * 64];
    signal theta[25 * 64] <== Theta()(in);
    signal rhopi[25 * 64] <== RhoPi()(theta);
    signal chi[25 * 64] <== Chi()(rhopi);
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
            newS.in[i * 64 + j] <== aux[i].out[j];
        }
    }
    // fill the missing s that was not covered by the loop over
    // blockSizeBytes/8
    for (var i=(blockSizeBytes / 8) * 64; i < 25 * 64; i++) {
        newS.in[i] <== s[i];
    }
    for (var i = 0; i < 25 * 64; i++) {
        out[i] <== newS.out[i];
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
    signal input in[25 * 64];
    signal output out[25 * 64];

    // 24 rounds
    component round[24];
    signal midRound[24*25*64];
    for (var i = 0; i < 24; i++) {
        round[i] = KeccakfRound(i);
        if (i==0) {
            for (var j = 0; j < 25 * 64; j++) {
                midRound[j] <== in[j];
            }
        }
        for (var j = 0; j < 25 * 64; j++) {
            round[i].in[j] <== midRound[i * 25 * 64 + j];
        }
        if (i < 23) {
            for (var j = 0; j < 25 * 64; j++) {
                midRound[(i + 1) * 25 * 64 + j] <== round[i].out[j];
            }
        }
    }

    for (var i = 0; i < 25 * 64; i++) {
        out[i] <== round[23].out[i];
    }
}

template Keccak(nBlocksIn) {
    signal input in[nBlocksIn * 136 * 8];
    signal input blocks;
    signal output out[32 * 8];
    var i;

    component f = Final(nBlocksIn);
    f.blocks <== blocks;
    for (i=0; i<nBlocksIn * 136 * 8; i++) {
        f.in[i] <== in[i];
    }
    component squeeze = Squeeze(32 * 8);
    for (i=0; i<25*64; i++) {
        squeeze.s[i] <== f.out[i];
    }
    for (i=0; i<32 * 8; i++) {
        out[i] <== squeeze.out[i];
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
    out <== Keccak(maxBlocks)(padded, numBlocks);
}