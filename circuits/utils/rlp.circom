pragma circom 2.2.2;

include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/mux1.circom";
include "./utils.circom";
include "./concat.circom";

// Decomposes an input number `num` into an array of `N` bytes.
// Each byte represents 8 bits of the number starting from the least significant byte.
//
// Example:
//   num:   66051
//   N:     8
//   bytes: [3, 2, 1, 0, 0, 0, 0, 0]
template ByteDecompose(N) { 
    signal input num;
    signal output bytes[N];
    var pow = 1;
    var total = 0;
    component byteCheckers[N];
    for (var i = 0; i < N; i++) {
        bytes[i] <-- (num >> (8 * i)) & 0xFF;
        total += pow * bytes[i];
        pow = pow * 256; 

        // Make sure the bytes[i] is actually a byte
        byteCheckers[i] = Num2Bits(8);
        byteCheckers[i].in <== bytes[i];
    }

    total === num; 
}

// Counts the number of bytes required to store the number (i.e., ignores trailing zeros).
//
// Example:
//   bytes: [3, 0, 1, 4, 2, 0, 0, 0]
//   len:   5
template CountBytes(N) {
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


// Reverses the first `inLen` elements of the input array `in`
// Elements beyond `inLen` are zero-padded.
//
// Example:
//   in:    [1, 2, 3, 4, 5], inLen: 3
//   output:[3, 2, 1, 0, 0]
template ReverseArray(N) {
    signal input in[N];
    signal input inLen;
    signal output out[N];

    AssertLessEqThan(16)(inLen, N);

    var lenDiff = N - inLen;
    signal reversed[N];

    component shifter = Shift(N, N);
    shifter.count <== lenDiff;
    shifter.in <== in; 

   for(var i = 0; i < N; i++) {
        reversed[i] <== shifter.out[N - i - 1];
    }

    out <== reversed;
}

template RlpInteger(N) {
    signal input num;
    signal output out[N];
    signal output outLen;

    component decomp = ByteDecompose(N);
    decomp.num <== num;

    component length = CountBytes(N);
    length.bytes <== decomp.bytes;

    component reversed = ReverseArray(N);
    reversed.in <== decomp.bytes;
    reversed.inLen <== length.len;

    component isSingleByte = LessThan(128);
    isSingleByte.in[0] <== num;
    isSingleByte.in[1] <== 128;

    component isZero = IsZero();
    isZero.in <== num;

    outLen <== (1 - isSingleByte.out) + length.len + isZero.out;

    component firstRlpByteSelector = Mux1();
    firstRlpByteSelector.c[0] <== 0x80 + length.len;
    firstRlpByteSelector.c[1] <== num;
    firstRlpByteSelector.s <== isSingleByte.out;

    out[0] <== firstRlpByteSelector.out + isZero.out * 0x80;
    for (var i = 1; i < N; i++) {
        out[i] <== (1 - isSingleByte.out) * reversed.out[i-1];
    }
}

template RlpEmptyAccount() {
    signal input balance;
    signal output out[88];
    signal output outLen;

    signal nonceAndBalanceRlp[22];
    signal nonceAndBalanceRlpLen;
    nonceAndBalanceRlp[0] <== 0x80; // Nonce of a burn-address is always zero
    component balanceRlp = RlpInteger(21);
    balanceRlp.num <== balance;
    for(var i = 0; i < 21; i++) {
        nonceAndBalanceRlp[i + 1] <== balanceRlp.out[i];
    }
    nonceAndBalanceRlpLen <== balanceRlp.outLen + 1;

    // Concatenated RLP of storage-hash and code-hash of an empty account
    // Storage-hash: 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
    // Code-hash:    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 
    var storageAndCodeHashRlpLen = 66;
    signal storageAndCodeHashRlp[storageAndCodeHashRlpLen];
    storageAndCodeHashRlp[0] <== 160;
    storageAndCodeHashRlp[1] <== 86;
    storageAndCodeHashRlp[2] <== 232;
    storageAndCodeHashRlp[3] <== 31;
    storageAndCodeHashRlp[4] <== 23;
    storageAndCodeHashRlp[5] <== 27;
    storageAndCodeHashRlp[6] <== 204;
    storageAndCodeHashRlp[7] <== 85;
    storageAndCodeHashRlp[8] <== 166;
    storageAndCodeHashRlp[9] <== 255;
    storageAndCodeHashRlp[10] <== 131;
    storageAndCodeHashRlp[11] <== 69;
    storageAndCodeHashRlp[12] <== 230;
    storageAndCodeHashRlp[13] <== 146;
    storageAndCodeHashRlp[14] <== 192;
    storageAndCodeHashRlp[15] <== 248;
    storageAndCodeHashRlp[16] <== 110;
    storageAndCodeHashRlp[17] <== 91;
    storageAndCodeHashRlp[18] <== 72;
    storageAndCodeHashRlp[19] <== 224;
    storageAndCodeHashRlp[20] <== 27;
    storageAndCodeHashRlp[21] <== 153;
    storageAndCodeHashRlp[22] <== 108;
    storageAndCodeHashRlp[23] <== 173;
    storageAndCodeHashRlp[24] <== 192;
    storageAndCodeHashRlp[25] <== 1;
    storageAndCodeHashRlp[26] <== 98;
    storageAndCodeHashRlp[27] <== 47;
    storageAndCodeHashRlp[28] <== 181;
    storageAndCodeHashRlp[29] <== 227;
    storageAndCodeHashRlp[30] <== 99;
    storageAndCodeHashRlp[31] <== 180;
    storageAndCodeHashRlp[32] <== 33;
    storageAndCodeHashRlp[33] <== 160;
    storageAndCodeHashRlp[34] <== 197;
    storageAndCodeHashRlp[35] <== 210;
    storageAndCodeHashRlp[36] <== 70;
    storageAndCodeHashRlp[37] <== 1;
    storageAndCodeHashRlp[38] <== 134;
    storageAndCodeHashRlp[39] <== 247;
    storageAndCodeHashRlp[40] <== 35;
    storageAndCodeHashRlp[41] <== 60;
    storageAndCodeHashRlp[42] <== 146;
    storageAndCodeHashRlp[43] <== 126;
    storageAndCodeHashRlp[44] <== 125;
    storageAndCodeHashRlp[45] <== 178;
    storageAndCodeHashRlp[46] <== 220;
    storageAndCodeHashRlp[47] <== 199;
    storageAndCodeHashRlp[48] <== 3;
    storageAndCodeHashRlp[49] <== 192;
    storageAndCodeHashRlp[50] <== 229;
    storageAndCodeHashRlp[51] <== 0;
    storageAndCodeHashRlp[52] <== 182;
    storageAndCodeHashRlp[53] <== 83;
    storageAndCodeHashRlp[54] <== 202;
    storageAndCodeHashRlp[55] <== 130;
    storageAndCodeHashRlp[56] <== 39;
    storageAndCodeHashRlp[57] <== 59;
    storageAndCodeHashRlp[58] <== 123;
    storageAndCodeHashRlp[59] <== 250;
    storageAndCodeHashRlp[60] <== 216;
    storageAndCodeHashRlp[61] <== 4;
    storageAndCodeHashRlp[62] <== 93;
    storageAndCodeHashRlp[63] <== 133;
    storageAndCodeHashRlp[64] <== 164;
    storageAndCodeHashRlp[65] <== 112;

    component concat = Concat(22, 66);
    concat.a <== nonceAndBalanceRlp;
    concat.aLen <== nonceAndBalanceRlpLen;
    concat.b <== storageAndCodeHashRlp;
    concat.bLen <== storageAndCodeHashRlpLen;

    out <== concat.out;
    outLen <== concat.outLen;
}

template LeafCalculator() {
    signal input key[33];
    signal input keyLen;
    signal input balance;
    signal output out[1024];
    signal output outLen;

    component rlpEmptyAccount = RlpEmptyAccount();
    rlpEmptyAccount.balance <== balance;

    signal accountRlp[92];
    signal accountRlpLen;
    signal keyRlp[36];
    signal keyRlpLen;

    accountRlp[0] <== 0xb8; 
    accountRlp[1] <== rlpEmptyAccount.outLen + 2;
    
    accountRlp[2] <== 0xf7 + 1; 
    accountRlp[3] <== rlpEmptyAccount.outLen;
    for(var i = 0; i < 88; i++) {
        accountRlp[i + 4] <== rlpEmptyAccount.out[i];
    }
    accountRlpLen <== 4 + rlpEmptyAccount.outLen;

    keyRlp[0] <== 0xf7 + 1;
    keyRlp[1] <== (keyLen + 1) + accountRlpLen;
    keyRlp[2] <== 0x80 + keyLen;
    for(var i = 0; i < 33; i++) {
        keyRlp[i+3] <== key[i];
    }
    keyRlpLen <== keyLen + 3;

    component leafCalc = Concat(36, 92);
    leafCalc.a <== keyRlp;
    leafCalc.aLen <== keyRlpLen;
    leafCalc.b <== accountRlp;
    leafCalc.bLen <== accountRlpLen;

    outLen <== leafCalc.outLen * 8;
    component decomp[128];
    for(var i = 0; i < 128; i++) {
        decomp[i] = Num2Bits(8);
        decomp[i].in <== leafCalc.out[i];
        for(var j = 0; j < 8; j++) {
            out[i*8+j] <== decomp[i].out[j];
        }
    }
}
