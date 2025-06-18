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

    assert(N <= 31); // Avoid overflows

    // Decompose into bits and arrange them into 8-bit chunks
    signal bits[N * 8] <== Num2Bits(N * 8)(num);
    signal byteBits[N][8];
    for (var i = 0; i < N; i++) {
        for(var j = 0; j < 8; j++) {
            byteBits[i][j] <== bits[8 * i + j];
        }
    }

    // Convert 8-bit chunks to bytes
    for (var i = 0; i < N; i++) {
        bytes[i] <== Bits2Num(8)(byteBits[i]);
    }
}

// Counts the number of bytes required to store the number (i.e., ignores leading zeros).
//
// Example:
//   bytes: [3, 0, 1, 4, 2, 0, 0, 0] (3 leading-zeros)
//   len:   5
template CountBytes(N) {
    signal input bytes[N];
    signal output len;

    // Example:
    // bytes: [3, 0, 1, 4, 2, 0, 0, 0]

    // Checking zero-ness of each byte
    // isZero (Reversed):   [0, 1, 0, 0, 0, 1, 1, 1]
    // isZero:              [1, 1, 1, 0, 0, 0, 1, 0]
    signal isZero[N];
    for (var i = 0; i < N; i++) {
        isZero[i] <== IsZero()(bytes[N - i - 1]);
    }

    // Accumulating 1s until we reach a zero
    // stillZero: [*, 1, 1, 1, 0, 0, 0, 0, 0]
    // (The first element is initially set to 1)
    signal stillZero[N + 1];
    stillZero[0] <== 1;
    for (var i = 0; i < N; i++) {
        stillZero[i + 1] <== isZero[i] * stillZero[i];
    }
    
    // Number of leading-zeros = Sum of bits in stillZero
    var leadingZeros = 0;
    for (var j = 1; j < N + 1; j++) {
        leadingZeros = leadingZeros + stillZero[j];
    }

    // Number of effective bytes = N - number of leading-zeros
    len <== N - leadingZeros;
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

    // Example:
    //   in:    [1, 2, 3, 4, 5], inLen: 3

    // Shift-right by `N - inLen` to put the elements at the last of
    // a 2 * N element array.
    // shifted: [0, 0, 0, 0, 0, 0, 0, 1, 2, 3]
    signal shifted[2 * N] <== Shift(N, N)(in, N - inLen);

    // Reverse the whole thing and only keep the last N elements
    // out: [3, 2, 1, 0, 0]
    for(var i = 0; i < N; i++) {
        out[i] <== shifted[N - i - 1];
    }
}

template RlpInteger(N) {
    signal input in;
    signal output out[N + 1];
    signal output outLen;

    assert(N <= 31); // Avoid overflows

    signal bytes[N] <== ByteDecompose(N)(in);
    signal length <== CountBytes(N)(bytes);
    signal reversedBytes[N] <== ReverseArray(N)(bytes, length);
    signal isSingleByte <== LessThan(N * 8)([in, 128]);
    signal isZero <== IsZero()(in);

    outLen <== (1 - isSingleByte) + length + isZero;

    signal firstRlpByte <== Mux1()([0x80 + length, in], isSingleByte);
    out[0] <== firstRlpByte + isZero * 0x80;
    for (var i = 1; i < N + 1; i++) {
        out[i] <== (1 - isSingleByte) * reversedBytes[i-1];
    }
}

template RlpEmptyAccount(maxBalanceBytes) {
    signal input balance;
    signal output out[4 + maxBalanceBytes + 66];
    signal output outLen;

    // 4 prefix bytes: [0xf8, TOTAL_BYTES_LEN, 0x80 (Nonce: 0), BALANCE_BYTES_LEN]
    signal prefixedNonceAndBalanceRlp[4 + maxBalanceBytes];
    signal nonceAndBalanceRlpLen;
    signal prefixedNonceAndBalanceRlpLen;
    prefixedNonceAndBalanceRlp[2] <== 0x80; // Nonce of a burn-address is always zero (RLP: 0x80)
    signal (balanceRlp[maxBalanceBytes + 1], balanceRlpLen) <== RlpInteger(maxBalanceBytes)(balance);
    for(var i = 0; i < maxBalanceBytes + 1; i++) {
        prefixedNonceAndBalanceRlp[i + 3] <== balanceRlp[i];
    }
    nonceAndBalanceRlpLen <== 1 + balanceRlpLen; // BALANCE_BYTES_LEN is the prefix
    prefixedNonceAndBalanceRlpLen <== 2 + nonceAndBalanceRlpLen; // [0x80 (Nonce: 0), BALANCE_BYTES_LEN] is the prefix

    // Concatenated RLP of storage-hash and code-hash of an empty account
    // Storage-hash: 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
    // Code-hash:    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 
    var storageAndCodeHashRlpLen = 66; // 1 + 32 + 1 + 32 (32-byte chunks are prefixed)
    signal storageAndCodeHashRlp[storageAndCodeHashRlpLen];
    storageAndCodeHashRlp[0] <== 160; // Prefix: 0x80 + 32
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
    storageAndCodeHashRlp[33] <== 160; // Prefix: 0x80 + 32
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

    prefixedNonceAndBalanceRlp[0] <== 0xf7 + 1; // + 1, because the next byte is number of total bytes
    prefixedNonceAndBalanceRlp[1] <== nonceAndBalanceRlpLen + storageAndCodeHashRlpLen;

    component concat = Concat(4 + maxBalanceBytes, 66);
    concat.a <== prefixedNonceAndBalanceRlp;
    concat.aLen <== prefixedNonceAndBalanceRlpLen;
    concat.b <== storageAndCodeHashRlp;
    concat.bLen <== storageAndCodeHashRlpLen;

    out <== concat.out;
    outLen <== concat.outLen;
}

template LeafCalculator(maxAddressHashBytes, maxBalanceBytes) {
    var maxRlpEmptyAccountLen = 4 + maxBalanceBytes + 66;
    var maxKeyRlpLen = 3 + maxAddressHashBytes + 1;
    var maxValueRlpLen = 2 + maxRlpEmptyAccountLen;
    var maxOutLen = maxKeyRlpLen + maxValueRlpLen;

    signal input addressHashNibbles[2 * maxAddressHashBytes];
    signal input addressHashNibblesLen;
    signal input balance;

    signal (key[maxAddressHashBytes + 1], keyLen) <== LeafKey(32)(addressHashNibbles, addressHashNibblesLen);    

    signal output out[maxOutLen * 8];
    signal output outLen;

    signal (
        rlpEmptyAccount[maxRlpEmptyAccountLen], rlpEmptyAccountLen
    ) <== RlpEmptyAccount(maxBalanceBytes)(balance);
    
    signal valueRlp[maxValueRlpLen];
    signal valueRlpLen;
    signal keyRlp[maxKeyRlpLen];
    signal keyRlpLen;

    valueRlp[0] <== 0xb7 + 1; 
    valueRlp[1] <== rlpEmptyAccountLen;
    for(var i = 0; i < maxRlpEmptyAccountLen; i++) {
        valueRlp[i + 2] <== rlpEmptyAccount[i];
    }
    valueRlpLen <== 2 + rlpEmptyAccountLen;

    keyRlp[0] <== 0xf7 + 1;
    keyRlp[1] <== (keyLen + 1) + valueRlpLen;
    keyRlp[2] <== 0x80 + keyLen;
    for(var i = 0; i < 33; i++) {
        keyRlp[i + 3] <== key[i];
    }
    keyRlpLen <== 3 + keyLen;

    signal (leafBytes[maxOutLen], leafBytesLen) <== Concat(maxKeyRlpLen, maxValueRlpLen)(
        a <== keyRlp,
        aLen <== keyRlpLen,
        b <== valueRlp,
        bLen <== valueRlpLen
    );

    outLen <== leafBytesLen * 8;
    component decomp[maxOutLen];
    for(var i = 0; i < maxOutLen; i++) {
        decomp[i] = Num2Bits(8);
        decomp[i].in <== leafBytes[i];
        for(var j = 0; j < 8; j++) {
            out[i * 8 + j] <== decomp[i].out[j];
        }
    }
}
