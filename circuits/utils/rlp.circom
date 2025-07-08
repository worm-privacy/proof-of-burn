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
//
// Reviewers:
//   Keyvan: OK
//
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
//
// Reviewers:
//   Keyvan: OK
//
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
//
// Reviewers:
//   Keyvan: OK
//
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
    signal shifted[2 * N] <== ShiftRight(N, N)(in, N - inLen);

    // Reverse the whole thing and only keep the last N elements
    // out: [3, 2, 1, 0, 0]
    for(var i = 0; i < N; i++) {
        out[i] <== shifted[N - i - 1];
    }
}

// Returns RLP of an integer up to 31 bytes
//
// Read: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
//
// Example:
//   in: [0], out: [0x80]
//   in: [1], out: [0x01]
//   in: [10], out: [0x0a]
//   in: [127], out: [0x7f]
//   in: [128], out: [0x81,0x80]
//   in: [255], out: [0x81,0xff]
//   in: [256], out: [0x82,0x01,0x00]
//
// Reviewers:
//   Keyvan: OK
//
template RlpInteger(N) {
    signal input in;
    signal output out[N + 1];
    signal output outLen;

    // Avoid overflows.
    // Also, RLP of all numbers up to 55-bytes start with:
    //   [0x80 + num_value_bytes]
    // Instead of:
    //   [0xb7 + num_len_bytes] (Which is the case where length is above 55 bytes)
    // Read: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    assert(N <= 31);

    // Decompose and reverse: calculate the big-endian version of the balance
    signal bytes[N] <== ByteDecompose(N)(in);
    signal length <== CountBytes(N)(bytes);
    signal bigEndian[N] <== ReverseArray(N)(bytes, length);

    // If the number is below 128, then the first byte is the number itself
    // Except when the number is zero, in that case the first byte is 0x80
    // If the number is greater than or equal 128, then the first byte is
    // (0x80 + number_of_bytes)
    signal isSingleByte <== LessThan(N * 8)([in, 128]);
    signal isZero <== IsZero()(in);
    signal firstRlpByte <== Mux1()([0x80 + length, in], isSingleByte);

    // If zero: 0 + 0x80 = 0x80 (Correct)
    // If below 128: num + 0 = num (Correct)
    // If greater than or equal 128: 0x80 + length (Correct)
    out[0] <== firstRlpByte + isZero * 0x80;
    
    // If the number is greater than or equal 128, then comes the rest of
    // the big-endian representation of bytes. Otherwise, everything is 0.
    for (var i = 1; i < N + 1; i++) {
        out[i] <== (1 - isSingleByte) * bigEndian[i - 1];
    }

    // If zero: (1 - 1) + 0 + 1 = 1 (Correct) [0x80]
    // If below 128: (1 - 1) + 1 + 0 = 1 (Correct) [num]
    // If greater than or equal 128: (1 - 0) + length + 0 = 1 + length (Correct) [0x80 + length, ...]
    outLen <== (1 - isSingleByte) + length + isZero;
}


// Returns RLP([NONCE, balance, STORAGE_HASH, CODE_HASH])
// Where:
//   NONCE = 0
//   STORAGE_HASH = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
//   CODE_HASH = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
//
// The result is the RLP of a "list" of "bytes" where the total length of the bytes is 
// always this range: 68 <= length <= 99, which is more than 55, thus RLP prefix of [0xf7 + len] 
// and less than 256, which allows it to be represented using a single byte)
// Read: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
//
// Reviewers:
//   Keyvan: OK
//
template RlpEmptyAccount(maxBalanceBytes) {
    signal input balance;

    assert(maxBalanceBytes <= 31); // Avoid overflows

    // Minimum RLP length is 1 (NONCE) + 1 (balance) + 33 (STORAGE_HASH) + 33 (CODE_HASH) = 68 (> 55 bytes)
    // Maximum RLP length is 1 (NONCE) + 32 (balance) + 33 (STORAGE_HASH) + 33 (CODE_HASH) = 99 (< 256, less than a byte)
    // So, the two-byte prefix is always [0xf7 + 1, TOTAL_BYTES_LEN] (Given the range: 55 < byte < 256)
    // (When the number of bytes in a list is less-than-equal 55, then the prefix is [0xc0 + len])
    // Read: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    
    // [0xf7 + 1, TOTAL_BYTES_LEN, 0x80 (Nonce: 0), BALANCE_BYTES_PREFIX] 
    //   + BALANCE_BYTES + [0x80 + 32] + STORAGE_HASH + [0x80 + 32] + CODE_HASH
    signal output out[4 + maxBalanceBytes + 66];
    signal output outLen;

    // 4 prefix bytes: [0xf8, TOTAL_BYTES_LEN, 0x80 (Nonce: 0), BALANCE_BYTES_PREFIX]
    signal prefixedNonceAndBalanceRlp[4 + maxBalanceBytes];
    signal prefixedNonceAndBalanceRlpLen;
    
    prefixedNonceAndBalanceRlp[2] <== 0x80; // Nonce of a burn-address is always zero (RLP: 0x80)
    signal (balanceRlp[maxBalanceBytes + 1], balanceRlpLen) <== RlpInteger(maxBalanceBytes)(balance);
    for(var i = 0; i < maxBalanceBytes + 1; i++) {
        prefixedNonceAndBalanceRlp[i + 3] <== balanceRlp[i];
    }

    signal nonceAndBalanceRlpLen; // Without the [0xf8, TOTAL_BYTES_LEN] prefix
    nonceAndBalanceRlpLen <== 1 + balanceRlpLen; // Nonce (Len: 1) and then the RLP of balance (Len: balanceRlpLen)
    prefixedNonceAndBalanceRlpLen <== 2 + nonceAndBalanceRlpLen; // [0xf8, TOTAL_BYTES_LEN] is the prefix

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

    // Final result: RLP(0, balance, storageHash, codeHash)
    component concat = Concat(4 + maxBalanceBytes, 66);
    concat.a <== prefixedNonceAndBalanceRlp;
    concat.aLen <== prefixedNonceAndBalanceRlpLen;
    concat.b <== storageAndCodeHashRlp;
    concat.bLen <== storageAndCodeHashRlpLen;

    out <== concat.out;
    outLen <== concat.outLen;
}

// Returns RLP(key, value)
// Where:
//   key:   addressHash
//   value: RLP([NONCE, balance, STORAGE_HASH, CODE_HASH])
//
// Read: https://ethereum.org/de/developers/docs/data-structures-and-encoding/patricia-merkle-trie
//
// Reviewers:
//   Keyvan: OK
//
template LeafCalculator(maxAddressHashBytes, maxBalanceBytes) {
    signal input addressHashNibbles[2 * maxAddressHashBytes];
    signal input addressHashNibblesLen;
    signal input balance;

    assert(maxAddressHashBytes <= 32);
    assert(maxBalanceBytes <= 31);

    // Min length: 4 + 1 + 66 = 71
    // Max length: 4 + 31 + 66 = 101
    // The "value" in a leaf node is RLP of an account
    var maxRlpEmptyAccountLen = 4 + maxBalanceBytes + 66; // More info in RlpEmptyAccount gadget
    assert(maxRlpEmptyAccountLen <= 101);

    // Min length: 2 + 71 = 73
    // Max length: 2 + 101 = 103
    // Byte-strings of length more than 55 bytes and less than 256 bytes are prefix with:
    // [0xb7 + 1, STRING_LEN]
    var maxValueRlpLen = 2 + maxRlpEmptyAccountLen; // Prefix: [0xb7 + 1, VALUE_LEN]
    assert(maxValueRlpLen <= 103);

    // Leaf keys are prefixed with 0x20 or 0x3_
    // Read: https://ethereum.org/de/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#specification
    // Min length: 2 (We later put an AssertGreaterEqThan on the keyLen to avoid keyLens lower than 2)
    // Max length: 33
    var maxKeyLen = 1 + maxAddressHashBytes; 
    assert(maxKeyLen <= 33);

    // keyLen is at least 2 bytes and at most 33 bytes, so [0x80 + keyLen] is the correct prefix
    // Min length: 3
    // Max length: 34
    var maxKeyRlpLen = 1 + maxKeyLen; // Prefix: [0x80 + KEY_LEN]
    assert(maxKeyLen <= 34);

    // KEY_RLP_LEN + VALUE_RLP_LEN is minimum (3 + 73 = 76) and maximum (34 + 103 = 137) bytes
    // So the correct prefix is always: [0xf7 + 1, KEY_RLP_LEN + VALUE_RLP_LEN]
    var maxPrefixedKeyRlpLen = 2 + maxKeyRlpLen;
    assert(maxKeyRlpLen + maxValueRlpLen <= 137);

    // maxBalanceBytes + maxAddressHashBytes + 76
    var maxOutLen = maxPrefixedKeyRlpLen + maxValueRlpLen; 

    signal output out[maxOutLen];
    signal output outLen;

    // Calculate the MPT leaf key based on the address-hash nibbles
    signal (key[maxKeyLen], keyLen) <== LeafKey(32)(addressHashNibbles, addressHashNibblesLen);    

    // A minimum of 2 bytes so that the prefix of key is always [0x80 + len]
    AssertGreaterEqThan(16)(keyLen, 2);

    signal (
        rlpEmptyAccount[maxRlpEmptyAccountLen], rlpEmptyAccountLen
    ) <== RlpEmptyAccount(maxBalanceBytes)(balance);
    
    // Key is the RLP-encoding of part of the address-hash.
    // (NOTE: This is also prefixed with the RLP of the whole leaf)
    signal prefixedKeyRlp[maxPrefixedKeyRlpLen];
    signal prefixedKeyRlpLen;

    // Value is the RLP-encoding of an empty-account RLP.
    signal valueRlp[maxValueRlpLen];
    signal valueRlpLen;

    valueRlp[0] <== 0xb7 + 1;
    valueRlp[1] <== rlpEmptyAccountLen;
    for(var i = 0; i < maxRlpEmptyAccountLen; i++) {
        valueRlp[i + 2] <== rlpEmptyAccount[i];
    }
    valueRlpLen <== 2 + rlpEmptyAccountLen;

    // Prefix of the whole leaf: RLP([key, value])
    prefixedKeyRlp[0] <== 0xf7 + 1;
    prefixedKeyRlp[1] <== (keyLen + 1) + valueRlpLen; // (keyLen + 1) is keyRlpLen

    prefixedKeyRlp[2] <== 0x80 + keyLen;
    for(var i = 0; i < 33; i++) {
        prefixedKeyRlp[i + 3] <== key[i];
    }
    prefixedKeyRlpLen <== 3 + keyLen;

    (out, outLen) <== Concat(maxPrefixedKeyRlpLen, maxValueRlpLen)(
        a <== prefixedKeyRlp,
        aLen <== prefixedKeyRlpLen,
        b <== valueRlp,
        bLen <== valueRlpLen
    );
}
