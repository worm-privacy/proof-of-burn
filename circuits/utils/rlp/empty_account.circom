pragma circom 2.2.2;

include "../utils.circom";
include "../concat.circom";
include "./integer.circom";

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