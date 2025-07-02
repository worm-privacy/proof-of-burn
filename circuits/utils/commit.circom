pragma circom 2.2.2;

include "../circomlib/circuits/bitify.circom";
include "./keccak.circom";
include "./utils.circom";

// Convert a field element to 256-bits
//
// Reviewers:
//   Keyvan: OK
//
template FieldToBits() {
    signal input in;
    signal output out[256];

    signal bitsStrict[254] <== Num2Bits_strict()(in);
    for(var i = 0; i < 254; i++) out[i] <== bitsStrict[i];
    out[254] <== 0;
    out[255] <== 0;
}

// Calculate keccak(abi.encodePacked(in[0], in[1], ..., in[N-1]))
// Where inputs are 256-bit data
// The last byte of output is truncated in order to make the result fit in a field element
//
// Reviewers:
//   Keyvan: OK
//
template PublicCommitment(N) {
    signal input in[N][256];
    signal output out;

    // Just to make sure the gadget is being used for only 6 elements
    assert(N == 6);

    // Number of keccak-blocks needed to store N 32-byte elements
    // numBlocks = Ceil(N * 32 / 136)
    var numBlocks = N * 32 \ 136 + (N * 32 % 136 != 0);

    signal bits[numBlocks * 136 * 8];
    for(var i = 0; i < N; i++) {
        for(var j = 0; j < 256; j++) {
            bits[i * 256 + j] <== in[i][j];
        }
    }
    // The rest of the bits are set tot zero
    for(var i = N * 256; i < numBlocks * 136 * 8; i++) {
        bits[i] <== 0;
    }

    signal hash[256] <== KeccakBits(numBlocks)(bits, N * 256);

    // Ignore the last byte while converting keccak to field element
    component bitsToNum = Bits2NumBigEndian(31);
    for(var i = 0; i < 31 * 8; i++) {
        bitsToNum.in[i] <== hash[i + 8];
    }
    out <== bitsToNum.out;
}