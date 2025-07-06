pragma circom 2.2.2;

include "../circomlib/circuits/bitify.circom";
include "./keccak.circom";
include "./utils.circom";

// Converts an array of binary bits into a number in big-endian format.
//
// Reviewers:
//   Keyvan: OK
//
template Bits2NumBigEndian(numBytes) {
    signal input in[numBytes * 8];
    signal output out;

    assert(numBytes <= 31); // Avoid overflows

    var result = 0;
    var step = 1;

    // Big-endian (Byte-level)
    for (var i = numBytes - 1; i >= 0; i--) {
        // Little-endian (Bit-level)
        for (var j = 0; j < 8; j++) {
            result += in[i * 8 + j] * step;
            step *= 2;
        }
    }

    out <== result;
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

    // Number of keccak-blocks needed to store N 32-byte elements
    // numBlocks = Ceil(N * 32 / 136)
    var numBlocks = N * 32 \ 136 + (N * 32 % 136 != 0);

    assert(numBlocks * 136 - N * 32 >= 1); // Reserve at least one byte for padding!

    // Fit the 256-bit numbers in the keccak blocks and calculate the hash
    signal flattenIn[N * 256] <== Flatten(N, 256)(in);
    signal bits[numBlocks * 136 * 8] <== Fit(N * 256, numBlocks * 136 * 8)(flattenIn);
    signal hash[256] <== KeccakBits(numBlocks)(bits, N * 256);
    
    // Ignore the least-significant byte while converting keccak to field element
    signal reducedHash[248] <== Fit(256, 248)(hash);
    out <== Bits2NumBigEndian(31)(reducedHash);
}