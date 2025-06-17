pragma circom 2.2.2;

include "./utils.circom";
include "./assert.circom";

// Shifts the `in` array to the left by the given `count` times, filling the end with zeros.
//
// Example:
//   in:    [1, 2, 3, 4, 5]
//   count: 2
//   out:   [3, 4, 5, 0, 0]
template ShiftLeft(n) {
    signal input in[n];
    signal input count;
    signal output out[n];

    AssertLessEqThan(16)(count, n);

    signal outsum[n][n+1];
    for(var i = 0; i < n; i++) {
        outsum[i][0] <== 0;
    }
    signal eqs[n][n];
    for(var i = 0; i < n; i++) {
        for(var j = 0; j < n; j++) {
            eqs[i][j] <== IsEqual()([i, j - count]);
            outsum[i][j+1] <== outsum[i][j] + eqs[i][j] * in[j];
        }
        out[i] <== outsum[i][n];
    }
}


// Converts an array of nibbles (4-bit values) into an array of bytes (8-bit values).
// Each byte is formed by combining two nibbles (4 bits each).
//
// Example:
//   nibbles: [0x1, 0x2, 0x3, 0x4, 0x5, 0x6]
//   bytes: [0x12, 0x34, 0x56]
template NibblesToBytes(n) {
    signal input nibbles[2 * n];
    signal output bytes[n];
    for(var i = 0; i < n; i++) {
        // Check if all nibbles are maximum 4-bit long
        AssertBits(4)(nibbles[2 * i]);
        AssertBits(4)(nibbles[2 * i + 1]);

        bytes[i] <== nibbles[2 * i] * 16 + nibbles[2 * i + 1];
    }
}


// Takes `N` nibbles and shifts them left by `count` with this pattern:
//
//   1. If even number of nibbles is remaining: [0x20, rest_of_the_nibbles_as_bytes]
//   2. If odd number of nibbles is remaining:  [0x30 + first_nibble, rest_of_the_nibbles_as_bytes]
//
// (Read more: https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#specification)
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   count:  0
//   out:    [0x20, 0x12, 0x34]
//   outLen: 3
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   count:  1
//   out:    [0x32, 0x34, 0x00]
//   outLen: 2
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   count:  2
//   out:    [0x20, 0x34, 0x00]
//   outLen: 2
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   count:  3
//   out:    [0x34, 0x00, 0x00]
//   outLen: 1
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   count:  4
//   out:    [0x20, 0x00, 0x00]
//   outLen: 1
template LeafKey(N) {
    signal input addressHashNibbles[2 * N];
    signal input addressHashNibblesLen;
    signal output out[N + 1];
    signal output outLen;

    signal outNibbles[2 * N + 2];
    signal outNibblesLen;

    signal (div, rem) <== Divide(16)(addressHashNibblesLen, 2);

    signal shifted[2 * N] <== ShiftLeft(2 * N)(addressHashNibbles, addressHashNibblesLen);
    signal temp[2 * N - 1];
    for(var i = 0; i < 2 * N; i++) {
        if(i == 2 * N - 1) {
            outNibbles[i+2] <== (1 - rem) * shifted[i];
        } else {
            temp[i] <== rem * shifted[i + 1];
            outNibbles[i + 2] <== (1 - rem) * shifted[i] + temp[i];
        }
    }
    outNibbles[0] <== 2 + rem;
    outNibbles[1] <== rem * shifted[0];

    out <== NibblesToBytes(N + 1)(outNibbles);
    outLen <== N + 1 - div - rem;
}