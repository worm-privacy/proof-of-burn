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

    var outVars[n];
    signal isEq[n][n];
    signal temp[n][n];
    // out[i] <== sum_j(in[j] * (i == j - count))
    for(var i = 0; i < n; i++) {
        for(var j = 0; j < n; j++) {
            isEq[i][j] <== IsEqual()([i, j - count]) ;
            temp[i][j] <== isEq[i][j] * in[j];
            outVars[i] += temp[i][j];
        }
        out[i] <== outVars[i];
    }
}


// Converts an array of nibbles (4-bit values) into an array of bytes (8-bit values).
// Each byte is formed by combining two nibbles (4 bits each).
//
// Example:
//   nibbles: [0x1, 0x2, 0x3, 0x4, 0x5, 0x6]
//   bytes: [0x12, 0x34, 0x56]
//
// Reviewers:
//   Keyvan: OK
//
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
//   len:    4
//   out:    [0x20, 0x12, 0x34]
//   outLen: 3
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    3
//   out:    [0x32, 0x34, 0x00]
//   outLen: 2
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    2
//   out:    [0x20, 0x34, 0x00]
//   outLen: 2
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    1
//   out:    [0x34, 0x00, 0x00]
//   outLen: 1
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    0
//   out:    [0x20, 0x00, 0x00]
//   outLen: 1
template LeafKey(N) {
    signal input addressHashNibbles[2 * N];
    signal input addressHashNibblesLen;
    signal output out[N + 1];
    signal output outLen;

    signal (div, rem) <== Divide(16)(addressHashNibblesLen, 2);

    // Shift left (2 * N - addressHashNibblesLen) times so that
    // the last addressHashNibblesLen nibbles remain
    signal shifted[2 * N] <== ShiftLeft(2 * N)(addressHashNibbles, 2 * N - addressHashNibblesLen);

    signal outNibbles[2 * N + 2];
    // 2 if even number of nibbles, 3 if odd number of nibbles
    outNibbles[0] <== 2 + rem;

    // If odd number of nibbles, the second nibble of the result 
    // should be the first nibble of the remaining value
    outNibbles[1] <== rem * shifted[0]; 

    signal temp[2 * N - 1];

    // If odd number of nibbles, shift-right by one
    for(var i = 0; i < 2 * N; i++) {
        if(i < 2 * N - 1) {
            temp[i] <== rem * shifted[i + 1];
            outNibbles[i + 2] <== (1 - rem) * shifted[i] + temp[i];
        } else {
            outNibbles[i + 2] <== (1 - rem) * shifted[i];
        }
    }

    out <== NibblesToBytes(N + 1)(outNibbles);
    outLen <== 1 + div;
}