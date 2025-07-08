pragma circom 2.2.2;

include "../circomlib/circuits/mux1.circom";
include "./utils.circom";
include "./assert.circom";

// Shifts the `in` array to the left by the given `count` times, filling the end with zeros.
//
// Example:
//   in:    [1, 2, 3, 4, 5]
//   count: 2
//   out:   [3, 4, 5, 0, 0]
//
// Reviewers:
//   Keyvan: OK
//
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
//
// Reviewers:
//   Keyvan: OK
//
template LeafKey(addressHashBytes) {
    signal input addressHashNibbles[2 * addressHashBytes];
    signal input addressHashNibblesLen;
    signal output out[addressHashBytes + 1];
    signal output outLen;

    // addressHash is at most 32 bytes (64 nibbles) so 6 bits
    signal (div, rem) <== Divide(6)(addressHashNibblesLen, 2);

    // Shift left (2 * addressHashBytes - addressHashNibblesLen) times so that
    // the last addressHashNibblesLen nibbles remain
    signal shifted[2 * addressHashBytes] <== ShiftLeft(2 * addressHashBytes)(
        addressHashNibbles, 2 * addressHashBytes - addressHashNibblesLen);

    signal outNibbles[2 * addressHashBytes + 2];
    // 2 if even number of nibbles, 3 if odd number of nibbles
    outNibbles[0] <== 2 + rem;

    // If odd number of nibbles, the second nibble of the result 
    // should be the first nibble of the remaining value
    // If even number of nibbles, the second nibble is 0
    outNibbles[1] <== rem * shifted[0]; 

    signal temp[2 * addressHashBytes - 1];

    // If odd number of nibbles, shift-right by one
    for(var i = 0; i < 2 * addressHashBytes; i++) {
        if(i < 2 * addressHashBytes - 1) {
            outNibbles[i + 2] <== Mux1()([shifted[i], shifted[i + 1]], rem);
        } else {
            // Avoid index out of bound
            outNibbles[i + 2] <== (1 - rem) * shifted[i];
        }
    }

    out <== Nibbles2Bytes(addressHashBytes + 1)(outNibbles);
    outLen <== 1 + div;
}