pragma circom 2.2.2;

include "../circomlib/circuits/bitify.circom";
include "./keccak.circom";
include "./utils.circom";
include "./assert.circom";

// Calculate keccak(abi.encodePacked(in[0], in[1], ..., in[N-1]))
// Where inputs are 32-byte data
// The last byte of output is truncated in order to make the result fit in a field element
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//      - Comment: Since it is being used indirectly by the spend.circom, there is no need to check that `in[n][32]` values are indeed `bytes`. This must always be eforced by the wrapper circuit that calls this.
//          - Keyvan's response: Added AssertByteString to ensure all inputs are bytes, just in case :)
//
template PublicCommitment(N) {
    signal input in[N][32];
    signal output out;

    // Check if all inputs are byte-strings
    for(var i = 0; i < N; i++) {
        AssertByteString(32)(in[i]);
    }

    // Number of keccak-blocks needed to store N 32-byte elements
    // numBlocks = Ceil(N * 32 / 136)
    var numBlocks = N * 32 \ 136 + (N * 32 % 136 != 0);

    assert(numBlocks * 136 - N * 32 >= 1); // Reserve at least one byte for padding!

    // Fit the 32-byte numbers in the keccak blocks and calculate the hash
    signal flattenIn[N * 32] <== Flatten(N, 32)(in);
    signal block[numBlocks * 136] <== Fit(N * 32, numBlocks * 136)(flattenIn);
    signal hash[32] <== KeccakBytes(numBlocks)(block, N * 32);
    
    // Ignore the least-significant byte while converting keccak to field element
    signal reducedHash[31] <== Fit(32, 31)(hash);
    out <== BigEndianBytes2Num(31)(reducedHash);
}