pragma circom 2.2.2;

// Fits a M-element array in a N-element block
//
// Reviewers:
//   Keyvan: OK
//
template Fit(M, N) {
    signal input in[M];
    signal output out[N];
    for(var i = 0; i < N; i++) {
        if(i < M) {
            out[i] <== in[i];
        } else {
            out[i] <== 0;
        }
    }
}

// Accepts N bytes (As 8xN bits) and outputs N bytes (As 8xN bits) where bytes are reversed
//
// Reviewers:
//   Keyvan: OK
//
template ReverseBytes(N) {
    signal input in[N * 8];
    signal output out[N * 8];
    for(var i = 0; i < N; i++) {
        for(var j = 0; j < 8; j++) {
            out[8 * i + j] <== in[8 * (N - 1 - i) + j];
        }
    }
}

// Accepts N bytes (As 8xN bits) and outputs 2xN nibbles (As a list of 4-bit numbers)
//
// Reviewers:
//   Keyvan: OK
//
template BitsToNibbles(N) {
    signal input in[8 * N]; // Each byte is 8 bits
    signal output out[2 * N]; // Each byte is 2 nibbles

    for(var i = 0; i < N; i++) {
        var higher = 0;
        var lower = 0;
        for(var j = 0; j < 4; j++) {
            lower += in[i * 8 + j] * (2 ** j);
            higher += in[i * 8 + j + 4] * (2 ** j);
        }
        out[2 * i] <== higher;
        out[2 * i + 1] <== lower;
    }
}

// Takes an burnKey input and generates a burn address represented as 64 4-bit nibbles 
// using the MiMC hash function, creating a unique address hash.
//
// Example:
//   burnKey: [A single field number]
//   addressHashNibbles: [64 nibbles, each 4 bits, resulting from MiMC(burnKey, 0)
//
template BurnKeyAndReceiverToAddressHash() {
    signal input burnKey;
    signal input receiver;
    signal output addressHashNibbles[64];

    signal hash <== Hasher()(burnKey, receiver);
    signal hashBits[256] <== FieldToBits()(hash);
    signal addressBits[160] <== Fit(256, 160)(hashBits);
    signal addressBitsReversed[160] <== ReverseBytes(20)(addressBits);
    signal addressBitsReversedBlock[8 * 136] <== Fit(160, 8 * 136)(addressBitsReversed);
    signal addressHash[256] <== KeccakBits(1)(addressBitsReversedBlock, 160);
    addressHashNibbles <== BitsToNibbles(32)(addressHash);
}