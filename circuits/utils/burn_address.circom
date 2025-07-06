pragma circom 2.2.2;

include "./utils.circom";

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

// Takes an burnKey input and generates a burn-address-hash represented as 64 4-bit nibbles 
// using the MiMC hash function, creating a unique address-hash with no known private-key
//
// Reviewers:
//   Keyvan: OK
//
template BurnKeyAndReceiverToAddressHash() {
    signal input burnKey;
    signal input receiverAddress;
    signal output addressHashNibbles[64];

    // Take the first 160-bits of MiMC7(burnKey, receiverAddress) as a burn-address
    signal hash <== Hasher()(burnKey, receiverAddress);
    signal hashBits[256] <== FieldToBigEndianBits()(hash);
    signal addressBits[160] <== Fit(256, 160)(hashBits);

    // Feed the address-bytes in the big-endian form to keccak in order to take the 
    // address-hash which will be used as the key of the MPT leaf
    signal addressBitsBlock[8 * 136] <== Fit(160, 8 * 136)(addressBits);
    signal addressHash[256] <== KeccakBits(1)(addressBitsBlock, 160);

    // Convert the burn-address-hash to 64 4-bit nibbles
    addressHashNibbles <== BitsToNibbles(32)(addressHash);
}