pragma circom 2.2.2;

include "./utils.circom";

// Accepts N bytes and outputs 2xN nibbles (As a list of 4-bit numbers)
//
// Reviewers:
//   Keyvan: OK
//
template BytesToNibbles(N) {
    signal input in[N];
    signal output out[2 * N]; // Each byte is 2 nibbles

    signal inDecomposed[N][8];

    for(var i = 0; i < N; i++) {
        inDecomposed[i] <== Num2Bits(8)(in[i]);
        var higher = 0;
        var lower = 0;
        for(var j = 0; j < 4; j++) {
            lower += inDecomposed[i][j] * (2 ** j);
            higher += inDecomposed[i][j + 4] * (2 ** j);
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

    // Take the first 20-bytes of MiMC7(burnKey, receiverAddress) as a burn-address
    signal hash <== Hasher()(burnKey, receiverAddress);
    signal hashBytes[32] <== FieldToBigEndianBytes()(hash);
    signal addressBytes[20] <== Fit(32, 20)(hashBytes);

    // Feed the address-bytes in the big-endian form to keccak in order to take the 
    // address-hash which will be used as the key of the MPT leaf
    signal addressBytesBlock[136] <== Fit(20, 136)(addressBytes);
    signal addressHash[32] <== KeccakBytes(1)(addressBytesBlock, 20);

    // Convert the burn-address-hash to 64 4-bit nibbles
    addressHashNibbles <== BytesToNibbles(32)(addressHash);
}