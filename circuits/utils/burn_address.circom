pragma circom 2.2.2;

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
    component addressHash = KeccakBits(1);
    for(var i = 0; i < 20; i++) {
        for(var j = 0; j < 8; j++) {
            addressHash.inBits[8 * (19 - i) + j] <== hashBits[8 * i + j];
        }
    }
    for(var i = 160; i < 8 * 136; i++) {
        addressHash.inBits[i] <== 0;
    }
    addressHash.inBitsLen <== 160;

    for(var i = 0; i < 32; i++) {
        var higher = 0;
        var lower = 0;
        for(var j = 0; j < 4; j++) {
            lower += addressHash.out[i * 8 + j] * (2 ** j);
            higher += addressHash.out[i * 8 + j + 4] * (2 ** j);
        }
        addressHashNibbles[2 * i] <== higher;
        addressHashNibbles[2 * i + 1] <== lower;
    }
}