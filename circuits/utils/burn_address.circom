pragma circom 2.2.2;

include "./utils.circom";

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
    signal hashBytes[32] <== Num2BytesBigEndian(32)(hash);
    signal addressBytes[20] <== Fit(32, 20)(hashBytes);

    // Feed the address-bytes in the big-endian form to keccak in order to take the 
    // address-hash which will be used as the key of the MPT leaf
    signal addressBytesBlock[136] <== Fit(20, 136)(addressBytes);
    signal addressHash[32] <== KeccakBytes(1)(addressBytesBlock, 20);

    // Convert the burn-address-hash to 64 4-bit nibbles
    addressHashNibbles <== Bytes2Nibbles(32)(addressHash);
}