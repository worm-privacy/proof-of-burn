pragma circom 2.2.2;

include "./utils.circom";

// The burn-address is the first 20 bytes of Poseidon2(burnKey, receiverAddress)
// The burn-address is bound to both a random salt and the address which has the
// authority to claim the minted ERC-20 coins.
//
// Reviewers:
//   Keyvan: OK
//
template BurnAddress() {
    signal input burnKey;
    signal input receiverAddress;
    signal output addressBytes[20];

    // Take the first 20-bytes of Poseidon2(burnKey, receiverAddress) as a burn-address
    signal hash <== Hasher()(burnKey, receiverAddress);
    signal hashBytes[32] <== Num2BigEndianBytes(32)(hash);
    addressBytes <== Fit(32, 20)(hashBytes);
}

// Returns Keccak of a burn-address as 64 4-bit nibbles.
// Ethereum state-trie maps address-hashes to accounts, that's why we return the 
// Keccak of address instead of the address itself.
//
// Reviewers:
//   Keyvan: OK
//
template BurnAddressHash() {
    signal input burnKey;
    signal input receiverAddress;
    signal output addressHashNibbles[64];

    // Calculate the address to which the burnt coins are sent
    signal addressBytes[20] <== BurnAddress()(burnKey, receiverAddress);

    // Feed the address-bytes in the big-endian form to keccak in order to take the 
    // address-hash which will be used as the key of the MPT leaf
    signal addressBytesBlock[136] <== Fit(20, 136)(addressBytes);
    signal addressHash[32] <== KeccakBytes(1)(addressBytesBlock, 20);

    // Convert the burn-address-hash to 64 4-bit nibbles
    addressHashNibbles <== Bytes2Nibbles(32)(addressHash);
}