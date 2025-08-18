pragma circom 2.2.2;

include "../circomlib/circuits/poseidon.circom";
include "./convert.circom";
include "./array.circom";
include "./constants.circom";

// The burn-address is the first 20 bytes of:
//   Poseidon4(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, receiverAddress, fee)
//
// The burn-address is bound to:
//   1. A random salt (The burnKey)
//   2. The address which has the authority to collect the minted ERC-20 coins
//   3. The fee which can be collected by the proof submitter
//
// The bound ensures that the burner can simply send their ETH to a derived address and
// delegate the responsibility of generating a proof and submitting it to the blockchain
// to the relayer, without the risk of the relayer taking all the ERC-20 tokens for
// themselves or charging more fees than specified by the burner. However, it is better
// for the burner to generate the proof themselves; otherwise, the burner's identity will
// be leaked to the relayer.
//
// Reviewers:
//   Keyvan: OK
//
template BurnAddress() {
    signal input burnKey;
    signal input receiverAddress;
    signal input fee;
    signal output addressBytes[20];

    // Take the first 20-bytes of
    //   Poseidon4(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, receiverAddress, fee) as a burn-address
    signal hash <== Poseidon(4)([POSEIDON_BURN_ADDRESS_PREFIX(), burnKey, receiverAddress, fee]);
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
    signal input fee;
    signal output addressHashNibbles[64];

    // Calculate the address to which the burnt coins are sent
    signal addressBytes[20] <== BurnAddress()(burnKey, receiverAddress, fee);

    // Feed the address-bytes in the big-endian form to keccak in order to take the 
    // address-hash which will be used as the key of the MPT leaf
    signal addressBytesBlock[136] <== Fit(20, 136)(addressBytes);
    signal addressHash[32] <== KeccakBytes(1)(addressBytesBlock, 20);

    // Convert the burn-address-hash to 64 4-bit nibbles
    addressHashNibbles <== Bytes2Nibbles(32)(addressHash);
}