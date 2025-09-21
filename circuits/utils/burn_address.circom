pragma circom 2.2.2;

include "../circomlib/circuits/poseidon.circom";
include "./convert.circom";
include "./array.circom";
include "./constants.circom";

// The burn-address is the first 20 bytes of:
//   Poseidon5(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, receiverAddress, feeAmount, revealAmount)
//
// The burn-address is bound to:
//   1. burnKey:         A random salt from which a nullifier is derived
//   2. receiverAddress: The address authorized to collect the minted BETH coins
//   3. feeAmount:       The amount of BETH that can be collected by the proof submitter
//   4. revealAmount:    The amount of BETH to be minted upon proof submission to the receiverAddress
//
//      (NOTE: The remaining BETH amount is revealed as an encrypted coin,
//       which can be partially revealed later through the Spend circuit)
//
// The bound ensures that the burner can simply send their ETH to a derived address and
// delegate the responsibility of generating a proof and submitting it to the blockchain
// to the relayer, without the risk of the relayer taking all the BETH tokens for
// themselves or charging more fees than specified by the burner. However, it is better
// for the burner to generate the proof themselves; otherwise, the burner's identity will
// be leaked to the relayer.
//
// Attack scenarios when revealing the burnKey to a relayer and delegating proof creation:
//
//  - If we do not commit to the feeAmount: The proof generator may collect all tokens by 
//    arbitrarily setting the feeAmount to the maximum possible value.
//  - If we do not commit to the revealAmount: The proof generator may set the revealAmount 
//    to 0, then reveal and spend the encrypted coin themselves through the Spend circuit, 
//    since they possess the burnKey.
//    (WARNING: When proof creation is delegated to someone else, always set the revealAmount 
//     to the maximum intended amount. Otherwise, the proof generator will be able to spend 
//     the remaining amount for themselves, as they hold the burnKey!)
//
// Reviewers:
//   Keyvan: OK
//      (UPDATE 21st September 2025: Also committing to the reveal amount to prevent a potential attack scenario.)
//
template BurnAddress() {
    signal input burnKey;
    signal input receiverAddress;
    signal input feeAmount;
    signal input revealAmount; // NOTE : Added later because of an attack scenario
    signal output addressBytes[20];

    // Take the first 20-bytes of
    //   Poseidon5(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, receiverAddress, feeAmount, revealAmount) as a burn-address
    signal hash <== Poseidon(5)([POSEIDON_BURN_ADDRESS_PREFIX(), burnKey, receiverAddress, feeAmount, revealAmount]);
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
    signal input feeAmount;
    signal input revealAmount;
    signal output addressHashNibbles[64];

    // Calculate the address to which the burnt coins are sent
    signal addressBytes[20] <== BurnAddress()(burnKey, receiverAddress, feeAmount, revealAmount);

    // Feed the address-bytes in the big-endian form to keccak in order to take the 
    // address-hash which will be used as the key of the MPT leaf
    signal addressBytesBlock[136] <== Fit(20, 136)(addressBytes);
    signal addressHash[32] <== KeccakBytes(1)(addressBytesBlock, 20);

    // Convert the burn-address-hash to 64 4-bit nibbles
    addressHashNibbles <== Bytes2Nibbles(32)(addressHash);
}