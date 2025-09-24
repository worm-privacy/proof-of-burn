pragma circom 2.2.2;

include "../circomlib/circuits/poseidon.circom";
include "./convert.circom";
include "./array.circom";
include "./constants.circom";
include "./keccak.circom";
include "./assert.circom";

// The "EIP-7503" string
//
// Reviewers:
//   Keyvan: OK
//
template EIP7503() {
    signal output out[8];
    out[0] <== 69; // 'E'
    out[1] <== 73; // 'I'
    out[2] <== 80; // 'P'
    out[3] <== 45; // '-'
    out[4] <== 55; // '7'
    out[5] <== 53; // '5'
    out[6] <== 48; // '0'
    out[7] <== 51; // '3'
}

// Concat 4 fixed-size strings
//
// Reviewers:
//   Keyvan: OK
//
template ConcatFixed6(A, B, C, D, E, F) {
    signal input a[A];
    signal input b[B];
    signal input c[C];
    signal input d[D];
    signal input e[E];
    signal input f[F];
    signal output out[A + B + C + D + E + F];

    for(var i = 0; i < A; i++) {
        out[i] <== a[i];
    }
    for(var i = 0; i < B; i++) {
        out[i + A] <== b[i];
    }
    for(var i = 0; i < C; i++) {
        out[i + A + B] <== c[i];
    }
    for(var i = 0; i < D; i++) {
        out[i + A + B + C] <== d[i];
    }
    for(var i = 0; i < E; i++) {
        out[i + A + B + C + D] <== e[i];
    }
    for(var i = 0; i < E; i++) {
        out[i + A + B + C + D + E] <== f[i];
    }
}

// The burn-address is the first 20 bytes of:
//   Poseidon2(
//      POSEIDON_BURN_ADDRESS_PREFIX,
//      keccak(burnKey | receiverAddress | proverFeeAmount | broadcasterFeeAmount | revealAmount)
//   )
//
// (An extra Poseidon2 is applied on the keccak result because we're too paranoid)
//
// Proof-of-Work: Assert keccakPart < 2 ^ (256 - 8 * minimumZeroBytes)
//
// The burn-address is bound to:
//   1. burnKey:               A random salt from which a nullifier is derived
//   2. receiverAddress:      The address authorized to collect the minted BETH coins
//   3. proverFeeAmount:      The amount of BETH that can be collected by the proof generator
//   3. broadcasterFeeAmount: The amount of BETH that can be collected by the proof broadcaster
//   4. revealAmount:         The amount of BETH to be minted upon proof submission to the receiverAddress
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
// Reviewers:
//   Keyvan: OK
//
template ProofOfWorkChecker() {
    signal input burnKey;
    signal input receiverAddress;
    signal input proverFeeAmount;
    signal input broadcasterFeeAmount;
    signal input revealAmount;
    signal input minimumZeroBytes;
    signal output addressBytes[20];

    signal burnKeyBytes[32] <== Num2BigEndianBytes(32)(burnKey);
    signal receiverAddressBytes[20] <== Num2BigEndianBytes(20)(receiverAddress);
    signal proverFeeAmountBytes[32] <== Num2BigEndianBytes(32)(proverFeeAmount);
    signal broadcasterFeeAmountBytes[32] <== Num2BigEndianBytes(32)(broadcasterFeeAmount);
    signal revealAmountBytes[32] <== Num2BigEndianBytes(32)(revealAmount);
    signal eip7503[8] <== EIP7503()();

    var hasherInputLen = 32 + 20 + 32 + 32 + 32 + 8;
    signal hasherInput[hasherInputLen] <== ConcatFixed6(32, 20, 32, 32, 32, 8)(
        burnKeyBytes, receiverAddressBytes, proverFeeAmountBytes, broadcasterFeeAmountBytes, eip7503
    );

    signal burnKeyBlock[136] <== Fit(hasherInputLen, 136)(hasherInput);
    signal burnKeyKeccak[32] <== KeccakBytes(1)(burnKeyBlock, hasherInputLen);

    signal shouldBeZero[32] <== Filter(32)(minimumZeroBytes);

    // Assert the first powMinimumZeroBytes bytes of keccak is zero
    for(var i = 0; i < 32; i++) {
        // If shouldBeZero[i] is 1, then burnKeyKeccak[i] should be zero
        // Otherwise it can obtain any value
        burnKeyKeccak[i] * shouldBeZero[i] === 0;
    }

    signal reducedKeccakBytes[31] <== Fit(32, 31)(burnKeyKeccak);
    signal reducedKeccak <== BigEndianBytes2Num(31)(reducedKeccakBytes);
    signal hashedReducedKeccak <== Poseidon(2)([POSEIDON_BURN_ADDRESS_PREFIX(), reducedKeccak]);
    signal hashedReducedKeccakBytes[32] <== Num2BigEndianBytes(32)(hash);
    addressBytes <== Fit(32, 20)(hashedReducedKeccakBytes);
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
    signal input proverFeeAmount;
    signal input broadcasterFeeAmount;
    signal input revealAmount;
    signal input minimumZeroBytes; // For PoW check
    
    signal output addressHashNibbles[64];

    // Calculate the address to which the burnt coins are sent
    signal addressBytes[20] <== BurnAddress()(burnKey, receiverAddress, broadcasterFeeAmount, proverFeeAmount, revealAmount, minimumZeroBytes);

    // Feed the address-bytes in the big-endian form to keccak in order to take the 
    // address-hash which will be used as the key of the MPT leaf
    signal addressBytesBlock[136] <== Fit(20, 136)(addressBytes);
    signal addressHash[32] <== KeccakBytes(1)(addressBytesBlock, 20);

    // Convert the burn-address-hash to 64 4-bit nibbles
    addressHashNibbles <== Bytes2Nibbles(32)(addressHash);
}