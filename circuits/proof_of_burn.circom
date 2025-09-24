//   __        _____  ____  __  __ 
//   \ \      / / _ \|  _ \|  \/  |
//    \ \ /\ / / | | | |_) | |\/| |
//     \ V  V /| |_| |  _ <| |  | |
//      \_/\_/  \___/|_| \_\_|  |_|
//

pragma circom 2.2.2;

include "./circomlib/circuits/poseidon.circom";
include "./utils/keccak.circom";
include "./utils/substring_check.circom";
include "./utils/concat.circom";
include "./utils/rlp/merkle_patricia_trie_leaf.circom";
include "./utils/public_commitment.circom";
include "./utils/proof_of_work.circom";
include "./utils/burn_address.circom";
include "./utils/constants.circom";

// Proves that there exists an account in a certain Ethereum block's state root, with a `balance` amount of ETH,
// such that its address equals the first 20 bytes of:
//   Poseidon2(
//      POSEIDON_BURN_ADDRESS_PREFIX,
//      keccak(burnKey | receiverAddress | proverFeeAmount | broadcasterFeeAmount | revealAmount)
//   )
//
// This is achieved by revealing some publicly verifiable inputs through a *single* public input — the Keccak hash 
// of 8 elements:
//
//   1. The `blockRoot`: the state root of the block being referenced, passed by a Solidity contract.
//   2. A `nullifier`: Poseidon2(POSEIDON_NULLIFIER_PREFIX, burnKey), used to prevent revealing the same burn address more than once.
//   *** In the case of minting a 1:1 BETH token in exchange for burnt ETH: ***
//   3. An encrypted representation of the remaining balance: Poseidon3(POSEIDON_COIN_PREFIX, burnKey, balance - proverFeeAmount - broadcasterFeeAmount - revealAmount).
//   4. A `proverFeeAmount`: so that the process of proof generation can be delegated to someone else and he can collect part of the minted BETH as compensation.
//   5. A `broadcasterFeeAmount`: so that the broadcaster of mint tx (not necessarily the burner) receives part of the minted BETH tokens as compensation.
//   6. A `revealAmount`: an amount from the minted balance that is directly withdrawn to the `receiverAddress`.
//   7. The `receiverAddress`: commits to the address authorized to receive the 1:1 tokens (otherwise, anyone could submit the proof and claim the tokens).
//   8. Ad `_extraCommitment`: To glue more information to the proof (E.g the prover address) that do not necessarily need to be processed in the circuit.
//
template ProofOfBurn(maxNumLayers, maxNodeBlocks, maxHeaderBlocks, minLeafAddressNibbles, amountBytes, powMinimumZeroBytes, maxBalance) {

    /***************************/
    /* START OF IN/OUT SIGNALS */
    /***************************/

    // Public commitment:
    //   Keccak(
    //     blockRoot | nullifier | remainingCoin | proverFeeAmount | 
    //     broadcasterFeeAmount | revealAmount | receiverAddress |
    //     _extraCommitment
    //   )
    signal output commitment;

    signal input burnKey; // Secret field number from which the burn address and nullifier are derived.
    signal input balance; // Balance of the burn-address

    // In case there is a 1:1 token to be minted:
    signal input proverFeeAmount; // To be paid to the one who makes the ZK proof (Could be the burner himself)
    signal input broadcasterFeeAmount; // To be paid to the relayer who broadcasts the mint transaction (Could be the burner himself)
    signal input revealAmount; // You can reveal part of minted amount upon creation
    signal input receiverAddress; // The address which can receive the minted 1:1 BETH token (160-bit number)
    // The rest of the balance (balance - revealAmount - proverFeeAmount -broadcasterFeeAmount) is revealed as an encrypted-coin which 
    // can later be minted through the spend.circom circuit

    signal input numLeafAddressNibbles; // Number of address nibbles in the leaf node (< 64)

    // Merkle-Patricia-Trie nodes data where:
    //   1. keccak(layers[0]) === stateRoot
    //   2. layers[numLayers - 1] ===
    //        Rlp(
    //          addressHashNibbles[-numLeafAddressNibble:],
    //          Rlp(NONCE, balance, EMPTY_STORAGE_HASH, EMPTY_CODE_HASH)
    //        )
    signal input layers[maxNumLayers][maxNodeBlocks * 136]; // MPT nodes in bytes
    signal input layerLens[maxNumLayers]; // Byte length of MPT nodes
    signal input numLayers; // Number of MPT nodes

    // Block-header data where: keccak(blockHeader) == blockRoot
    signal input blockHeader[maxHeaderBlocks * 136]; // Block header bytes which should be hashed into blockRoot
    signal input blockHeaderLen; // Length of block header in bytes

    signal input byteSecurityRelax; // Relax the minLeafAddressNibbles by increasing PoW zero bytes

    signal input _extraCommitment; // Commit to some extra arbitrary input

    /*************************/
    /* END OF IN/OUT SIGNALS */
    /*************************/

    /******************************/
    /* START OF INPUT VALIDATIONS */
    /******************************/

    assert(amountBytes <= 31);

    AssertLessEqThan(amountBytes * 8)(balance, maxBalance);

    AssertBits(160)(receiverAddress); // Make sure receiver is a 160-bit number

    // At least `minLeafAddressNibbles` nibbles should be present in the leaf node
    // The prover can relax the security by doing more PoW
    AssertLessEqThan(16)(byteSecurityRelax * 2, minLeafAddressNibbles);
    AssertGreaterEqThan(16)(numLeafAddressNibbles, minLeafAddressNibbles - byteSecurityRelax * 2);

    // (proverFeeAmount + broadcasterFeeAmount + revealAmount) should be less than the amount being minted
    // (proverFeeAmount + broadcasterFeeAmount + revealAmount) will NOT overflow since balance, proverFeeAmount,
    // broadcasterFeeAmount/revealAmount amounts are limited
    // to `amountBytes` bytes which is <= 31.
    AssertBits(amountBytes * 8)(proverFeeAmount);
    AssertBits(amountBytes * 8)(broadcasterFeeAmount);
    AssertBits(amountBytes * 8)(revealAmount);
    AssertLessEqThan(amountBytes * 8)(proverFeeAmount + broadcasterFeeAmount + revealAmount, balance);
    
    for(var i = 0; i < maxNumLayers; i++) {
        // Check layer lens are less than maximum length
        AssertLessThan(16)(layerLens[i], maxNodeBlocks * 136 * 8);
        AssertByteString(maxNodeBlocks * 136)(layers[i]);
    }
    // Check block-header len is less than maximum length
    AssertLessThan(16)(blockHeaderLen, maxHeaderBlocks * 136 * 8);
    AssertByteString(maxHeaderBlocks * 136)(blockHeader);

    /****************************/
    /* END OF INPUT VALIDATIONS */
    /****************************/

    // Calculate encrypted-balance of the remaining-coin
    signal remainingCoin <== Poseidon(3)([
        POSEIDON_COIN_PREFIX(),
        burnKey,
        balance - proverFeeAmount - broadcasterFeeAmount - revealAmount
    ]);

    // Calculate nullifier
    signal nullifier <== Poseidon(2)([POSEIDON_NULLIFIER_PREFIX(), burnKey]);

    // Calculate keccak hash of a burn-address
    // Also check if PoW has been done in order to find burnKey
    //   - The user can increase the PoW zero-bytes through `byteSecurityRelax` and relax 
    //   - the minimum number of leaf-key bytes needed.
    signal addressHashNibbles[64] <== BurnAddressHash()(
        burnKey, receiverAddress, proverFeeAmount, broadcasterFeeAmount,
        revealAmount, powMinimumZeroBytes + byteSecurityRelax
    );

    // Calculate the block-root 
    signal blockRoot[32] <== KeccakBytes(maxHeaderBlocks)(blockHeader, blockHeaderLen);

    // Fetch the stateRoot from the block-header
    var stateRootOffset = 91; // stateRoot starts from byte 91 of the block-header
    signal stateRoot[32];
    for(var i = 0; i < 32; i++) {
        stateRoot[i] <== blockHeader[stateRootOffset + i];
    }

    // Calculate public commitment
    signal nullifierBytes[32] <== Num2BigEndianBytes(32)(nullifier);
    signal remainingCoinBytes[32] <== Num2BigEndianBytes(32)(remainingCoin);
    signal proverFeeAmountBytes[32] <== Num2BigEndianBytes(32)(proverFeeAmount);
    signal broadcasterFeeAmountBytes[32] <== Num2BigEndianBytes(32)(broadcasterFeeAmount);
    signal revealAmountBytes[32] <== Num2BigEndianBytes(32)(revealAmount);
    signal receiverAddressBytes[32] <== Num2BigEndianBytes(32)(receiverAddress);
    signal extraCommitmentBytes[32] <== Num2BigEndianBytes(32)(_extraCommitment);
    commitment <== PublicCommitment(8)(
        [blockRoot, nullifierBytes, remainingCoinBytes, proverFeeAmountBytes, broadcasterFeeAmountBytes, revealAmountBytes, receiverAddressBytes, extraCommitmentBytes]
    );
    
    // layers[numLayers - 1]
    signal lastLayer[maxNodeBlocks * 136] <== SelectorArray1D(
        maxNumLayers, maxNodeBlocks * 136)(layers, numLayers - 1);
    
    // layerLens[numLayer - 1]
    signal lastLayerLen <== Selector(maxNumLayers)(layerLens, numLayers - 1);

    // Calculate keccaks of all layers and check if the keccak of each
    // layer is substring of the upper layer
    signal layerExists[maxNumLayers] <== Filter(maxNumLayers)(numLayers); // layerExists[i] <== i < numLayers
    signal substringCheckers[maxNumLayers - 1];
    signal layerKeccaks[maxNumLayers][32];
    signal reducedLayerKeccaks[maxNumLayers][31];

    for(var i = 0; i < maxNumLayers; i++) {
        // Calculate keccak of this layer
        layerKeccaks[i] <== KeccakBytes(maxNodeBlocks)(layers[i], layerLens[i]);

        // Ignore the last byte of keccak so that the bytes fit in a field element
        reducedLayerKeccaks[i] <== Fit(32, 31)(layerKeccaks[i]);

        // Check if keccak(layers[i]) is substring of layers[i - 1]
        if(i > 0) {
            substringCheckers[i - 1] <== SubstringCheck(maxNodeBlocks * 136, 31)(
                subInput <== reducedLayerKeccaks[i],
                mainLen <== layerLens[i - 1],
                mainInput <== layers[i - 1]
            );

            // Check substring-ness only when the layer exists
            // - When layer doesn't exist: (1 - substringChecker) *  0 === 0 (Correct)
            // - When layer exists: (1 - substringChecker) * 1 === 0 -> substringChecker === 1 (Correct)
            (1 - substringCheckers[i - 1]) * layerExists[i] === 0;
        }
    }

    // Keccak of the top layer should be equal with the claimed state-root
    for(var i = 0; i < 32; i++) {
        layerKeccaks[0][i] === stateRoot[i];
    }

    var maxLeafLen = 139;

    // Calculate leaf-layer through address-hash and its balance
    signal (leaf[maxLeafLen], leafLen) <== RlpMerklePatriciaTrieLeaf(32, amountBytes)(
        addressHashNibbles, numLeafAddressNibbles, balance
    );
    
    // Make sure the calculated leaf-layer is equal with the last-layer
    for(var i = 0; i < maxLeafLen; i++) {
        leaf[i] === lastLayer[i];
    }
    leafLen === lastLayerLen;
}