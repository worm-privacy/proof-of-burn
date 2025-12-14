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
//   Poseidon4(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, revealAmount, burnExtraCommitment).
// This is achieved by revealing some publicly verifiable inputs through a *single* public input — the Keccak hash 
// of 8 elements:
//
//   1. The `blockRoot`: the state root of the block being referenced, passed by a Solidity contract.
//   2. A `nullifier`: Poseidon2(POSEIDON_NULLIFIER_PREFIX, burnKey), used to prevent revealing the same burn address more than once.
//   *** In the case of minting a 1:1 BETH token in exchange for burnt ETH: ***
//   3. An encrypted representation of the remaining balance: Poseidon3(POSEIDON_COIN_PREFIX, burnKey, intendedBalance - revealAmount).
//   4. A `revealAmount`: an amount from the minted balance that is directly revealed upon submission of the proof.
//   5. A `burnExtraCommitment`: commits to the way the revealed amount should be distributed by the contract. (E.g the amounts of prover and broadcaster fees)
//   6. A `_proofExtraCommitment`: to glue information to the proof that aren't necessarily processed in the circuit. (E.g prover address)
//
template ProofOfBurn(maxNumLayers, maxNodeBlocks, maxHeaderBlocks, minLeafAddressNibbles, amountBytes, powMinimumZeroBytes, maxIntendedBalance, maxActualBalance) {

    /***************************/
    /* START OF IN/OUT SIGNALS */
    /***************************/
    
    // Public commitment: Keccak(blockRoot, nullifier, remainingCoin, revealAmount, burnExtraCommitment, proofExtraCommitment)
    signal output commitment;

    signal input burnKey; // Secret field number from which the burn address and nullifier are derived.
    signal input actualBalance; // Actual balance of the burn-address (May contain dust coming from attackers)
    signal input intendedBalance; // Intended balance of the burn-address (Without dust)

    // In case there is a 1:1 token to be minted:
    signal input revealAmount; // You can reveal part of minted amount upon creation
    signal input burnExtraCommitment; // Commit to the way revealAmount is distributed by the contract through a commitment
    // The rest of the balance (intendedBalance - revealAmount) is revealed as 
    // an encrypted-coin which can later be minted through the spend.circom circuit

    signal input numLeafAddressNibbles; // Number of address nibbles in the leaf node (< 64)

    // Merkle-Patricia-Trie nodes data where:
    //   1. keccak(layers[0]) === stateRoot
    //   2. layers[numLayers - 1] ===
    //        Rlp(
    //          addressHashNibbles[-numLeafAddressNibble:],
    //          Rlp(NONCE, actualBalance, EMPTY_STORAGE_HASH, EMPTY_CODE_HASH)
    //        )
    signal input layers[maxNumLayers][maxNodeBlocks * 136]; // MPT nodes in bytes
    signal input layerLens[maxNumLayers]; // Byte length of MPT nodes
    signal input numLayers; // Number of MPT nodes

    // Block-header data where: keccak(blockHeader) == blockRoot
    signal input blockHeader[maxHeaderBlocks * 136]; // Block header bytes which should be hashed into blockRoot
    signal input blockHeaderLen; // Length of block header in bytes

    signal input byteSecurityRelax; // Relax the minLeafAddressNibbles by increasing PoW zero bytes

    signal input _proofExtraCommitment; // Commit to some extra arbitrary input

    /*************************/
    /* END OF IN/OUT SIGNALS */
    /*************************/

    /******************************/
    /* START OF INPUT VALIDATIONS */
    /******************************/

    assert(amountBytes <= 31);

    AssertLessEqThan(amountBytes * 8)(intendedBalance, maxIntendedBalance);
    AssertLessEqThan(amountBytes * 8)(actualBalance, maxActualBalance);
    AssertLessEqThan(amountBytes * 8)(intendedBalance, actualBalance);

    // At least `minLeafAddressNibbles` nibbles should be present in the leaf node
    // The prover can relax the security by doing more PoW
    AssertLessEqThan(16)(byteSecurityRelax * 2, minLeafAddressNibbles);
    AssertGreaterEqThan(16)(numLeafAddressNibbles, minLeafAddressNibbles - byteSecurityRelax * 2);

    // revealAmount should be less than the amount being minted
    // revealAmount will NOT overflow since intendedBalance/revealAmount 
    // amounts are limited to `amountBytes` bytes which is <= 31.
    AssertBits(amountBytes * 8)(revealAmount);
    AssertLessEqThan(amountBytes * 8)(revealAmount, intendedBalance);
    
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
    signal remainingCoin <== Poseidon(3)([POSEIDON_COIN_PREFIX(), burnKey, intendedBalance - revealAmount]);

    // Calculate nullifier
    signal nullifier <== Poseidon(2)([POSEIDON_NULLIFIER_PREFIX(), burnKey]);

    // Calculate keccak hash of a burn-address
    signal addressHashNibbles[64] <== BurnAddressHash()(burnKey, revealAmount, burnExtraCommitment);

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
    signal revealAmountBytes[32] <== Num2BigEndianBytes(32)(revealAmount);
    signal burnExtraCommitmentBytes[32] <== Num2BigEndianBytes(32)(burnExtraCommitment);
    signal extraCommitmentBytes[32] <== Num2BigEndianBytes(32)(_proofExtraCommitment);
    commitment <== PublicCommitment(6)(
        [blockRoot, nullifierBytes, remainingCoinBytes, revealAmountBytes, burnExtraCommitmentBytes, extraCommitmentBytes]
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
    signal isLeaf[maxNumLayers];

    var numDetectedLeaves = 0;
    for(var i = 0; i < maxNumLayers; i++) {
        // Check if layers[i] is a MPT leaf
        isLeaf[i] <== LeafDetector(maxNodeBlocks * 136)(layers[i], layerLens[i]);
        numDetectedLeaves += isLeaf[i];

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

    // Only the last layer of the trie proof should look like a leaf! Otherwise
    // attackers may fake proofs by putting arbitrary strings in codeHash/storageHash
    // fields of an account.
    numDetectedLeaves === 1;
    signal isLastLayerLeaf <== LeafDetector(maxNodeBlocks * 136)(lastLayer, lastLayerLen);
    isLastLayerLeaf === 1;

    // Keccak of the top layer should be equal with the claimed state-root
    for(var i = 0; i < 32; i++) {
        layerKeccaks[0][i] === stateRoot[i];
    }

    var maxLeafLen = 139;

    // Calculate leaf-layer through address-hash and its balance
    signal (leaf[maxLeafLen], leafLen) <== RlpMerklePatriciaTrieLeaf(32, amountBytes)(
        addressHashNibbles, numLeafAddressNibbles, actualBalance
    );
    
    // Make sure the calculated leaf-layer is equal with the last-layer
    for(var i = 0; i < maxLeafLen; i++) {
        leaf[i] === lastLayer[i];
    }
    leafLen === lastLayerLen;

    // Check if PoW has been done in order to find burnKey
    // The user can increase the PoW zero-bytes through `byteSecurityRelax` and relax 
    // the minimum number of leaf-key bytes needed.
    ProofOfWorkChecker()(burnKey, revealAmount, burnExtraCommitment, powMinimumZeroBytes + byteSecurityRelax);
}