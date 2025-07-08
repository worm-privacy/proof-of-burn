//   __        _____  ____  __  __ 
//   \ \      / / _ \|  _ \|  \/  |
//    \ \ /\ / / | | | |_) | |\/| |
//     \ V  V /| |_| |  _ <| |  | |
//      \_/\_/  \___/|_| \_\_|  |_|
//

pragma circom 2.2.2;

include "./utils/keccak.circom";
include "./utils/substring_check.circom";
include "./utils/concat.circom";
include "./utils/hasher.circom";
include "./utils/rlp.circom";
include "./utils/leaf.circom";
include "./utils/commit.circom";
include "./utils/proof_of_work.circom";
include "./utils/burn_address.circom";

// Proves that there exists an account in a certain Ethereum block's state root, with a `balance` amount of ETH,
// such that its address equals the first 20 bytes of MiMC7(burnKey, receiverAddress). This is achieved by revealing
// some publicly verifiable inputs through a *single* public input — the Keccak hash of 6 elements:
//
//   1. The `blockRoot`: the state root of the block being referenced, passed by a Solidity contract.
//   2. A `nullifier`: MiMC7(burnKey, 1), used to prevent revealing the same burn address more than once.
//   *** In the case of minting a 1:1 ERC-20 token in exchange for burnt ETH: ***
//   3. An encrypted representation of the remaining balance: MiMC7(burnKey, balance - fee - spend).
//   4. A `fee`: so that the proof submitter (not necessarily the burner) receives part of the minted ERC-20 tokens as compensation.
//   5. A `spend`: an amount from the minted balance that is directly withdrawn to the `receiverAddress`.
//   6. The `receiverAddress`: commits to the address authorized to receive the 1:1 tokens (otherwise, anyone could submit the proof and claim the tokens).
//
template ProofOfBurn(maxNumLayers, maxNodeBlocks, maxHeaderBlocks, minLeafAddressNibbles, amountBytes, powMinimumZeroBytes) {

    /***************************/
    /* START OF IN/OUT SIGNALS */
    /***************************/

    // Public commitment: Keccak(blockRoot, nullifier, encryptedBalance, fee, spend, receiverAddress)
    signal output commitment;

    signal input burnKey; // Secret field number from which the burn address and nullifier are derived.
    signal input balance; // Balance of the burn-address

    // In case there is a 1:1 token to be minted:
    signal input fee; // To be paid to the relayer who actually submits the proof
    signal input spend; // You can spend part of minted amount upon creation
    signal input receiverAddress; // The address which can receive the minted 1:1 token (160-bit number)
    // The rest of the balance (balance - spend - fee) is revealed as an encrypted-coin which can later be minted
    // through the spend.circom circuit

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

    /*************************/
    /* END OF IN/OUT SIGNALS */
    /*************************/

    assert(amountBytes <= 31);

    AssertBits(160)(receiverAddress); // Make sure receiver is a 160-bit number

    // Check if PoW has been done in order to find burnKey
    ProofOfWorkChecker(powMinimumZeroBytes)(burnKey);

    // At least `minLeafAddressNibbles` nibbles should be present in the leaf node
    AssertGreaterEqThan(16)(numLeafAddressNibbles, minLeafAddressNibbles);

    // fee, spend and (fee + spend) should be less than the amount being minted
    // (fee + spend) will NOT overflow since balance/fee/spend amounts are limited
    // to `amountBytes` bytes.
    AssertLessEqThan(amountBytes * 8)(fee, balance);
    AssertLessEqThan(amountBytes * 8)(spend, balance);
    AssertLessEqThan(amountBytes * 8)(fee + spend, balance);
    
    for(var i = 0; i < maxNumLayers; i++) {
        // Check layer lens are less than maximum length
        AssertLessThan(16)(layerLens[i], maxNodeBlocks * 136 * 8);
        AssertByteString(maxNodeBlocks * 136)(layers[i]);
    }
    // Check block-header len is less than maximum length
    AssertLessThan(16)(blockHeaderLen, maxHeaderBlocks * 136 * 8);
    AssertByteString(maxHeaderBlocks * 136)(blockHeader);

    // Calculate encrypted-balance
    signal encryptedBalance <== Hasher()(burnKey, balance - fee - spend);

    // Calculate nullifier
    signal nullifier <== Hasher()(burnKey, 1);

    // Calculate burn-address
    signal addressHashNibbles[64] <== BurnKeyAndReceiverToAddressHash()(burnKey, receiverAddress);
    signal addressHashBytes[32] <== NibblesToBytes(32)(addressHashNibbles);

    // Fetch stateRoot and stateRoot from block-header
    signal blockRoot[32] <== KeccakBytes(maxHeaderBlocks)(blockHeader, blockHeaderLen);
    signal stateRoot[32];
    for(var i = 0; i < 32; i++) {
        stateRoot[i] <== blockHeader[91 + i];
    }

    // Calculate public commitment
    signal nullifierBytes[32] <== FieldToBigEndianBytes()(nullifier);
    signal encryptedBalanceBytes[32] <== FieldToBigEndianBytes()(encryptedBalance);
    signal feeBytes[32] <== FieldToBigEndianBytes()(fee);
    signal spendBytes[32] <== FieldToBigEndianBytes()(spend);
    signal receiverAddressBytes[32] <== FieldToBigEndianBytes()(receiverAddress);
    commitment <== PublicCommitment(6)(
        [blockRoot, nullifierBytes, encryptedBalanceBytes, feeBytes, spendBytes, receiverAddressBytes]
    );
    
    // layers[numLayers - 1]
    signal lastLayer[maxNodeBlocks * 136] <== ArraySelector(
        maxNumLayers, maxNodeBlocks * 136)(layers, numLayers - 1);
    
    // layers[numLayer - 1]
    signal lastLayerLen <== Selector(maxNumLayers)(layerLens, numLayers - 1);

    // Calculate keccaks of all layers and check if the keccak of each
    // layer is substring of the upper layer
    signal existingLayer[maxNumLayers];
    signal substringCheckers[maxNumLayers - 1];
    signal layerKeccaks[maxNumLayers][32];
    signal reducedLayerKeccaks[maxNumLayers][31];

    for(var i = 0; i < maxNumLayers; i++) {
        // Layer exists if: i < numLayers
        existingLayer[i] <== LessThan(16)([i, numLayers]);

        // Calculate keccak of this layer
        layerKeccaks[i] <== KeccakBytes(maxNodeBlocks)(layers[i], layerLens[i]);

        // Ignore the last byte of keccak so that the bytes fit in a field element
        reducedLayerKeccaks[i] <== Fit(32, 31)(layerKeccaks[i]);

        if(i > 0) {
            substringCheckers[i - 1] <== SubstringCheck(maxNodeBlocks * 136, 31)(
                subInput <== reducedLayerKeccaks[i],
                mainLen <== layerLens[i - 1],
                mainInput <== layers[i - 1]
            );

            // Check substring-ness only when the layer exists
            // - When layer doesn't exist: (1 - substringChecker) *  0 === 0 (Correct)
            // - When layer exists: (1 - substringChecker) * 1 === 0 -> substringChecker === 1 (Correct)
            (1 - substringCheckers[i - 1]) * existingLayer[i] === 0;
        }
    }

    // Keccak of the top layer should be equal with the claimed state-root
    for(var i = 0; i < 32; i++) {
        layerKeccaks[0][i] === stateRoot[i];
    }

    // Calculate leaf-layer through address-hash and its balance
    signal (leafBytes[139], leafBytesLen) <== LeafCalculator(32, amountBytes)(
        addressHashNibbles, numLeafAddressNibbles, balance
    );
    
    // Make sure the calculated leaf-layer is equal with the last-layer
    for(var i = 0; i < 139; i++) {
        leafBytes[i] === lastLayer[i];
    }
    leafBytesLen === lastLayerLen;
}