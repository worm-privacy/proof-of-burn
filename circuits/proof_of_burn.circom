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

// Proves that there is an account in a certain Ethereum block's state-root, containing `balance` amount of ETH,
// such that its address is equal with MiMC7(burnKey, receiverAddress), revealing some publicly verifiable inputs:
//   1. A `nullifier`: MiMC7(burnKey, 1) to
//   2. In case we are going to mint a 1:1 ERC-20 coin for the burnt ETH:
//     * A `fee` so that the proof-submitter (Which is not neccessarily the burner) gets part of the minted ERC-20 coin as a fee
//     * A `spend` so that the actual 
//     * An encrypted version of the rest of the balance: MiMC7(burnKey, balance - fee - spend)
//     * A `receiverAddress` to commit to the address which is allowed to received the 1:1 tokens (Otherwise anyone who submits the proof on the contract will be able to mint and get the 1:1 tokens for himself)
template ProofOfBurn(maxNumLayers, maxNodeBlocks, maxHeaderBlocks, minLeafAddressNibbles, amountBytes, powMaxAllowedBits) {
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
    //   1. keccak(layerBits[0]) === stateRoot
    //   2. layerBits[numLayers - 1] ===
    //        Rlp(
    //          addressHashNibbles[-numLeafAddressNibble:],
    //          Rlp(NONCE, balance, EMPTY_STORAGE_HASH, EMPTY_CODE_HASH)
    //        )
    signal input layerBits[maxNumLayers][maxNodeBlocks * 136 * 8]; // MPT nodes in bits
    signal input layerBitsLens[maxNumLayers]; // Bit length of MPT nodes
    signal input numLayers; // Number of MPT nodes

    // Block-header data where: keccak(blockHeader) == blockRoot
    signal input blockHeader[maxHeaderBlocks * 136 * 8]; // Block header bits which should be hashed into blockRoot
    signal input blockHeaderLen; // Length of block header in bits

     // Public commitment: Keccak(blockRoot, nullifier, encryptedBalance, fee, spend, receiverAddress)
    signal output commitment;

    assert(amountBytes <= 31);

    AssertBits(160)(receiverAddress); // Make sure receiver is a 160-bit number

    // Check if PoW has been done in order to find burnKey
    ProofOfWorkChecker(powMaxAllowedBits)(burnKey);

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
        AssertLessThan(16)(layerBitsLens[i], maxNodeBlocks * 136 * 8);
        AssertBinary(maxNodeBlocks * 136 * 8)(layerBits[i]);
    }
    // Check block-header len is less than maximum length
    AssertLessThan(16)(blockHeaderLen, maxHeaderBlocks * 136 * 8);
    AssertBinary(maxHeaderBlocks * 136 * 8)(blockHeader);

    // Calculate encrypted-balance
    signal encryptedBalance <== Hasher()(burnKey, balance - fee - spend);

    // Calculate nullifier
    signal nullifier <== Hasher()(burnKey, 1);

    // Calculate burn-address
    signal addressHashNibbles[64] <== BurnKeyAndReceiverToAddressHash()(burnKey, receiverAddress);
    signal addressHashBytes[32] <== NibblesToBytes(32)(addressHashNibbles);

    // Fetch stateRoot and stateRoot from block-header
    signal blockRoot[256] <== KeccakBits(maxHeaderBlocks)(blockHeader, blockHeaderLen);
    signal stateRoot[256];
    for(var i = 0; i < 256; i++) {
        stateRoot[i] <== blockHeader[91 * 8 + i];
    }

    // Calculate public commitment
    signal nullifierBits[256] <== FieldToBits()(nullifier);
    signal encryptedBalanceBits[256] <== FieldToBits()(encryptedBalance);
    signal feeBits[256] <== FieldToBits()(fee);
    signal spendBits[256] <== FieldToBits()(spend);
    signal receiverAddressBits[256] <== FieldToBits()(receiverAddress);
    commitment <== PublicCommitment(6)(
        [blockRoot, nullifierBits, encryptedBalanceBits, feeBits, spendBits, receiverAddressBits]
    );
    
    // layerBits[numLayers - 1]
    signal lastLayerBits[maxNodeBlocks * 136 * 8] <== ArraySelector(
        maxNumLayers, maxNodeBlocks * 136 * 8)(layerBits, numLayers - 1);
    
    // lastLayerBits[numLayer - 1]
    signal lastLayerLen <== Selector(maxNumLayers)(layerBitsLens, numLayers - 1);

    // Calculate keccaks of all layers and check if the keccak of each
    // layer is substring of the upper layer
    signal existingLayer[maxNumLayers];
    signal substringCheckers[maxNumLayers - 1];
    signal layerKeccaks[maxNumLayers][256];
    signal reducedLayerKeccaks[maxNumLayers][248];

    for(var i = 0; i < maxNumLayers; i++) {
        // Layer exists if: i < numLayers
        existingLayer[i] <== LessThan(16)([i, numLayers]);

        // Calculate keccak of this layer
        layerKeccaks[i] <== KeccakBits(maxNodeBlocks)(layerBits[i], layerBitsLens[i]);

        // Ignore the last byte of keccak so that the bits fit in a field element
        for(var j = 0; j < 248; j++) {
            reducedLayerKeccaks[i][j] <== layerKeccaks[i][j];
        }

        if(i > 0) {
            substringCheckers[i - 1] <== SubstringCheck(maxNodeBlocks * 136 * 8, 248)(
                subInput <== reducedLayerKeccaks[i],
                mainLen <== layerBitsLens[i - 1],
                mainInput <== layerBits[i - 1]
            );

            // Check substring-ness only when the layer exists
            // - When layer doesn't exist: (1 - substringChecker) *  0 === 0 (Correct)
            // - When layer exists: (1 - substringChecker) * 1 === 0 -> substringChecker === 1 (Correct)
            (1 - substringCheckers[i - 1]) * existingLayer[i] === 0;
        }
    }

    // Keccak of the top layer should be equal with the claimed state-root
    for(var i = 0; i < 256; i++) {
        layerKeccaks[0][i] === stateRoot[i];
    }

    // Calculate leaf-layer through address-hash and its balance
    signal (leafBits[1112], leafBitsLen) <== LeafCalculator(32, amountBytes)(
        addressHashNibbles, numLeafAddressNibbles, balance
    );
    
    // Make sure the calculated leaf-layer is equal with the last-layer
    for(var i = 0; i < 1112; i++) {
        leafBits[i] === lastLayerBits[i];
    }
    leafBitsLen === lastLayerLen;
}