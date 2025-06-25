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


// Convert a field element to 256-bits
//
// Reviewers:
//   Keyvan: OK
//
template FieldToBits() {
    signal input in;
    signal output out[256];

    signal bitsStrict[254] <== Num2Bits_strict()(in);
    for(var i = 0; i < 254; i++) out[i] <== bitsStrict[i];
    out[254] <== 0;
    out[255] <== 0;
}

// Computes the Keccak hash of the concatenation of `blockhash()`, `nullifier`, and `encryptedBalance`, 
// and zeroes out the last byte of the hash to make it storeable in the field, returning it as a commitment.
//
// Example:
//   blockRoot:        [256-bit input]
//   nullifier:        Field-element
//   encryptedBalance: Field-element
//   fee:              Field-element
//   receiverAddress:  Field-element
//   commitment: The resulting commitment after applying the hash and zeroing the last byte.
template InputsHasher() {
    signal input blockRoot[256];
    signal input nullifier;
    signal input encryptedBalance;
    signal input fee;
    signal input spend;
    signal input receiverAddress;

    signal output commitment;

    signal nullifierBits[256] <== FieldToBits()(nullifier);
    signal encryptedBalanceBits[256] <== FieldToBits()(encryptedBalance);
    signal feeBits[256] <== FieldToBits()(fee);
    signal spendBits[256] <== FieldToBits()(spend);
    signal receiverAddressBits[256] <== FieldToBits()(receiverAddress);

    // Pack the inputs within a 272 byte keccak block
    signal keccakInputBits[2176];
    for(var i = 0; i < 256; i++) {
        keccakInputBits[i] <== blockRoot[i];
        keccakInputBits[256 + i] <== nullifierBits[i];
        keccakInputBits[512 + i] <== encryptedBalanceBits[i];
        keccakInputBits[768 + i] <== feeBits[i];
        keccakInputBits[1024 + i] <== spendBits[i];
        keccakInputBits[1280 + i] <== receiverAddressBits[i];
    }
    for(var i = 1536; i < 2176; i++) {
        keccakInputBits[i] <== 0;
    }
    
    signal hash[256] <== KeccakBits(2)(keccakInputBits, 1280);

    // Ignore the last byte while converting keccak to field element
    component bitsToNum = Bits2NumBigEndian(31);
    for(var i = 0; i < 31 * 8; i++) {
        bitsToNum.in[i] <== hash[i + 8];
    }
    commitment <== bitsToNum.out;
}

// Takes an burnKey input and generates a burn address represented as 64 4-bit nibbles 
// using the MiMC hash function, creating a unique address hash.
//
// Example:
//   burnKey: [A single field number]
//   addressHashNibbles: [64 nibbles, each 4 bits, resulting from MiMC(burnKey, 0)
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


// Proof-of-Work: MiMC(burnKey, 2) < 2^maxBits
//
// Reviewers:
//   Keyvan: OK
//
template ProofOfWorkChecker(powMaxAllowedBits) {
    signal input burnKey;
    signal hash <== Hasher()(burnKey, 2);
    AssertBits(powMaxAllowedBits)(hash);
}

template ProofOfBurn(maxNumLayers, maxNodeBlocks, maxHeaderBlocks, minLeafAddressNibbles, amountBytes, powMaxAllowedBits) {
    signal input burnKey; // Secret field number from which the burn address and nullifier are derived.
    signal input balance; // Balance of the burn-address
    signal input fee; // To be paid to the relayer who actually submits the proof
    signal input spend; // You can spend part of minted amount upon creation
    signal input numLeafAddressNibbles; // Number of address nibbles in the leaf node
    signal input receiverAddress; // The address which can receive the minted burnt-token

    // Merkle-Patricia-Trie nodes data
    signal input layerBits[maxNumLayers][maxNodeBlocks * 136 * 8]; // MPT nodes in bits
    signal input layerBitsLens[maxNumLayers]; // Bit length of MPT nodes
    signal input numLayers; // Number of MPT nodes

    // Block-header data
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
    commitment <== InputsHasher()(blockRoot, nullifier, encryptedBalance, fee, spend, receiverAddress);
    
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