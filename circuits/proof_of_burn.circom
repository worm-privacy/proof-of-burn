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
//   nullifier:        [256-bit input]
//   encryptedBalance: [256-bit input]
//   fee:              Field-element
//   receiverAddress:  Field-element
//   commitment: The resulting commitment after applying the hash and zeroing the last byte.
template InputsHasher() {
    signal input blockRoot[256];
    signal input nullifier[256];
    signal input encryptedBalance[256];
    signal input fee;
    signal input receiverAddress;

    signal output commitment;

    signal feeBits[256] <== FieldToBits()(fee);
    signal receiverAddressBits[256] <== FieldToBits()(receiverAddress);

    // Pack the inputs within a 136 byte keccak block
    signal keccakInputBits[2176];
    for(var i = 0; i < 256; i++) {
        keccakInputBits[i] <== blockRoot[i];
        keccakInputBits[256 + i] <== nullifier[i];
        keccakInputBits[512 + i] <== encryptedBalance[i];
        keccakInputBits[768 + i] <== feeBits[i];
        keccakInputBits[1024 + i] <== receiverAddressBits[i];
    }
    for(var i = 1280; i < 2176; i++) {
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

// Encrypts a balance by applying the MiMC hash function with a given burnKey as the salt. 
// The burnKey acts as a unique value that ensures different encrypted outputs for the same balance.
template EncryptBalance() {
    signal input burnKey;
    signal input balance;
    signal output encryptedBalance[256];

    signal hash <== Hasher()(burnKey, balance);
    encryptedBalance <== FieldToBits()(hash);
}

// Nullifier: MiMC(burnKey, 1)
template BurnKeyToNullifier() {
    signal input burnKey;
    signal output nullifier[256];

    signal hash <== Hasher()(burnKey, 1);
    nullifier <== FieldToBits()(hash);
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
    signal input fee; // To be paid to the relayer who actually submits the proof
    signal input balance; // Balance of the burn-address
    signal input layerBits[maxNumLayers][maxNodeBlocks * 136 * 8]; // MPT nodes in bits
    signal input layerBitsLens[maxNumLayers]; // Bit length of MPT nodes
    signal input numLayers; // Number of MPT nodes
    signal input blockHeader[maxHeaderBlocks * 136 * 8]; // Block header bits which should be hashed into blockRoot
    signal input blockHeaderLen; // Length of block header in bits
    signal input numLeafAddressNibbles; // Number of address nibbles in the leaf node
    signal input receiverAddress; // The address which can receive the minted burnt-token

    signal output commitment; // Public commitment: Keccak(blockRoot, nullifier, encryptedBalance)

    AssertBits(160)(receiverAddress); // Make sure receiver is a 160-bit number

    // Check if PoW has been done in order to find burnKey
    ProofOfWorkChecker(powMaxAllowedBits)(burnKey);

    // At least `minLeafAddressNibbles` nibbles should be present in the leaf node
    AssertGreaterEqThan(16)(numLeafAddressNibbles, minLeafAddressNibbles);

    // fee should be less than the amount being minted
    AssertLessEqThan(amountBytes * 8)(fee, balance);

    for(var i = 0; i < maxNumLayers; i++) {
        // Check layer lens are less than maximum length
        AssertLessThan(16)(layerBitsLens[i], maxNodeBlocks * 136 * 8);
        AssertBinary(maxNodeBlocks * 136 * 8)(layerBits[i]);
    }
    // Check block-header len is less than maximum length
    AssertLessThan(16)(blockHeaderLen, maxHeaderBlocks * 136 * 8);
    AssertBinary(maxHeaderBlocks * 136 * 8)(blockHeader);

    // Calculate encrypted-balance
    signal encryptedBalance[256] <== EncryptBalance()(burnKey, balance - fee);

    // Calculate nullifier
    signal nullifier[256] <== BurnKeyToNullifier()(burnKey);

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
    commitment <== InputsHasher()(blockRoot, nullifier, encryptedBalance, fee, receiverAddress);
    
    // Fetch the last layer (layerBits[numLayers - 1]) bits
    component lastLayerBitsSelectors[maxNodeBlocks * 136 * 8];
    for(var j = 0; j < maxNodeBlocks * 136 * 8; j++) {
        lastLayerBitsSelectors[j] = Selector(maxNumLayers);
        lastLayerBitsSelectors[j].select <== numLayers - 1;
    }
    for(var i = 0; i < maxNumLayers; i++) {
        for(var j = 0; j < 4 * 136 * 8; j++) {
            lastLayerBitsSelectors[j].vals[i] <== layerBits[i][j];
        }
    }

    // Fetch the last layer (layerBitsLens[numLayers - 1]) len
    component lastLayerLenSelector = Selector(maxNumLayers);
    lastLayerLenSelector.select <== numLayers - 1;
    for(var i = 0; i < maxNumLayers; i++) {
        lastLayerLenSelector.vals[i] <== layerBitsLens[i];
    }

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
        leafBits[i] === lastLayerBitsSelectors[i].out;
    }
    leafBitsLen === lastLayerLenSelector.out;
}