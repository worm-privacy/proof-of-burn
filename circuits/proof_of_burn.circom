//   __        _____  ____  __  __ 
//   \ \      / / _ \|  _ \|  \/  |
//    \ \ /\ / / | | | |_) | |\/| |
//     \ V  V /| |_| |  _ <| |  | |
//      \_/\_/  \___/|_| \_\_|  |_|
//

pragma circom 2.2.2;

include "./utils/keccak/keccak.circom";
include "./utils/substring_finder.circom";
include "./utils/concat.circom";
include "./utils/hasher.circom";
include "./utils/rlp.circom";
include "./utils/leaf.circom";


// Convert a field element to 256-bits
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
//   blockRoot: [256-bit input]
//   nullifier: [256-bit input]
//   encryptedBalance: [256-bit input]
//   fee:              [256-bit input]
//   commitment: The resulting commitment after applying the hash and zeroing the last byte.
template InputsHasher() {
    signal input blockRoot[256];
    signal input nullifier[256];
    signal input encryptedBalance[256];
    signal input fee;

    signal output commitment;

    signal feeBits[256] <== FieldToBits()(fee);

    // Pack the inputs within a 136 byte keccak block
    signal keccakInputBits[1088];
    for(var i = 0; i < 256; i++) {
        keccakInputBits[i] <== blockRoot[i];
        keccakInputBits[256 + i] <== nullifier[i];
        keccakInputBits[512 + i] <== encryptedBalance[i];
        keccakInputBits[768 + i] <== feeBits[i];
    }
    for(var i = 1024; i < 1088; i++) {
        keccakInputBits[i] <== 0;
    }
    
    signal hash[256] <== KeccakBits(1)(keccakInputBits, 1024);
    component bitsToNum = Bits2NumBigEndian(248);
    for(var i = 0; i < 248; i++) {
        bitsToNum.in[i] <== hash[i + 8];
    }
    commitment <== bitsToNum.out;
}

// Takes an entropy input and generates a burn address represented as 64 4-bit nibbles 
// using the MiMC hash function, creating a unique address hash.
//
// Example:
//   entropy: [A single field number]
//   addressHashNibbles: [64 nibbles, each 4 bits, resulting from MiMC(entropy, 0)
template EntropyToAddressHash() {
    signal input entropy;
    signal output addressHashNibbles[64];

    signal hash <== Hasher()(entropy, 0);
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

// Encrypts a balance by applying the MiMC hash function with a given entropy as the salt. 
// The entropy acts as a unique value that ensures different encrypted outputs for the same balance.
template EncryptBalance() {
    signal input entropy;
    signal input balance;
    signal output encryptedBalance[256];

    signal hash <== Hasher()(balance, entropy);
    encryptedBalance <== FieldToBits()(hash);
}

// Nullifier: MiMC(entropy, 1)
template EntropyToNullifier() {
    signal input entropy;
    signal output nullifier[256];

    signal hash <== Hasher()(entropy, 1);
    nullifier <== FieldToBits()(hash);
}


// Proof-of-Work: MiMC(entropy, 2) < 2^maxBits
template ProofOfWorkChecker(maxBits) {
    signal input entropy;
    signal hash <== Hasher()(entropy, 2);
    AssertBits(maxBits)(hash);
}

template ProofOfBurn(maxNumLayers, maxNodeBlocks, maxHeaderBlocks, minLeafAddressNibbles, amountBytes, powBits) {
    signal input entropy; // Secret field number from which the burn address and nullifier are derived.
    signal input fee; // To be paid to the relayer who actually submits the proof
    signal input balance; // Balance of the burn-address
    signal input layerBits[maxNumLayers][maxNodeBlocks * 136 * 8]; // MPT nodes in bits
    signal input layerBitsLens[maxNumLayers]; // Bit length of MPT nodes
    signal input numLayers; // Number of MPT nodes
    signal input blockHeader[maxHeaderBlocks * 136 * 8]; // Block header bits which should be hashed into blockRoot
    signal input blockHeaderLen; // Length of block header in bits
    signal input numLeafAddressNibbles; // Number of address nibbles in the leaf node

    signal output commitment; // Public commitment: Keccak(blockRoot, nullifier, encryptedBalance)

    // Check if PoW has been done in order to find entropy
    ProofOfWorkChecker(powBits)(entropy);

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
    signal encryptedBalance[256] <== EncryptBalance()(entropy, balance - fee);

    // Calculate nullifier
    signal nullifier[256] <== EntropyToNullifier()(entropy);

    // Calculate burn-address
    signal addressHashNibbles[64] <== EntropyToAddressHash()(entropy);
    signal addressHashBytes[32] <== NibblesToBytes(32)(addressHashNibbles);

    // Fetch stateRoot and stateRoot from block-header
    signal blockRoot[256] <== KeccakBits(maxHeaderBlocks)(blockHeader, blockHeaderLen);
    signal stateRoot[256];
    for(var i = 0; i < 256; i++) {
        stateRoot[i] <== blockHeader[91 * 8 + i];
    }

    // Calculate public commitment
    commitment <== InputsHasher()(blockRoot, nullifier, encryptedBalance, fee);
    
    // Fetch the last layer bits and len
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
    for(var i = 0; i < maxNumLayers; i++) {
        // Layer exists if: i < numLayers
        existingLayer[i] <== LessThan(16)([i, numLayers]);

        // Calculate keccak of this layer
        layerKeccaks[i] <== KeccakBits(maxNodeBlocks)(layerBits[i], layerBitsLens[i]);

        if(i > 0) {
            substringCheckers[i - 1] <== SubstringCheck(maxNodeBlocks * 136 * 8, 256)(
                subInput <== layerKeccaks[i],
                mainLen <== layerBitsLens[i - 1],
                mainInput <== layerBits[i - 1]
            );

            (1 - substringCheckers[i - 1]) * existingLayer[i] === 0;
        }
    }

    // Keccak of the top layer should be equal with the claimed state-root
    for(var i = 0; i < 256; i++) {
        layerKeccaks[0][i] === stateRoot[i];
    }

    // Calculate leaf-layer through address-hash and its balance
    component rlpBurn = LeafCalculator(33, amountBytes);
    (rlpBurn.key, rlpBurn.keyLen) <== LeafKey(32)(addressHashNibbles, 64 - numLeafAddressNibbles);
    rlpBurn.balance <== balance;
    rlpBurn.outLen === lastLayerLenSelector.out;
    
    // Make sure the calculated leaf-layer is equal with the last-layer
    for(var i = 0; i < 128 * 8; i++) {
        rlpBurn.out[i] === lastLayerBitsSelectors[i].out;
    }
}

component main {public [fee]} = ProofOfBurn(4, 4, 5, 20, 31, 250);