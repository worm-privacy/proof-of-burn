//   __        _____  ____  __  __ 
//   \ \      / / _ \|  _ \|  \/  |
//    \ \ /\ / / | | | |_) | |\/| |
//     \ V  V /| |_| |  _ <| |  | |
//      \_/\_/  \___/|_| \_\_|  |_|
//

pragma circom 2.1.5;

include "./utils/keccak/keccak.circom";
include "./utils/substring_finder.circom";
include "./utils/concat.circom";
include "./utils/hasher.circom";
include "./utils/rlp.circom";
include "./utils/leaf.circom";


// Computes the Keccak hash of the concatenation of `blockhash()`, `nullifier`, and `encryptedBalance`, 
// and zeroes out the last byte of the hash to make it storeable in the field, returning it as a commitment.
//
// Example:
//   blockRoot: [256-bit input]
//   nullifier: [256-bit input]
//   encryptedBalance: [256-bit input]
//   commitment: The resulting commitment after applying the hash and zeroing the last byte.
template InputsHasher() {
    signal input blockRoot[256];
    signal input nullifier[256];
    signal input encryptedBalance[256];
    signal output commitment;

    // Pack the inputs within a 136 byte keccak block
    signal keccakInputBits[1088];
    for(var i = 0; i < 256; i++) {
        keccakInputBits[i] <== blockRoot[i];
        keccakInputBits[256 + i] <== nullifier[i];
        keccakInputBits[512 + i] <== encryptedBalance[i];
    }
    for(var i = 768; i < 1088; i++) {
        keccakInputBits[i] <== 0;
    }
    
    component keccak = KeccakBits(1);
    keccak.inBits <== keccakInputBits;
    keccak.inBitsLen <== 768;
    component bitsToNum = Bits2NumBigEndian(248);
    for(var i = 0; i < 248; i++) {
        bitsToNum.in[i] <== keccak.out[i + 8];
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

    component burnHasher = Hasher();
    burnHasher.left <== entropy;
    burnHasher.right <== 0;
    component encBurnToBits = Num2Bits_strict();
    encBurnToBits.in <== burnHasher.hash;
    component addressHash = KeccakBits(1);
    for(var i = 0; i < 20; i++) {
        for(var j = 0; j < 8; j++) {
            addressHash.inBits[8*(19-i)+j] <== encBurnToBits.out[8*i + j];
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
            lower += addressHash.out[i*8 + j] * (2 ** j);
            higher += addressHash.out[i*8 + j + 4] * (2 ** j);
        }
        addressHashNibbles[2 * i] <== higher;
        addressHashNibbles[2 * i + 1] <== lower;
    }
}

// Converts an array of nibbles (4-bit values) into an array of bytes (8-bit values).
// Each byte is formed by combining two nibbles (4 bits each).
//
// Example:
//   nibbles: [0x1, 0x2, 0x3, 0x4, 0x5, 0x6]
//   bytes: [0x12, 0x34, 0x56]
template NibblesToBytes(n) {
    signal input nibbles[2 * n];
    signal output bytes[n];
    for(var i = 0; i < n; i++) {
        bytes[i] <== nibbles[2 * i] * 16 + nibbles[2 * i + 1];
    }
}

// Encrypts a balance by applying the MiMC hash function with a given entropy as the salt. 
// The entropy acts as a unique value that ensures different encrypted outputs for the same balance.
template EncryptBalance() {
    signal input balance;
    signal input entropy;
    signal output encryptedBalance[256];

    component hasher = Hasher();
    hasher.left <== balance;
    hasher.right <== entropy;
    component encToBits = Num2Bits_strict();
    encToBits.in <== hasher.hash;
    for(var i = 0; i < 254; i++) {
        encryptedBalance[i] <== encToBits.out[i];
    }
    encryptedBalance[254] <== 0;
    encryptedBalance[255] <== 0;
}

template EntropyToNullifier() {
    signal input entropy;
    signal output nullifier[256];

    component hasher = Hasher();
    hasher.left <== entropy;
    hasher.right <== 1;
    component encToBits = Num2Bits_strict();
    encToBits.in <== hasher.hash;
    for(var i = 0; i < 254; i++) {
        nullifier[i] <== encToBits.out[i];
    }
    nullifier[254] <== 0;
    nullifier[255] <== 0;
}

template ProofOfBurn(maxNumLayers, maxNodeBlocks, maxHeaderBlocks) {
    signal input entropy; // Secret field-number, from which the burn-address and nullifier is derived
    signal input balance; // Balance of the burn-address
    signal input layerBits[maxNumLayers][maxNodeBlocks * 136 * 8]; // MPT nodes in bits
    signal input layerBitsLens[maxNumLayers]; // Bit length of MPT nodes
    signal input numLayers; // Number of MPT nodes
    signal input blockHeader[maxHeaderBlocks * 136 * 8]; // Block header bits which should be hashed into blockRoot
    signal input blockHeaderLen; // Length of block header in bits
    signal input numLeafAddressNibbles;
    
    signal output commitment; // Public commitment: Keccak(blockRoot, nullifier, encryptedBalance)

    component layerLenCheckers[maxNumLayers];
    for(var i = 0; i < maxNumLayers; i++) {
        // Check layer lens are less than maximum length
        layerLenCheckers[i] = LessThan(16);
        layerLenCheckers[i].in[0] <== layerBitsLens[i];
        layerLenCheckers[i].in[1] <== maxNodeBlocks * 136 * 8;
        layerLenCheckers[i].out === 1;

        // Check layer bits are binary
        for(var j = 0; j < maxNodeBlocks * 136 * 8; j++) {
            layerBits[i][j] * (1 - layerBits[i][j]) === 0;
        }
    }
    // Check block-header len is less than maximum length
    component blockHeaderLenChecker = LessThan(16);
    blockHeaderLenChecker.in[0] <== blockHeaderLen;
    blockHeaderLenChecker.in[1] <== maxHeaderBlocks * 136 * 8;
    blockHeaderLenChecker.out === 1;

    // Check block-header bits are binary
    for(var j = 0; j < maxHeaderBlocks * 136 * 8; j++) {
        blockHeader[j] * (1 - blockHeader[j]) === 0;
    }


    // Calculate encrypted-balance
    signal encryptedBalance[256];
    component balanceEnc = EncryptBalance();
    balanceEnc.entropy <== entropy;
    balanceEnc.balance <== balance;
    encryptedBalance <== balanceEnc.encryptedBalance;

    // Calculate nullifier
    signal nullifier[256];
    component entToNul = EntropyToNullifier();
    entToNul.entropy <== entropy;
    nullifier <== entToNul.nullifier;

    // Calculate burn-address
    component entropyToAddressHash = EntropyToAddressHash();
    entropyToAddressHash.entropy <== entropy;
    component addressHash = NibblesToBytes(32);
    addressHash.nibbles <== entropyToAddressHash.addressHashNibbles;

    component termer = LeafKey(64);
    termer.address <== entropyToAddressHash.addressHashNibbles;
    termer.count <== 64 - numLeafAddressNibbles;
    component termBytes = NibblesToBytes(33);
    termBytes.nibbles <== termer.out;
    signal termBytesLen;
    component halver = Divide(16);
    halver.a <== termer.outLen;
    halver.b <== 2;
    halver.rem === 0;
    termBytesLen <== halver.out;

    // Fetch stateRoot and stateRoot from block-header
    signal blockRoot[256];
    signal stateRoot[256];
    component headerKeccak = KeccakBits(maxHeaderBlocks);
    headerKeccak.inBits <== blockHeader;
    headerKeccak.inBitsLen <== blockHeaderLen;
    for(var i = 0; i < 256; i++) {
        blockRoot[i] <== headerKeccak.out[i];
    }
    for(var i = 0; i < 256; i++) {
        stateRoot[i] <== blockHeader[91 * 8 + i];
    }

    // Calculate public commitment
    component inpsHasher = InputsHasher();
    inpsHasher.blockRoot <== blockRoot;
    inpsHasher.nullifier <== nullifier;
    inpsHasher.encryptedBalance <== encryptedBalance;
    commitment <== inpsHasher.commitment;
    
    component lastLayerBitsSelectors[maxNodeBlocks * 136 * 8];
    for(var j = 0; j < maxNodeBlocks*136*8; j++) {
        lastLayerBitsSelectors[j] = Selector(maxNumLayers);
        lastLayerBitsSelectors[j].select <== numLayers - 1;
    }
    component lastLayerLenSelector = Selector(maxNumLayers);
    lastLayerLenSelector.select <== numLayers - 1;

    component keccaks[maxNumLayers];
    signal isValidLayer[maxNumLayers + 1];
    isValidLayer[0] <== 1;
    component existingLayer[maxNumLayers];
    component substringCheckers[maxNumLayers - 1];
    signal layerKeccaks[maxNumLayers][256];
    
    for(var i = 0; i < maxNumLayers; i++) {
        // Layer exists if: i < numLayers
        existingLayer[i] = LessThan(16);
        existingLayer[i].in[0] <== i;
        existingLayer[i].in[1] <== numLayers;

        keccaks[i] = KeccakBits(maxNodeBlocks);
        keccaks[i].inBits <== layerBits[i];
        keccaks[i].inBitsLen <== layerBitsLens[i];
        layerKeccaks[i] <== keccaks[i].out;

        if(i > 0) {
            substringCheckers[i-1] = SubstringCheck(maxNodeBlocks * 136 * 8, 256);
            substringCheckers[i-1].subInput <== layerKeccaks[i];
            substringCheckers[i-1].mainLen <== layerBitsLens[i - 1];
            substringCheckers[i-1].mainInput <== layerBits[i - 1];
            
            substringCheckers[i-1].out === existingLayer[i-1].out;
        }
        
        for(var j = 0; j < 4*136*8; j++) {
            lastLayerBitsSelectors[j].vals[i] <== layerBits[i][j];
        }
        lastLayerLenSelector.vals[i] <== layerBitsLens[i];
    }

    for(var i = 0; i < 256; i++) {
        layerKeccaks[0][i] === stateRoot[i];
    }

    
    component rlpBurn = LeafCalculator();
    rlpBurn.term <== termBytes.bytes;
    rlpBurn.term_len <== termBytesLen;
    rlpBurn.balance <== balance;
    rlpBurn.rlp_encoded_len === lastLayerLenSelector.out;
    for(var i = 0; i < 128 * 8; i++) {
        rlpBurn.rlp_encoded[i] === lastLayerBitsSelectors[i].out;
    }
}

component main = ProofOfBurn(4, 4, 5);