pragma circom 2.1.5;

include "./utils/keccak/keccak.circom";
include "./utils/substring_finder.circom";
include "./utils/concat.circom";
include "./utils/hasher.circom";
include "./utils/rlp.circom";


template BitPad(maxBlocks, blockSize) {
    var maxBits = maxBlocks * blockSize;
    signal input in[maxBits];
    signal input ind;

    signal output out[maxBits];
    signal output num_blocks;

    component div = Divide(32);
    div.a <== ind + 1;
    div.b <== blockSize;
    num_blocks <== div.out + 1;

    signal eqs[maxBits+1];
    eqs[0] <== 1;
    component eqcomps[maxBits];
    for(var i = 0; i < maxBits; i++) {
        eqcomps[i] = IsEqual();
        eqcomps[i].in[0] <== i;
        eqcomps[i].in[1] <== ind;
        eqs[i+1] <== eqs[i] * (1 - eqcomps[i].out);
    }

    component isLast[maxBits];
    for(var i = 0; i < maxBits; i++) {
        isLast[i] = IsEqual();
        isLast[i].in[0] <== i;
        isLast[i].in[1] <== num_blocks * blockSize - 1;
        out[i] <== in[i] * eqs[i+1] + eqcomps[i].out + isLast[i].out;
    }
}

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
    component bitsToNum = Bits2NumBigendian(248);
    for(var i = 0; i < 248; i++) {
        bitsToNum.in[i] <== keccak.out[i + 8];
    }
    commitment <== bitsToNum.out;
}

template KeccakBits(maxBlocks) {
    signal input inBits[maxBlocks * 136 * 8];
    signal input inBitsLen;
    signal output out[256];

    component padder = BitPad(maxBlocks, 136 * 8);
    padder.in <== inBits;
    padder.ind <== inBitsLen;
    component keccak = Keccak(maxBlocks);
    keccak.in <== padder.out;
    keccak.blocks <== padder.num_blocks;
    out <== keccak.out;
}

template EntropyToAddressHash() {
    signal input entropy;
    signal output addressHashBytes[32];

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
        var bt = 0;
        for(var j = 0; j < 8; j++) {
            bt += addressHash.out[i*8 + j] * (2 ** j);
        }
        addressHashBytes[i] <== bt;
    }
}

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

template ProofOfBurn(maxNumLayers, maxBlocks) {
    signal input entropy; // Secret field-number, from which the burn-address and nullifier is derived
    signal input blockRoot[256]; // Accesible by blockhash() in Solidity
    signal input balance; // Balance of the burn-address
    signal input layerBits[maxNumLayers][maxBlocks * 136 * 8]; // MPT nodes in bits
    signal input layerBitsLens[maxNumLayers]; // Bit length of MPT nodes
    signal input numLayers; // Number of MPT nodes
    signal input blockHeader[5 * 136 * 8]; // Block header bits which should be hashed into blockRoot
    signal input blockHeaderLen; // Length of block header in bits
    signal input term[64]; // Leaf-node's key terminal
    signal input termLen; // Length of leaf-node's key terminal
    
    signal output commitment; // Public commitment: Keccak(blockRoot, nullifier, encryptedBalance)

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

    // Calculate public commitment
    component inpsHasher = InputsHasher();
    inpsHasher.blockRoot <== blockRoot;
    inpsHasher.nullifier <== nullifier;
    inpsHasher.encryptedBalance <== encryptedBalance;
    commitment <== inpsHasher.commitment;

    // Fetch stateRoot from block header
    signal stateRoot[256];
    component headerKeccak = KeccakBits(5);
    headerKeccak.inBits <== blockHeader;
    headerKeccak.inBitsLen <== blockHeaderLen;
    for(var i = 0; i < 256; i++) {
        blockRoot[i] === headerKeccak.out[i];
    }
    for(var i = 0; i < 256; i++) {
        stateRoot[i] <== blockHeader[91*8 + i];
    }
    
    component lastLayerBitsSelectors[maxBlocks * 136 * 8];
    for(var j = 0; j < maxBlocks*136*8; j++) {
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

        keccaks[i] = KeccakBits(maxBlocks);
        keccaks[i].inBits <== layerBits[i];
        keccaks[i].inBitsLen <== layerBitsLens[i];
        layerKeccaks[i] <== keccaks[i].out;

        if(i > 0) {
            substringCheckers[i-1] = SubstringCheck(maxBlocks * 136 * 8, 256);
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
    rlpBurn.term <== term;
    rlpBurn.term_len <== termLen;
    rlpBurn.balance <== balance;
    component termShift = Shift(64, 64);
    termShift.in <== term;
    termShift.count <== 64 - termLen;
    for(var i = 64 - 20; i < 64; i++) {
        termShift.out[i] === entropyToAddressHash.addressHashBytes[i-32];
    }

    rlpBurn.rlp_encoded_len === lastLayerLenSelector.out;
    for(var i = 0; i < 159 * 8; i++) {
        rlpBurn.rlp_encoded[i] === lastLayerBitsSelectors[i].out;
    }
}

component main = ProofOfBurn(4, 4);