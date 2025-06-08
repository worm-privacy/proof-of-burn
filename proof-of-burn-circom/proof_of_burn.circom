pragma circom 2.1.5;

include "./utils/keccak/keccak.circom";
include "./utils/substring_finder.circom";
include "./utils/hasher.circom";
include "./utils/padding.circom";
include "./utils/hashbytes.circom";
include "./utils/concat.circom";
include "./utils/rlp.circom";

template BitPad(maxBlocks, blockSize) {
    var maxBits = maxBlocks * blockSize;
    signal input in[maxBits];
    signal input ind;

    signal output out[maxBits];
    signal output num_blocks;

    component div = Divide();
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

template LeafHasher() {
    signal input balance;
    signal output hash[32 * 8];

}

template ProofOfBurn(maxNumLayers, maxBlocks) {
    signal input blockRoot[256];
    signal input nullifier[256];
    signal input encryptedBalance[256];
    signal output commitment;
    component inpsHasher = InputsHasher();
    inpsHasher.blockRoot <== blockRoot;
    inpsHasher.nullifier <== nullifier;
    inpsHasher.encryptedBalance <== encryptedBalance;
    commitment <== inpsHasher.commitment;

    signal input blockHeader[5 * 136 * 8];
    signal input blockHeaderLen;

    component headerKeccak = KeccakBits(5);
    headerKeccak.inBits <== blockHeader;
    headerKeccak.inBitsLen <== blockHeaderLen;
    for(var i =0;i<256;i++) {
        blockRoot[i] === headerKeccak.out[i];
    }

    signal stateRoot[256];
    for(var i =0;i<256;i++) {
        stateRoot[i] <== blockHeader[91*8 + i];
    }
    
    signal input layerBits[maxNumLayers][maxBlocks * 136 * 8];
    signal input layerBitsLens[maxNumLayers];

    component keccaks[maxNumLayers];
    signal layerKeccaks[maxNumLayers][256];
    for(var i = 0; i < maxNumLayers; i++) {
        keccaks[i] = KeccakBits(maxBlocks);
        keccaks[i].inBits <== layerBits[i];
        keccaks[i].inBitsLen <== layerBitsLens[i];
        layerKeccaks[i] <== keccaks[i].out;
    }

    for(var i = 0; i < 256; i++) {
        layerKeccaks[0][i] === stateRoot[i];
    }
}

component main = ProofOfBurn(10, 4);