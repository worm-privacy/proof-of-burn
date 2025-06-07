pragma circom 2.1.5;

include "./utils/keccak/keccak.circom";
include "./utils/substring_finder.circom";
include "./utils/hasher.circom";
include "./utils/padding.circom";
include "./utils/hashbytes.circom";
include "./utils/concat.circom";
include "./utils/rlp.circom";

template InputsHasher() {
    signal input blockRoot[32];
    signal input nullifier[32];
    signal input encryptedBalance[32];
    signal output commitment;

    // Pack the inputs within a 136 byte keccak block
    signal keccakInputBytes[136];
    for(var i = 0; i < 32; i++) {
        keccakInputBytes[i] <== blockRoot[i];
        keccakInputBytes[32 + i] <== nullifier[i];
        keccakInputBytes[64 + i] <== encryptedBalance[i];
    }
    // Padding
    keccakInputBytes[96] <== 0x80;
    for(var i = 97; i < 135; i++) keccakInputBytes[i] <== 0;
    keccakInputBytes[135] <== 0x01;

    component bytesToBits = BytesToBits(136);
    bytesToBits.bytes <== keccakInputBytes;
    component keccak = Keccak(1);
    keccak.in <== bytesToBits.bits;
    keccak.blocks <== 1;
    component bitsToNum = Bits2Num(256);
    bitsToNum.in <== keccak.out;
    commitment <== bitsToNum.out;
}

template LeafHasher() {
    signal input balance;
    signal output hash[32 * 8];

}

template ProofOfBurn(maxNumLayers, maxBlocks) {
    signal input blockRoot[32];
    signal input nullifier[32];
    signal input encryptedBalance[32];
    signal output commitment;
    component inpsHasher = InputsHasher();
    inpsHasher.blockRoot <== blockRoot;
    inpsHasher.nullifier <== nullifier;
    inpsHasher.encryptedBalance <== encryptedBalance;
    commitment <== inpsHasher.commitment;

    signal input layerBits[maxNumLayers][maxBlocks * 136 * 8];
    signal input layerBlockCounts[maxNumLayers];

    component keccaks[maxNumLayers];
    signal layerKeccaks[maxNumLayers][32 * 8];
    for(var i = 0; i < maxNumLayers; i++) {
        keccaks[i] = Keccak(maxBlocks);
        keccaks[i].in <== layerBits[i];
        keccaks[i].blocks <== layerBlockCounts[i];
        layerKeccaks[i] <== keccaks[i].out;
    }

    component accountRlp = Rlp();
    accountRlp.balance <== 1234;
}

component main = ProofOfBurn(1, 4);