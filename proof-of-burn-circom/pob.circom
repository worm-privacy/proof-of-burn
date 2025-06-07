pragma circom 2.1.5;

include "./utils/keccak/keccak.circom";
include "./utils/substring_finder.circom";
include "./utils/hasher.circom";
include "./utils/padding.circom";
include "./utils/hashbytes.circom";
include "./utils/concat.circom";
include "./utils/rlp.circom";

template HashAddress() {
    signal input address[20];
    signal output hash_address[32];

    component addr_decomp[20];
    signal hashed_address_bits[32 * 8];
    signal keccak_input[136 * 8];
    for(var i = 0; i < 136; i++) {
        if(i < 20) {
            addr_decomp[i] = BitDecompose(8);
            addr_decomp[i].num <== address[i];
            for(var j = 0; j < 8; j++) {
                keccak_input[8 * i + j] <== addr_decomp[i].bits[j];
            }
        } else {
            if(i == 20) {
                for(var j = 0; j < 8; j++) {
                    keccak_input[8 * i + j] <== (0x01 >> j) & 1;
                }
            } else if(i == 135) {
                for(var j = 0; j < 8; j++) {
                    keccak_input[8 * i + j] <== (0x80 >> j) & 1;
                }
            } else {
                for(var j = 0; j < 8; j++) {
                    keccak_input[8 * i + j] <== 0;
                }
            }
        }
    }
    component keccak = Keccak(1);
    keccak.in <== keccak_input;
    keccak.blocks <== 1;
    hashed_address_bits <== keccak.out;
    for(var i = 0; i < 32; i++) {
        var sum = 0;
        for(var j = 0; j < 8; j++) {
            sum += (2 ** j) * hashed_address_bits[i * 8 + j];
        }
        hash_address[i] <== sum;
    }
}

template LowerInUpperChecker(maxBlocks) {
    signal input lowerBytes[maxBlocks * 136];
    signal input lowerLen;
    signal input upperBytes[maxBlocks * 136];
    signal input upperLen;

    signal lowerBits[maxBlocks * 136 * 8];
    signal lowerBlocks;
    signal upperBits[maxBlocks * 136 * 8];
    signal upperBlocks;

    component padderLower = Padding(maxBlocks, 136);
    component lowerToBits = BytesToBits(maxBlocks * 136);
    padderLower.a <== lowerBytes;
    padderLower.aLen <== lowerLen;
    lowerToBits.bytes <== padderLower.out;
    lowerBits <== lowerToBits.bits;
    lowerBlocks <== padderLower.num_blocks;

    component padderUpper = Padding(maxBlocks, 136);
    component upperToBits = BytesToBits(maxBlocks * 136);
    padderUpper.a <== upperBytes;
    padderUpper.aLen <== upperLen;
    upperToBits.bytes <== padderUpper.out;
    upperBits <== upperToBits.bits;
    upperBlocks <== padderUpper.num_blocks;
    

    component keccak = Keccak(maxBlocks);
    keccak.in <== lowerBits;
    keccak.blocks <== lowerBlocks;

    // Check if keccak(lowerLayer) is in upperLayer
    component substringChecker = substringCheck(maxBlocks, 136 * 8, 32 * 8);
    substringChecker.subInput <== keccak.out;
    substringChecker.numBlocks <== upperBlocks;
    substringChecker.mainInput <== upperBits;
}

template ProofOfBurn(maxNumLayers, maxBlocks) {
    signal input burn_preimage;
    component burn_hasher = Hasher();
    burn_hasher.left <== burn_preimage;
    burn_hasher.right <== burn_preimage;
    component burn_bits = Num2Bits_strict();
    burn_bits.in <== burn_hasher.hash;

    signal address[20];
    component byter[20];
    for(var i = 0; i < 20; i++) {
        byter[i] = Bits2Num(8);
        for(var j = 0; j < 8; j++) {
            byter[i].in[j] <== burn_bits.out[8*i+j];
        }
        address[i] <== byter[i].out;
    }
    
    signal input lowerLayerPrefixLen;
    signal input lowerLayerPrefix[136 * maxBlocks - 99];
    signal input salt;

    signal input nonce;
    signal input balance;
    signal input storageHash[32];
    signal input codeHash[32];

    signal output state_root;
    signal output nullifier;
    signal output encryptedBalance;

    component nullifier_calc = Hasher();
    nullifier_calc.left <== burn_preimage;
    nullifier_calc.right <== 0;
    nullifier <== nullifier_calc.hash;

    component balanceEnc = Hasher();
    balanceEnc.left <== balance;
    balanceEnc.right <== salt;
    encryptedBalance <== balanceEnc.hash;

    component account_rlp_calculator = Rlp();
    account_rlp_calculator.nonce <== nonce;
    account_rlp_calculator.balance <== balance;
    account_rlp_calculator.storage_hash <== storageHash;
    account_rlp_calculator.code_hash <== codeHash;

    signal lowerLayerLen;
    signal lowerLayer[99];

    lowerLayerLen <== account_rlp_calculator.rlp_encoded_len;
    lowerLayer <== account_rlp_calculator.rlp_encoded;

    signal hash_address[32];
    component addr_hasher = HashAddress();
    addr_hasher.address <== address;
    hash_address <== addr_hasher.hash_address;

    signal upperLayerBytes[136 * maxBlocks];
    signal upperLayerBytesLen;

    component concat = Concat(136 * maxBlocks - 99, 99);
    concat.a <== lowerLayerPrefix;
    concat.aLen <== lowerLayerPrefixLen;
    concat.b <== lowerLayer;
    concat.bLen <== lowerLayerLen;
    upperLayerBytes <== concat.out;
    upperLayerBytesLen <== concat.outLen;

    signal input layerLens[maxNumLayers];
    signal input layerBytes[maxNumLayers][maxBlocks * 136];

    component leafChecker = LowerInUpperChecker(maxBlocks);
    leafChecker.lowerBytes <== upperLayerBytes;
    leafChecker.lowerLen <== upperLayerBytesLen;
    leafChecker.upperBytes <== layerBytes[0];
    leafChecker.upperLen <== layerLens[0];

    component lowerInUpperCheckers[maxNumLayers - 1];
    for(var i = 0; i < maxNumLayers - 1; i++){
        lowerInUpperCheckers[i] = LowerInUpperChecker(maxBlocks);
        lowerInUpperCheckers[i].lowerBytes <== layerBytes[i];
        lowerInUpperCheckers[i].lowerLen <== layerLens[i];
        lowerInUpperCheckers[i].upperBytes <== layerBytes[i+1];
        lowerInUpperCheckers[i].upperLen <== layerLens[i+1];
    }
}

component main = ProofOfBurn(8, 4);