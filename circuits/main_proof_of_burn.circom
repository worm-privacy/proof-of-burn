pragma circom 2.2.2;

include "./proof_of_burn.circom";

component main = ProofOfBurn(
    16, // maxNumLayers (Maximum number of Merkle-Patricia-Trie proof nodes supported)
        // Number of MPT nodes in account proofs of 100 richest addresses as of July 2nd 2025: Min: 8 Max: 10 Avg: 8.69
    
    4,  // maxNodeBlocks (Keccak blocks are 136 bytes. Merkle-Patricia-Trie nodes are maximum 532 bytes ~ 3.91 blocks)
    8,  // maxHeaderBlocks (Average header len of the last 100 blocks as of July 2nd 2025 is 643 bytes ~ 4.72 blocks)

    50, // minLeafAddressNibbles (4 ^ 50 = 2 ^ 100 bits of security)
        // Number of address-hash bytes present in leaf among 100 richest addresses: Min: 27 Max: 30 Avg: 28.04
        // Bitcoin's world record of lowest block-hash has only 23 zero bytes

    31, // amountBytes (248-bits to disallow field overflows)
    250 // powMaxAllowedBits (Fields are 254 bits. So approximately 2^254 / 2^250 number of MiMC7 hashes required)
);