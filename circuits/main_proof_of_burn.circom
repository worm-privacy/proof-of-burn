pragma circom 2.2.2;

include "./proof_of_burn.circom";

component main = ProofOfBurn(
    16, // maxNumLayers (Maximum number of Merkle-Patricia-Trie proof nodes supported)
        // Number of MPT nodes in account proofs of 100 richest addresses as of July 2nd 2025: Min: 8 Max: 10 Avg: 8.69
    
    4,  // maxNodeBlocks (Keccak blocks are 136 bytes. Merkle-Patricia-Trie nodes are maximum 532 bytes ~ 3.91 blocks)
        // Length of MPT nodes in accounts proofs of 100 richest addresses as of July 7th 2025: Min: 35 Max: 532 Avg: 432.23

    8,  // maxHeaderBlocks (Average header len of the last 100 blocks as of July 2nd 2025 is 643 bytes ~ 4.72 blocks)

    50, // minLeafAddressNibbles (4 ^ 50 = 2 ^ 100 bits of security)
        // Number of address-hash nibbles present in leaf among 100 richest addresses: Min: 54 Max: 60 Avg: 56.08
        // Bitcoin's world record of lowest block-hash has only 23 zero bytes (46 zero nibbles)

    31, // amountBytes (248-bits to disallow field overflows)

    250 // powMaxAllowedBits (Fields are 254 bits. So approximately 2^254 / 2^250 number of MiMC7 hashes required)
        // This is to add extra security bits to disallow conflicts
);