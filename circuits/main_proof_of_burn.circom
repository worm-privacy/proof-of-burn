pragma circom 2.2.2;

include "./proof_of_burn.circom";

component main = ProofOfBurn(
    4, // maxNumLayers (Maximum number of Merkle-Patricia-Trie proof nodes)
    4, // maxNodeBlocks (Keccak blocks are 136 bytes. Merkle-Patricia-Trie nodes are maximum 532 bytes)
    5, // maxHeaderBlocks (Average block header size in as of [DATE] is [X] bytes)
    20, // minLeafAddressNibbles (4 ^ 20 bits of security)
    31, // amountBytes (248-bits to disallow field overflows)
    250 // powMaxAllowedBits (Fields are 254 bits. So approximately 2^254 / 2^250 number of MiMC7 hashes required)
);