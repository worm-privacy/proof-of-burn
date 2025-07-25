pragma circom 2.2.2;

include "./proof_of_burn.circom";

// 16      -> maxNumLayers (Maximum number of Merkle-Patricia-Trie proof nodes supported)
//            Number of MPT nodes in account proofs of 100 richest addresses as of July 2nd 2025: Min: 8 Max: 10 Avg: 8.69
//
// 4       -> maxNodeBlocks (Keccak blocks are 136 bytes. Merkle-Patricia-Trie nodes are maximum 532 bytes ~ 3.91 blocks)
//            Length of MPT nodes in accounts proofs of 100 richest addresses as of July 7th 2025: Min: 35 Max: 532 Avg: 432.23
//            Maximum lengths are for branch nodes with 16 non-empty slots: len(rlp.encode([keccak(...)] * 16 + [0])) == 532
//
// 8       -> maxHeaderBlocks (Average header len of the last 100 blocks as of July 2nd 2025 is 643 bytes ~ 4.72 blocks)
//
// 50      -> minLeafAddressNibbles (4 * 50 = 200 bits of security (?!))
//            Number of address-hash nibbles present in leaf among 100 richest addresses: Min: 54 Max: 60 Avg: 56.08
//            Bitcoin's world record of lowest block-hash has only 23 zero nibbles
//
// 31      -> amountBytes (248-bits to disallow field overflows)
//
// 2       -> powMinimumZeroBytes (Adds 8 * powMinimumZeroBytes extra bits of security)
//            This is to make it harder to find address-hash collisions
//
// 10 ETH  -> maxBalance (To reduce the incentive to prove large amounts of ETH by performing address-hash collision attack)
//
component main = ProofOfBurn(16, 4, 8, 50, 31, 2, 10 * (10 ** 18));