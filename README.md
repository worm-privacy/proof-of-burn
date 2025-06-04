# Proof of Burn circuits in Noir 👽

The circuit calculates the account-rlp of a burn address and then generate the leaf-trie-node accordingly.

It will then iterate through trie nodes and check whether `keccak(layer[i])` is within `keccak(layer[i+1])`.

Finally it will return the keccak of last layer as the state_root. The account balance and its nullifier are also exposed as public inputs.
