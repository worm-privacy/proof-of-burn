# 🔥 Proof-of-Burn circuits in Circom 🔥

The circuit calculates the account-rlp of a burn address and then generate the leaf-trie-node accordingly.

It will then iterate through trie nodes and check whether `keccak(layer[i])` is within `keccak(layer[i+1])`.

Finally it will return the keccak of last layer as the state_root. The account balance and its nullifier are also exposed as public inputs.

## Test on ganache

1. Install Rust toolkit
    - `curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh`
2. Install Circom
    - `git clone https://github.com/iden3/circom.git`
    - `cd circom && cargo install --path circom`
3. Start a Ganache server
    - `ganache -d`
4. Run the Makefile
    - `make`

After running `make`, the `main.py` script will first initiate a transfer to a burn-address and will then generate an input file for the circuit. Then it will try to generate a witness file through the Circom-generated C program.
