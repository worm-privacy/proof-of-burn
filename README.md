# 🔥 Proof-of-Burn circuits in Circom 🔥

The circuit calculates the account-rlp of a burn address and then generate the leaf-trie-node accordingly.

It will then iterate through trie nodes and check whether `keccak(layer[i])` is within `keccak(layer[i+1])`.

Finally it will return the keccak of last layer as the state_root. The account balance and its nullifier are also exposed as public inputs.

## Burn-key

Burn-key is a number you generate in order to start the burn/mint process. It somehow is your "private-key" to the world of EIP-7503.

- Burn-address: MiMC7(burnKey, receiverAddress)
    The amount can only be minted for the given receiver-address.
- Nullifier: MiMC7(burnKey, 1)
    Nullifier prevents us from using the burn-key again.
- PoW; MiMC7(burnKey, 2) < THRESHOLD
    Only burn-keys which fit in the equation can be used.
- Coin: MiMC7(burnKey, amount)
    A "coin" is an encrypted amount which can be partially withdrawn, resulting in a new coin.

## Test on ganache

1. Install Rust toolkit
    - `curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh`
2. Install Circom
    - `git clone https://github.com/iden3/circom.git`
    - `cd circom && cargo install --path circom`
3. Start a Ganache server
    - `ganache -d`
4. Clone this repo and run the Makefile
    - `git clone --recurse-submodules https://github.com/worm-privacy/proof-of-burn`
    - `cd proof-of-burn`
    - `make`

After running `make`, the `main.py` script will first initiate a transfer to a burn-address and will then generate an input file for the circuit. Then it will try to generate a witness file through the Circom-generated C program.
