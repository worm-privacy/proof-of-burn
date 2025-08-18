# 🔥 Proof-of-Burn circuits in Circom 🔥

The circuit calculates the account-rlp of a burn address and then generate the leaf-trie-node accordingly.

It will then iterate through trie nodes and check whether `keccak(layer[i])` is within `keccak(layer[i+1])`.

Finally it will return the keccak of last layer as the state_root. The account balance and its nullifier are also exposed as public inputs.

## Burn-key

Burn-key is a number you generate in order to start the burn/mint process. It somehow is your "private-key" to the world of EIP-7503.

- Burn-address: `Truncate160(Poseidon4(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, receiverAddress, fee))`
    Is the 160 first bits of the Poseidon3 hash of a random-number `burnKey`, a `receiverAddress` and a `fee`. The amount can only be minted for the given receiver-address, and the relayer may only collect `fee` amount of the minted value.
- PoW: `Keccak(burnKey | receiverAddress | fee | "EIP-7503") < THRESHOLD`
    Only burn-keys which fit in the equation can be used. This is in order to increase the bit-security of the protocol.
- Nullifier: `Poseidon2(POSEIDON_NULLIFIER_PREFIX, burnKey)`
    Nullifier prevents us from using the burn-key again.
- Coin: `Poseidon3(POSEIDON_COIN_PREFIX, burnKey, amount)`
    A "coin" is an encrypted amount which can be partially withdrawn, resulting in a new coin.

The burn-address hash, which is present in the Merkle-Patricia-Trie leaf key for which we provide a proof, is calculated using the following formula:
`f₄(f₃(f₂(f₁(burnKey, receiverAddress, fee))))`, where `burnKey` and `receiverAddress` and `fee` are all 254-bit numbers (finite-field elements), resulting in a 254 × 3 = 762-bit input space. The function `f₁` is Poseidon2 with a 254-bit output space. The output is then passed to `f₂(x)`, which selects the first 160 bits to produce an Ethereum address, yielding a 160-bit output space. This is followed by `f₃`, which is Keccak with a 256-bit output space, and finally `f₄`, which truncates the result to at least 50 nibbles (200 bits), giving a 200-bit output space.

Since the smallest output space among these functions is 160 bits (due to `f₂`), the overall security of this scheme is limited by that step. By the ***pigeonhole principle***, compressing a 762-bit input space into a 160-bit output space necessarily implies that many different inputs will map to the same output. As a result, an attacker attempting to find a valid `(burnKey, receiverAddress, fee)` tuple that maps to a specific leaf would, in the worst case, need to try approximately 2^160 combinations.

Thus, we consider the Merkle-Patricia-Trie leaves in this scheme to provide 160-bit preimage resistance, which corresponds to 160-bit security against such brute-force attacks.

While the Merkle-Patricia-Trie leaf key construction offers 160-bit preimage resistance due to the truncation to a 160-bit Ethereum address, this may not be sufficient for long-term or high-assurance applications. To strengthen the scheme, we add an additional constraint: the Keccak256 hash of `burnKey || receiverAddress || fee || "EIP-7503"` must begin with three zero bytes. Since each zero byte contributes 8 bits of difficulty, this adds 24 bits of security, raising the effective brute-force cost from 2^160 to 2^184. This constraint filters out the vast majority of candidate inputs, ensuring that only those satisfying both the original hash chain and the prefix condition are considered valid, thereby increasing the overall security of the scheme.

## Test Locally

> [!NOTE]
> Optionally, use `nix-shell` and then skip to step 5.
>
> Or, use the Dockerfile

1. Install Rust toolkit
    - `curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh`
2. Install Circom
    - `git clone https://github.com/iden3/circom.git`
    - `cd circom && cargo install --path circom`
3. Clone this repo
    - `git clone --recurse-submodules https://github.com/worm-privacy/proof-of-burn`
    - `cd proof-of-burn`
4. Install Python dependencies
    - `python -m venv .venv`
    - `source .venv/bin/activate`
    - `pip install -r tests/requirements.txt`
5. Start Ganache *or* Anvil (Foundry) server
    - `ganache -d`
    - `anvil --mnemonic "myth like bonus scare over problem client lizard pioneer submit female collect"`
6. Run the Makefile
    - `make`

After running `make`, the `main.py` script will first initiate a transfer to a burn-address and will then generate an input file for the circuit. Then it will try to generate a witness file through the Circom-generated C program.

## TODO

- [ ] The Proof-of-Work mechanism may have vulenrability.
- [ ] More reviewers needed for the circuits.
- [ ] We should also commit to fee in burn-address generation
