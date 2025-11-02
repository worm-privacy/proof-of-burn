# 🔥 Proof-of-Burn circuits in Circom 🔥

[![Test circuits](https://github.com/worm-privacy/proof-of-burn/actions/workflows/test.yml/badge.svg)](https://github.com/worm-privacy/proof-of-burn/actions/workflows/test.yml)
[![Discord](https://img.shields.io/discord/1213528108796350484)](https://discord.gg/EIP7503)
[![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/EIP7503)](https://x.com/EIP7503)


The circuit calculates the account-rlp of a burn address and then generate the leaf-trie-node accordingly.

It will then iterate through trie nodes and check whether `keccak(layer[i])` is within `keccak(layer[i+1])`.

As a public input, it will expect a single public commitment which itself is Keccak hash of multiple values (In order to optimize gas usage):

1. The `blockRoot`: the state root of the block being referenced, passed by a Solidity contract.
2. A `nullifier`: `Poseidon2(POSEIDON_NULLIFIER_PREFIX, burnKey)`, used to prevent revealing the same burn address more than once.
3. An encrypted representation of the remaining balance: `Poseidon3(POSEIDON_COIN_PREFIX, burnKey, intendedBalance - revealAmount)`.
4. A `revealAmount`: an amount from the minted balance that is directly revealed upon submission of the proof.
5. A `burnExtraCommitment`: commits to the way the revealed amount should be distributed by the contract.
6. A `_proofExtraCommitment`: to glue information to the proof that aren't necessarily processed in the circuit.

## Burn-key

Burn-key is a number you generate in order to start the burn/mint process. It somehow is your "private-key" to the world of EIP-7503.

- Burn-address: `Truncate160(Poseidon4(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, revealAmount, burnExtraCommitment))`
  - Is the 160 first bits of the Poseidon4 hash of a random-number `burnKey`, and 2 other values we are commiting to:
  - A `revealAmount` which specifies part of the BETH that will be minted upon submission of the proof.
  - A `burnExtraCommitment` which commits on the way the minted amount should be distributed by the contract after being minted.
- PoW: `Keccak(burnKey | revealAmount | burnExtraCommitment | 'EIP-7503') < THRESHOLD`
    Only burn-keys which fit in the equation can be used. This is in order to increase the bit-security of the protocol.
- Nullifier: `Poseidon2(POSEIDON_NULLIFIER_PREFIX, burnKey)`
    Nullifier prevents us from using the burn-key again.
- Coin: `Poseidon3(POSEIDON_COIN_PREFIX, burnKey, amount)`
    A "coin" is an encrypted amount which can be partially withdrawn, resulting in a new coin.

The burn-address hash, which is present in the Merkle-Patricia-Trie leaf key for which we provide a proof, is calculated using the following formula:
`f₄(f₃(f₂(f₁(burnKey, receiverAddress, burnExtraCommitment))))`, where the inputs are all 254-bit numbers (finite-field elements), resulting in a 254 × 3 bit input space. The function `f₁` is Poseidon2 with a 254-bit output space. The output is then passed to `f₂(x)`, which selects the first 160 bits to produce an Ethereum address, yielding a 160-bit output space. This is followed by `f₃`, which is Keccak with a 256-bit output space, and finally `f₄`, which truncates the result to at least 50 nibbles (200 bits), giving a 200-bit output space.

Since the smallest output space among these functions is 160 bits (due to `f₂`), the overall security of this scheme is limited by that step.

Thus, we consider the Merkle-Patricia-Trie leaves in this scheme to provide 160-bit preimage resistance, which corresponds to 160-bit security against such brute-force attacks.

While the Merkle-Patricia-Trie leaf key construction offers 160-bit preimage resistance due to the truncation to a 160-bit Ethereum address, this may not be sufficient for long-term or high-assurance applications. To strengthen the scheme, we add an additional constraint: the Keccak256 hash of `burnKey | revealAmount | burnExtraCommitment | 'EIP-7503'` must begin with two zero bytes. Since each zero byte contributes 8 bits of difficulty, this adds 16 bits of security, raising the effective brute-force cost from 2^160 to 2^176. This constraint filters out the vast majority of candidate inputs, ensuring that only those satisfying both the original hash chain and the prefix condition are considered valid, thereby increasing the overall security of the scheme.

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
