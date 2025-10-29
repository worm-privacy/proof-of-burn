import web3
import io
import json
from ..constants import (
    POSEIDON_COIN_PREFIX,
    POSEIDON_NULLIFIER_PREFIX,
)
from ..poseidon import poseidon2, poseidon3, Field
from .public_commitment import expected_commitment


with io.open("tests/test_pob_input.json") as f:
    proof_of_burn_inp = json.load(f)

burn_key = int(proof_of_burn_inp["burnKey"])

pob_expected_commitment = expected_commitment(
    [
        int.from_bytes(
            bytes.fromhex(
                "01393d97db416e378fc2605c4f143c31ada5610d41e4fbfd276da0f476d0347a"
            ),
            "big",
        ),  # Block root
        poseidon2(POSEIDON_NULLIFIER_PREFIX, Field(burn_key)).val,  # Nullifier,
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(1000000000000000000 - 123 - 234 - 23),
        ).val,  # Encrypted balance
        123,  # Prover fee
        23,  # Broadcaster fee
        234,  # Spend
        web3.Web3.to_int(
            hexstr="0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"
        ),  # Receiver
        0,  # Extra commitment
    ]
)[1][0]

import copy

proof_of_burn_corrupted_layer_0 = copy.deepcopy(proof_of_burn_inp)
proof_of_burn_corrupted_layer_0["layers"][0][0] += 1

proof_of_burn_corrupted_layer_1 = copy.deepcopy(proof_of_burn_inp)
proof_of_burn_corrupted_layer_1["layers"][1][0] += 1

proof_of_burn_corrupted_layer_2 = copy.deepcopy(proof_of_burn_inp)
proof_of_burn_corrupted_layer_2["layers"][2][0] += 1

proof_of_burn_corrupted_layer_3 = copy.deepcopy(proof_of_burn_inp)
proof_of_burn_corrupted_layer_3["layers"][3][0] += 1

test_proof_of_burn = (
    "ProofOfBurn(4, 4, 5, 20, 31, 2, 10 ** 18, 10 ** 19)",
    [
        (
            proof_of_burn_inp,
            [pob_expected_commitment],
        ),
        (
            proof_of_burn_corrupted_layer_0,
            None,
        ),
        (
            proof_of_burn_corrupted_layer_1,
            None,
        ),
        (
            proof_of_burn_corrupted_layer_2,
            None,
        ),
        (
            proof_of_burn_corrupted_layer_3,
            [pob_expected_commitment],  # layer[3] is unused so doesn't matter!
        ),
    ],
)
