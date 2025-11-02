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
burn_extra_commit = int(proof_of_burn_inp["burnExtraCommitment"])

pob_expected_commitment = expected_commitment(
    [
        int.from_bytes(
            bytes.fromhex(
                "e36499b50da290131c3fa32d4f60717c8c529ae1bc3a216f32d05c05fe80368d"
            ),
            "big",
        ),  # Block root
        poseidon2(POSEIDON_NULLIFIER_PREFIX, Field(burn_key)).val,  # Nullifier,
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(1000000000000000000 - 234),
        ).val,  # Encrypted balance
        234,  # Spend
        burn_extra_commit,
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
            [pob_expected_commitment],  # layer[2] is unused so doesn't matter!
        ),
        (
            proof_of_burn_corrupted_layer_3,
            [pob_expected_commitment],  # layer[3] is unused so doesn't matter!
        ),
    ],
)
