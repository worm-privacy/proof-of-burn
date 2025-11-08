import io
import json
from ..constants import (
    POSEIDON_COIN_PREFIX,
)
from ..poseidon import poseidon3, Field
from .public_commitment import expected_commitment
import copy


with io.open("tests/test_spend_input.json") as f:
    spend_inp = json.load(f)

burn_key = int(spend_inp["burnKey"])

spend_expected_commitment = expected_commitment(
    [
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(999999999999999766),
        ).val,  # coin
        321,  # withdrawnBalance
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(999999999999999766 - 321),
        ).val,  # remainingCoin (coin - withdrawnBalance)
        999,  # extraCommitment
    ]
)[1][0]

spend_broken_1 = copy.deepcopy(spend_inp)
spend_broken_1["withdrawnBalance"] = "999999999999999767"

spend_broken_2 = copy.deepcopy(spend_inp)
spend_broken_2["withdrawnBalance"] = str(2**240 - 1)

spend_all = copy.deepcopy(spend_inp)
spend_all["withdrawnBalance"] = "999999999999999766"
spend_all_expected_commitment = expected_commitment(
    [
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(999999999999999766),
        ).val,  # coin
        999999999999999766,  # withdrawnBalance
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(0),
        ).val,  # remainingCoin (coin - withdrawnBalance)
        999,  # extraCommitment
    ]
)[1][0]

test_spend = (
    "Spend(31)",
    [
        (
            spend_inp,
            [spend_expected_commitment],
        ),
        (spend_broken_1, None),
        (spend_broken_2, None),
        (
            spend_all,
            [spend_all_expected_commitment],
        ),
    ],
)
