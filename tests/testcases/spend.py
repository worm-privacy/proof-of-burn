import io
import json
from ..constants import (
    POSEIDON_COIN_PREFIX,
)
from ..poseidon import poseidon3, Field
from .public_commitment import expected_commitment


with io.open("tests/test_spend_input.json") as f:
    spend_inp = json.load(f)

burn_key = int(spend_inp["burnKey"])

spend_expected_commitment = expected_commitment(
    [
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(1000000000000000000 - 234),
        ).val,  # coin
        321,  # withdrawnAmount
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(1000000000000000000 - 234 - 321 - 12),
        ).val,  # remainingCoin (coin - withdrawnAmount - broadcasterFee)
        12,  # broadcasterFee
        int("0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"[2:], 16),  # receiverAddress
    ]
)[1][0]

test_spend = (
    "Spend(31)",
    [
        (
            spend_inp,
            [spend_expected_commitment],
        ),
    ],
)
