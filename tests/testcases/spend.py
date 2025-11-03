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
            Field(999999999999999766 - 321 - 12),
        ).val,  # remainingCoin (coin - withdrawnBalance - broadcasterFee)
        12,  # broadcasterFee
        int("0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"[2:], 16),  # receiverAddress
    ]
)[1][0]

spend_broken_1 = copy.deepcopy(spend_inp)
spend_broken_1["withdrawnBalance"] = "999999999999999767"
spend_broken_1["broadcasterFee"] = 0

spend_broken_2 = copy.deepcopy(spend_inp)
spend_broken_2["withdrawnBalance"] = 0
spend_broken_2["broadcasterFee"] = "999999999999999767"

spend_broken_3 = copy.deepcopy(spend_inp)
spend_broken_3["withdrawnBalance"] = "999999999999999760"
spend_broken_3["broadcasterFee"] = 7

spend_broken_4 = copy.deepcopy(spend_inp)
spend_broken_4["withdrawnBalance"] = str(2**240 - 1)
spend_broken_4["broadcasterFee"] = 0

spend_broken_5 = copy.deepcopy(spend_inp)
spend_broken_5["withdrawnBalance"] = 0
spend_broken_5["broadcasterFee"] = str(2**240 - 1)


spend_all = copy.deepcopy(spend_inp)
spend_all["withdrawnBalance"] = "999999999999999760"
spend_all["broadcasterFee"] = 6
spend_all_expected_commitment = expected_commitment(
    [
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(1000000000000000000 - 234),
        ).val,  # coin
        999999999999999760,  # withdrawnBalance
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(0),
        ).val,  # remainingCoin (coin - withdrawnBalance - broadcasterFee)
        6,  # broadcasterFee
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
        (spend_broken_1, None),
        (spend_broken_2, None),
        (spend_broken_3, None),
        (spend_broken_4, None),
        (spend_broken_5, None),
        (spend_all, [spend_all_expected_commitment]),
    ],
)
