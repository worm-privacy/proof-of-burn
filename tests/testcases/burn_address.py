from ..poseidon import poseidon6, Field
from ..constants import POSEIDON_BURN_ADDRESS_PREFIX
import web3


def burn_addr_calc(
    burn_key, recv_addr, prover_fee_amount, broadcaster_fee_amount, reveal_amount
):
    res = web3.Web3.keccak(
        int.to_bytes(
            poseidon6(
                POSEIDON_BURN_ADDRESS_PREFIX,
                Field(burn_key),
                Field(recv_addr),
                Field(prover_fee_amount),
                Field(broadcaster_fee_amount),
                Field(reveal_amount),
            ).val,
            32,
            "big",
        )[:20]
    ).hex()
    return [int(ch, base=16) for ch in res]


test_burn_address_hash = (
    "BurnAddressHash()",
    [
        (
            {
                "burnKey": 123,
                "receiverAddress": 2345,
                "proverFeeAmount": 4567,
                "broadcasterFeeAmount": 5678,
                "revealAmount": 98765,
            },
            burn_addr_calc(123, 2345, 4567, 5678, 98765),
        ),
        (
            {
                "burnKey": str(7**40),
                "receiverAddress": str(3**150),
                "proverFeeAmount": str(7**43),
                "broadcasterFeeAmount": str(6**41),
                "revealAmount": str(9**41),
            },
            burn_addr_calc(7**40, 3**150, 7**43, 6**41, 9**41),
        ),
    ],
)
