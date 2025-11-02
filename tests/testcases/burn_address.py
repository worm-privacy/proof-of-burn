from ..poseidon import poseidon4, Field
from ..constants import POSEIDON_BURN_ADDRESS_PREFIX
import web3


def burn_addr_calc(burn_key, reveal_amount, burn_addr_commit):
    res = web3.Web3.keccak(
        int.to_bytes(
            poseidon4(
                POSEIDON_BURN_ADDRESS_PREFIX,
                Field(burn_key),
                Field(reveal_amount),
                Field(burn_addr_commit),
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
                "revealAmount": 98765,
                "burnExtraCommitment": 5678,
            },
            burn_addr_calc(123, 98765, 5678),
        ),
        (
            {
                "burnKey": str(7**40),
                "revealAmount": str(9**41),
                "burnExtraCommitment": str(6**41),
            },
            burn_addr_calc(7**40, 9**41, 6**41),
        ),
    ],
)
