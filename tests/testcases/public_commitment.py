from eth_abi import packed
import web3


def expected_commitment(vals):
    concat_bytes = []
    for v in vals:
        concat_bytes.extend(int.to_bytes(v, 32, "big"))

    expected = int.from_bytes(
        web3.Web3.keccak(packed.encode_packed(["uint256"] * len(vals), vals))[:31],
        "big",
    )
    return (
        {"in": concat_bytes},
        [expected],
    )


test_public_commitment_1 = (
    "PublicCommitment(1)",
    [
        expected_commitment([0]),
        expected_commitment([123456]),
        expected_commitment([2**256 - 1]),
    ],
)

test_public_commitment_2 = (
    "PublicCommitment(2)",
    [
        expected_commitment([0, 1]),
        expected_commitment([123456, 2345678]),
        expected_commitment([987654321, 2**256 - 1]),
        expected_commitment([2**256 - 1, 2**256 - 1]),
    ],
)

test_public_commitment_6 = (
    "PublicCommitment(6)",
    [
        expected_commitment([0, 1, 2, 3, 4, 5]),
        expected_commitment([v * 3**100 for v in [0, 1, 2, 3, 4, 5]]),
        expected_commitment([2**256 - 1] * 6),
    ],
)
