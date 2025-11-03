test_pow_eip7503_postfix = (
    "EIP7503()",
    [
        (
            {},
            list(b"EIP-7503"),
        ),
    ],
)

test_concat_fixed_4 = (
    "ConcatFixed4(1,2,3,4)",
    [
        (
            {
                "a": [1],
                "b": [2, 3],
                "c": [4, 5, 6],
                "d": [7, 8, 9, 10],
            },
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        ),
    ],
)

test_proof_of_work = (
    "ProofOfWorkChecker()",
    [
        (
            {
                "burnKey": 123,
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 0,
            },
            [],
        ),
        (
            {
                "burnKey": 811,
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 1,
            },
            None,
        ),
        (
            {
                "burnKey": 812,  # 1 zero bytes
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 1,
            },
            [],
        ),
        (
            {
                "burnKey": 813,
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 1,
            },
            None,
        ),
        (
            {
                "burnKey": 47109,  # 2 zero bytes
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 1,
            },
            [],
        ),
        (
            {
                "burnKey": 811,
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 2,
            },
            None,
        ),
        (
            {
                "burnKey": 812,  # 1 zero bytes
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 2,
            },
            None,
        ),
        (
            {
                "burnKey": 813,
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 2,
            },
            None,
        ),
        (
            {
                "burnKey": 47108,
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 2,
            },
            None,
        ),
        (
            {
                "burnKey": 47109,  # 2 zero bytes
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 2,
            },
            [],
        ),
        (
            {
                "burnKey": 47110,
                "revealAmount": 234,
                "burnExtraCommitment": 345,
                "minimumZeroBytes": 2,
            },
            None,
        ),
    ],
)
