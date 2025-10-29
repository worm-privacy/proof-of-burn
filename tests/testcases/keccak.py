test_pad = (
    "Pad(3, 4)",
    [
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 0},
            [0x1, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 1},
            [5, 0x1, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 2},
            [5, 5, 0x1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 3},
            [5, 5, 5, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 4},
            [5, 5, 5, 5, 0x1, 0, 0, 0x80, 0, 0, 0, 0, 2],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 5},
            [5, 5, 5, 5, 5, 0x1, 0, 0x80, 0, 0, 0, 0, 2],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 6},
            [5, 5, 5, 5, 5, 5, 0x1, 0x80, 0, 0, 0, 0, 2],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 7},
            [5, 5, 5, 5, 5, 5, 5, 0x81, 0, 0, 0, 0, 2],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 8},
            [5, 5, 5, 5, 5, 5, 5, 5, 0x1, 0, 0, 0x80, 3],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 9},
            [5, 5, 5, 5, 5, 5, 5, 5, 5, 0x1, 0, 0x80, 3],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 10},
            [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0x1, 0x80, 3],
        ),
        (
            {"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 11},
            [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0x81, 3],
        ),
        ({"in": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], "inLen": 12}, None),
    ],
)


def keccak(inp):
    return list(web3.Web3.keccak(inp))


def blockify(inp, blks):
    return list(inp) + [0] * (blks * 136 - len(inp))


test_keccak_1 = (
    "KeccakBytes(1)",
    [
        ({"in": blockify(b"", 1), "inLen": 0}, keccak(b"")),
        ({"in": blockify(b"salam", 1), "inLen": 5}, keccak(b"salam")),
        ({"in": blockify(b"salam", 1), "inLen": 4}, keccak(b"sala")),
        ({"in": blockify(b"a" * 135, 1), "inLen": 135}, keccak(b"a" * 135)),
        ({"in": blockify(b"a" * 136, 1), "inLen": 136}, None),
    ],
)

test_keccak_2 = (
    "KeccakBytes(2)",
    [
        ({"in": blockify(b"", 2), "inLen": 0}, keccak(b"")),
        ({"in": blockify(b"salam", 2), "inLen": 5}, keccak(b"salam")),
        ({"in": blockify(b"a" * 135, 2), "inLen": 135}, keccak(b"a" * 135)),
        ({"in": blockify(b"a" * 136, 2), "inLen": 136}, keccak(b"a" * 136)),
        ({"in": blockify(b"a" * 136, 2), "inLen": 130}, keccak(b"a" * 130)),
        ({"in": blockify(b"a" * 137, 2), "inLen": 137}, keccak(b"a" * 137)),
        ({"in": blockify(b"a" * 271, 2), "inLen": 271}, keccak(b"a" * 271)),
        ({"in": blockify(b"a" * 272, 2), "inLen": 272}, None),
    ],
)
