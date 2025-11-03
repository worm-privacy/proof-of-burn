from ..poseidon import poseidon2, poseidon3, poseidon4, Field

test_poseidon_2 = (
    "Poseidon(2)",
    [
        ({"inputs": [1, 2]}, [poseidon2(Field(1), Field(2)).val]),
        ({"inputs": [1, 3]}, [poseidon2(Field(1), Field(3)).val]),
        ({"inputs": [2, 3]}, [poseidon2(Field(2), Field(3)).val]),
        (
            {"inputs": [str(3**150), str(7**40)]},
            [poseidon2(Field(3**150), Field(7**40)).val],
        ),
    ],
)
test_poseidon_3 = (
    "Poseidon(3)",
    [
        ({"inputs": [1, 2, 3]}, [poseidon3(Field(1), Field(2), Field(3)).val]),
        ({"inputs": [1, 3, 4]}, [poseidon3(Field(1), Field(3), Field(4)).val]),
        ({"inputs": [2, 3, 5]}, [poseidon3(Field(2), Field(3), Field(5)).val]),
        (
            {"inputs": [str(3**150), str(7**40), str(6**50)]},
            [poseidon3(Field(3**150), Field(7**40), Field(6**50)).val],
        ),
    ],
)
test_poseidon_4 = (
    "Poseidon(4)",
    [
        (
            {"inputs": [1, 2, 4, 5]},
            [poseidon4(Field(1), Field(2), Field(4), Field(5)).val],
        ),
        (
            {"inputs": [1, 3, 2, 4]},
            [poseidon4(Field(1), Field(3), Field(2), Field(4)).val],
        ),
        (
            {"inputs": [2, 3, 5, 1]},
            [poseidon4(Field(2), Field(3), Field(5), Field(1)).val],
        ),
        (
            {"inputs": [str(3**150), str(7**40), str(6**20), str(7**35)]},
            [
                poseidon4(
                    Field(3**150), Field(7**40), Field(6**20), Field(7**35)
                ).val
            ],
        ),
    ],
)
