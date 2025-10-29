from ..poseidon import poseidon2, Field

test_poseidon = (
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
