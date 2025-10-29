test_substring_check = (
    "SubstringCheck(10, 3)",
    [
        (
            {
                "mainInput": [1, 123, 256, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 3,
                "subInput": [1, 123, 256],
            },
            None,
        ),
        (
            {
                "mainInput": [1, 123, 255, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 3,
                "subInput": [1, 123, 255],
            },
            [1],
        ),
        (
            {
                "mainInput": [1, 0, 3, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 3,
                "subInput": [1, 0, 3],
            },
            [1],
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 3,
                "subInput": [1, 0, 3],
            },
            [0],
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 3,
                "subInput": [1, 0, 256],
            },
            None,
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 0,
                "subInput": [1, 0, 1],
            },
            None,
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 2,
                "subInput": [1, 0, 1],
            },
            None,
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 3,
                "subInput": [1, 0, 1],
            },
            [1],
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 3,
                "subInput": [0, 1, 0],
            },
            [0],
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 4,
                "subInput": [1, 1, 1],
            },
            [0],
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 5,
                "subInput": [1, 1, 1],
            },
            [1],
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 1, 0, 0, 0],
                "mainLen": 9,
                "subInput": [0, 0, 0],
            },
            [0],
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 1, 0, 0, 0],
                "mainLen": 10,
                "subInput": [0, 0, 0],
            },
            [1],
        ),
        (
            {
                "mainInput": [1, 0, 1, 1, 1, 0, 0, 0, 1, 0],
                "mainLen": 11,
                "subInput": [0, 1, 0],
            },
            None,
        ),
    ],
)
