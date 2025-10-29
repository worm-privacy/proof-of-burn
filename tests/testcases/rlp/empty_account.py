import rlp
import web3


def rlp_empty_account(balance, max_balance_bytes):
    predict = list(
        rlp.encode(
            [
                0,
                balance,
                web3.Web3.to_bytes(
                    hexstr="0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                ),
                web3.Web3.to_bytes(
                    hexstr="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                ),
            ]
        )
    )
    predict_len = len(predict)
    predict = predict + [0] * (70 + max_balance_bytes - predict_len) + [predict_len]
    return predict


test_rlp_empty_account_1 = (
    "RlpEmptyAccount(3)",
    [
        ({"balance": 0}, rlp_empty_account(0, 3)),
        ({"balance": 1}, rlp_empty_account(1, 3)),
        ({"balance": 10}, rlp_empty_account(10, 3)),
        ({"balance": 255}, rlp_empty_account(255, 3)),
        ({"balance": 256}, rlp_empty_account(256, 3)),
        ({"balance": 257}, rlp_empty_account(257, 3)),
        ({"balance": 0xFFFF}, rlp_empty_account(0xFFFF, 3)),
        ({"balance": 0x10000}, rlp_empty_account(0x10000, 3)),
        ({"balance": 0xFFFFFF}, rlp_empty_account(0xFFFFFF, 3)),
        ({"balance": 0x1000000}, None),
    ],
)

test_rlp_empty_account_2 = (
    "RlpEmptyAccount(10)",
    [
        ({"balance": str(256**7 - 1234)}, rlp_empty_account(256**7 - 1234, 10)),
        ({"balance": str(256**10 - 1)}, rlp_empty_account(256**10 - 1, 10)),
        ({"balance": str(256**10)}, None),
    ],
)

test_rlp_empty_account_3 = (
    "RlpEmptyAccount(31)",
    [
        (
            {"balance": str(256**7 - 192837465)},
            rlp_empty_account(256**7 - 192837465, 31),
        ),
        (
            {"balance": str(256**10 - 987654321)},
            rlp_empty_account(256**10 - 987654321, 31),
        ),
        ({"balance": str(256**31 - 1)}, rlp_empty_account(256**31 - 1, 31)),
        ({"balance": str(256**31)}, None),
    ],
)
