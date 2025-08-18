import io
import subprocess
import json


def run(main, test_cases):
    print()
    print(f"Testing {main}")
    print("=" * 20)
    with io.open("circuits/test.circom", "w") as f:
        imports = """
        pragma circom 2.2.2;
        
        include "./circomlib/circuits/poseidon.circom";
        include "utils/shift.circom";
        include "utils/public_commitment.circom";
        include "utils/concat.circom";
        include "utils/rlp/integer.circom";
        include "utils/rlp/empty_account.circom";
        include "utils/rlp/merkle_patricia_trie_leaf.circom";
        include "utils/selector.circom";
        include "utils/substring_check.circom";
        include "utils/array.circom";
        include "utils/divide.circom";
        include "utils/convert.circom";
        include "utils/keccak.circom";
        include "proof_of_burn.circom";
        include "spend.circom";
        
        """
        f.write(imports + f"component main = {main};")
    subprocess.run(["circom", "-c", "circuits/test.circom", "--O0"])
    with io.open("test_cpp/main.cpp") as f:
        test_cpp = f.read()
        test_cpp = test_cpp.replace(
            "fclose(write_ptr);",
            """fclose(write_ptr);
                std::ofstream out("output.json",std::ios::binary | std::ios::out);
                out<<"["<<std::endl;
                int numOutputs = get_main_input_signal_start() - 1;
                for (int i=0;i<numOutputs;i++) {
                    ctx->getWitness(i + 1, &v);
                    out<<"\\\""<<Fr_element2str(&v)<<"\\\"";
                    if(i < numOutputs - 1) {
                        out<<",";
                    }
                    out<<std::endl;
                }
                out<<"]";
                out.flush();
                out.close();""",
        )
    with io.open("test_cpp/main.cpp", "w") as f:
        f.write(test_cpp)
    subprocess.run(["make"], cwd="test_cpp/")
    outputs = []
    for test_case, expected in test_cases:
        with io.open("test_cpp/input.json", "w") as f:
            json.dump(test_case, f)
        res = subprocess.run(
            ["./test", "input.json", "witness.wtns"],
            cwd="test_cpp/",
            capture_output=True,
        )
        if res.stderr:
            if expected != None:
                raise Exception(f"Expected null!")
            outputs.append(None)
        else:
            with io.open("test_cpp/output.json", "r") as f:
                output = [int(p) for p in json.load(f)]
                if output != expected:
                    raise Exception(f"Unexpected output! {output} != {expected}")
                outputs.append(output)
    return outputs


def bytes_to_bits(bytes):
    out = []
    for byte in bytes:
        lst = [int(a) for a in list(reversed(bin(byte)[2:]))]
        for i in range(8):
            out.append(lst[i] if i < len(lst) else 0)
    return out


from eth_abi import packed
from .poseidon import poseidon1, poseidon2, poseidon3, Field, FIELD_SIZE
import rlp, web3


# Number to 256-bit little-endian list
def field_to_be_bits(elem):
    return list(int.to_bytes(elem, 32, "big"))


run(
    "Num2BigEndianBytes(32)",
    [
        ({"in": 123}, field_to_be_bits(123)),
        ({"in": 0}, field_to_be_bits(0)),
        ({"in": 1}, field_to_be_bits(1)),
        ({"in": str(3**150)}, field_to_be_bits(3**150)),
        ({"in": str(FIELD_SIZE - 10)}, field_to_be_bits(FIELD_SIZE - 10)),
        ({"in": str(FIELD_SIZE - 1)}, field_to_be_bits(FIELD_SIZE - 1)),
    ],
)


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


with io.open("tests/test_pob_input.json") as f:
    proof_of_burn_inp = json.load(f)

burn_key = int(proof_of_burn_inp["burnKey"])

from .constants import (
    POSEIDON_COIN_PREFIX,
    POSEIDON_NULLIFIER_PREFIX,
)

pob_expected_commitment = expected_commitment(
    [
        int.from_bytes(
            bytes.fromhex(
                "50753f792b258ce00fcf5262822b6a8bd5ea3c465ea1c5f01a01aa8235ae56a1"
            ),
            "big",
        ),  # Block root
        poseidon2(POSEIDON_NULLIFIER_PREFIX, Field(burn_key)).val,  # Nullifier,
        poseidon3(
            POSEIDON_COIN_PREFIX,
            Field(burn_key),
            Field(1000000000000000000 - 123 - 234),
        ).val,  # Encrypted balance
        123,  # Fee
        234,  # Spend
        web3.Web3.to_int(
            hexstr="0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"
        ),  # Receiver
    ]
)[1][0]

import copy

proof_of_burn_corrupted_layer_0 = copy.deepcopy(proof_of_burn_inp)
proof_of_burn_corrupted_layer_0["layers"][0][0] += 1

proof_of_burn_corrupted_layer_1 = copy.deepcopy(proof_of_burn_inp)
proof_of_burn_corrupted_layer_1["layers"][1][0] += 1

proof_of_burn_corrupted_layer_2 = copy.deepcopy(proof_of_burn_inp)
proof_of_burn_corrupted_layer_2["layers"][2][0] += 1

proof_of_burn_corrupted_layer_3 = copy.deepcopy(proof_of_burn_inp)
proof_of_burn_corrupted_layer_3["layers"][3][0] += 1

run(
    "ProofOfBurn(4, 4, 5, 20, 31, 2, 10 ** 18)",
    [
        (
            proof_of_burn_inp,
            [pob_expected_commitment],
        ),
        (
            proof_of_burn_corrupted_layer_0,
            None,
        ),
        (
            proof_of_burn_corrupted_layer_1,
            None,
        ),
        (
            proof_of_burn_corrupted_layer_2,
            [pob_expected_commitment],  # layer[2] is unused so doesn't matter!
        ),
        (
            proof_of_burn_corrupted_layer_3,
            [pob_expected_commitment],  # layer[3] is unused so doesn't matter!
        ),
    ],
)

run(
    "Flatten(2, 3)",
    [
        ({"in": [[1, 2, 3], [4, 5, 6]]}, [1, 2, 3, 4, 5, 6]),
    ],
)

run(
    "AssertLessThan(3)",
    [
        ({"a": 0, "b": 1}, []),
        ({"a": 1, "b": 0}, None),
        ({"a": 3, "b": 6}, []),
        ({"a": 6, "b": 3}, None),
        ({"a": 4, "b": 5}, []),
        ({"a": 5, "b": 4}, None),
        ({"a": 6, "b": 7}, []),
        ({"a": 7, "b": 6}, None),
        ({"a": 0, "b": 0}, None),
        ({"a": 1, "b": 1}, None),
        ({"a": 3, "b": 3}, None),
        ({"a": 7, "b": 7}, None),
        ({"a": 6, "b": 8}, None),
        ({"a": 8, "b": 6}, None),
    ],
)

run(
    "AssertLessEqThan(3)",
    [
        ({"a": 0, "b": 1}, []),
        ({"a": 1, "b": 0}, None),
        ({"a": 3, "b": 6}, []),
        ({"a": 6, "b": 3}, None),
        ({"a": 4, "b": 5}, []),
        ({"a": 5, "b": 4}, None),
        ({"a": 6, "b": 7}, []),
        ({"a": 7, "b": 6}, None),
        ({"a": 0, "b": 0}, []),
        ({"a": 1, "b": 1}, []),
        ({"a": 3, "b": 3}, []),
        ({"a": 7, "b": 7}, []),
        ({"a": 6, "b": 8}, None),
        ({"a": 8, "b": 6}, None),
    ],
)

run(
    "AssertGreaterEqThan(3)",
    [
        ({"a": 0, "b": 1}, None),
        ({"a": 1, "b": 0}, []),
        ({"a": 3, "b": 6}, None),
        ({"a": 6, "b": 3}, []),
        ({"a": 4, "b": 5}, None),
        ({"a": 5, "b": 4}, []),
        ({"a": 6, "b": 7}, None),
        ({"a": 7, "b": 6}, []),
        ({"a": 0, "b": 0}, []),
        ({"a": 1, "b": 1}, []),
        ({"a": 3, "b": 3}, []),
        ({"a": 7, "b": 7}, []),
        ({"a": 6, "b": 8}, None),
        ({"a": 8, "b": 6}, None),
    ],
)

run(
    "AssertByteString(3)",
    [
        ({"in": [100, 200, 250]}, []),
        ({"in": [250, 0, 1]}, []),
        ({"in": [0, 1, 1]}, []),
        ({"in": [123, 255, 255]}, []),
        ({"in": [255, 255, 255]}, []),
        ({"in": [1, 256, 1]}, None),
    ],
)

run(
    "AssertBits(3)",
    [
        ({"in": 0}, []),
        ({"in": 1}, []),
        ({"in": 2}, []),
        ({"in": 3}, []),
        ({"in": 4}, []),
        ({"in": 5}, []),
        ({"in": 6}, []),
        ({"in": 7}, []),
        ({"in": 8}, None),
        ({"in": 9}, None),
        ({"in": 20}, None),
        ({"in": 2**100}, None),
    ],
)


def burn_addr_calc(burn_key, recv_addr, fee):
    res = web3.Web3.keccak(
        int.to_bytes(
            poseidon3(Field(burn_key), Field(recv_addr), Field(fee)).val, 32, "big"
        )[:20]
    ).hex()
    return [int(ch, base=16) for ch in res]


run(
    "BurnAddressHash()",
    [
        (
            {"burnKey": 123, "receiverAddress": 2345, "fee": 4567},
            burn_addr_calc(123, 2345, 4567),
        ),
        (
            {
                "burnKey": str(7**40),
                "receiverAddress": str(3**150),
                "fee": str(7**43),
            },
            burn_addr_calc(7**40, 3**150, 7**43),
        ),
    ],
)

run(
    "Bytes2Nibbles(3)",
    [
        ({"in": [0xAB, 0x12, 0xF5]}, [0xA, 0xB, 0x1, 0x2, 0xF, 0x5]),
    ],
)

run(
    "Reverse(3)",
    [
        ({"in": [1, 2, 3]}, [3, 2, 1]),
        ({"in": [123, 234, 56]}, [56, 234, 123]),
    ],
)

run(
    "Fit(5, 3)",
    [
        ({"in": [1, 2, 3, 4, 5]}, [1, 2, 3]),
    ],
)

run(
    "Fit(3, 5)",
    [
        ({"in": [1, 2, 3]}, [1, 2, 3, 0, 0]),
    ],
)

run(
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


run(
    "PublicCommitment(1)",
    [
        expected_commitment([0]),
        expected_commitment([123456]),
        expected_commitment([2**256 - 1]),
    ],
)

run(
    "PublicCommitment(2)",
    [
        expected_commitment([0, 1]),
        expected_commitment([123456, 2345678]),
        expected_commitment([987654321, 2**256 - 1]),
        expected_commitment([2**256 - 1, 2**256 - 1]),
    ],
)

run(
    "PublicCommitment(6)",
    [
        expected_commitment([0, 1, 2, 3, 4, 5]),
        expected_commitment([v * 3**100 for v in [0, 1, 2, 3, 4, 5]]),
        expected_commitment([2**256 - 1] * 6),
    ],
)

run(
    "SelectorArray2D(3, 2, 2)",
    [
        (
            {
                "arrays": [[[1, 2], [3, 4]], [[2, 4], [6, 8]], [[3, 6], [9, 12]]],
                "select": 0,
            },
            [1, 2, 3, 4],
        ),
        (
            {
                "arrays": [[[1, 2], [3, 4]], [[2, 4], [6, 8]], [[3, 6], [9, 12]]],
                "select": 1,
            },
            [2, 4, 6, 8],
        ),
        (
            {
                "arrays": [[[1, 2], [3, 4]], [[2, 4], [6, 8]], [[3, 6], [9, 12]]],
                "select": 2,
            },
            [3, 6, 9, 12],
        ),
        (
            {
                "arrays": [[[1, 2], [3, 4]], [[2, 4], [6, 8]], [[3, 6], [9, 12]]],
                "select": 3,
            },
            None,
        ),
    ],
)

run(
    "Num2LittleEndianBytes(4)",
    [
        ({"in": [0x00]}, [0, 0, 0, 0]),
        ({"in": [0xDE]}, [0xDE, 0, 0, 0]),
        ({"in": [0xDEAD]}, [0xAD, 0xDE, 0, 0]),
        ({"in": [0xDEADBE]}, [0xBE, 0xAD, 0xDE, 0]),
        ({"in": [0xDEADBEEF]}, [0xEF, 0xBE, 0xAD, 0xDE]),
        ({"in": [0xFF]}, [0xFF, 0, 0, 0]),
        ({"in": [0xFFFFFFFF]}, [0xFF, 0xFF, 0xFF, 0xFF]),
        ({"in": [0xFFFFFFFF + 1]}, None),
    ],
)

run(
    "TruncatedAddressHash(3)",
    [
        (
            {
                "addressHashNibbles": [0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
                "addressHashNibblesLen": 6,
            },
            [0x20, 0x12, 0x34, 0x56, 4],
        ),
        (
            {
                "addressHashNibbles": [0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
                "addressHashNibblesLen": 5,
            },
            [0x32, 0x34, 0x56, 0x00, 3],
        ),
        (
            {
                "addressHashNibbles": [0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
                "addressHashNibblesLen": 4,
            },
            [0x20, 0x34, 0x56, 0x00, 3],
        ),
        (
            {
                "addressHashNibbles": [0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
                "addressHashNibblesLen": 3,
            },
            [0x34, 0x56, 0x00, 0x00, 2],
        ),
        (
            {
                "addressHashNibbles": [0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
                "addressHashNibblesLen": 2,
            },
            [0x20, 0x56, 0x00, 0x00, 2],
        ),
        (
            {
                "addressHashNibbles": [0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
                "addressHashNibblesLen": 1,
            },
            [0x36, 0x00, 0x00, 0x00, 1],
        ),
        (
            {
                "addressHashNibbles": [0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
                "addressHashNibblesLen": 0,
            },
            [0x20, 0x00, 0x00, 0x00, 1],
        ),
        (
            {
                "addressHashNibbles": [0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
                "addressHashNibblesLen": 7,
            },
            None,
        ),
    ],
)

run(
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

run(
    "RlpEmptyAccount(10)",
    [
        ({"balance": str(256**7 - 1234)}, rlp_empty_account(256**7 - 1234, 10)),
        ({"balance": str(256**10 - 1)}, rlp_empty_account(256**10 - 1, 10)),
        ({"balance": str(256**10)}, None),
    ],
)

run(
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

run(
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

run(
    "CountBytes(4)",
    [
        ({"bytes": [0, 0, 0, 0]}, [0]),
        ({"bytes": [5, 0, 0, 0]}, [4]),
        ({"bytes": [0, 6, 0, 0]}, [3]),
        ({"bytes": [0, 0, 7, 0]}, [2]),
        ({"bytes": [0, 0, 0, 8]}, [1]),
        ({"bytes": [10, 0, 0, 9]}, [4]),
        ({"bytes": [11, 12, 0, 13]}, [4]),
        ({"bytes": [15, 14, 0, 0]}, [4]),
        ({"bytes": [0, 14, 16, 0]}, [3]),
        ({"bytes": [0, 14, 10000, 0]}, [3]),
        ({"bytes": [0, 0, 10000, 0]}, [2]),
        ({"bytes": [0, 0, 10000, 543]}, [2]),
    ],
)

run(
    "LittleEndianBytes2Num(2)",
    [
        ({"in": [0, 0]}, [0]),
        ({"in": [0, 1]}, [256]),
        ({"in": [1, 0]}, [1]),
        ({"in": [1, 1]}, [257]),
        ({"in": [0, 128]}, [128 * 256]),
        ({"in": [128, 0]}, [128]),
        ({"in": [128, 128]}, [128 * 256 + 128]),
        ({"in": [12345, 23456]}, None),
    ],
)

run(
    "BigEndianBytes2Num(2)",
    [
        ({"in": [0, 0]}, [0]),
        ({"in": [0, 1]}, [1]),
        ({"in": [1, 0]}, [256]),
        ({"in": [1, 1]}, [257]),
        ({"in": [0, 128]}, [128]),
        ({"in": [128, 0]}, [128 * 256]),
        ({"in": [128, 128]}, [128 * 256 + 128]),
        ({"in": [12345, 23456]}, None),
    ],
)

run(
    "Divide(16)",
    [
        ({"a": [10], "b": 1}, [10, 0]),
        ({"a": [10], "b": 2}, [5, 0]),
        ({"a": [10], "b": 3}, [3, 1]),
        ({"a": [11], "b": 3}, [3, 2]),
        ({"a": [12], "b": 3}, [4, 0]),
        ({"a": [0], "b": 1}, [0, 0]),
        ({"a": [0], "b": 10}, [0, 0]),
    ],
)

run(
    "RlpInteger(3)",
    [
        ({"in": 0}, [0x80, 0, 0, 0, 1]),
        ({"in": 1}, [1, 0, 0, 0, 1]),
        ({"in": 3}, [3, 0, 0, 0, 1]),
        ({"in": 10}, [10, 0, 0, 0, 1]),
        ({"in": 127}, [127, 0, 0, 0, 1]),
        ({"in": 128}, [0x81, 128, 0, 0, 2]),
        ({"in": 0xFF}, [0x81, 0xFF, 0, 0, 2]),
        ({"in": 0x100}, [0x82, 1, 0, 0, 3]),
        ({"in": 0xFFFF}, [0x82, 0xFF, 0xFF, 0, 3]),
        ({"in": 0xFFFF}, [0x82, 0xFF, 0xFF, 0, 3]),
        ({"in": 0x10000}, [0x83, 1, 0, 0, 4]),
        ({"in": 0xFFFFFF}, [0x83, 0xFF, 0xFF, 0xFF, 4]),
        ({"in": 0x1000000}, None),
    ],
)

run(
    "RlpInteger(31)",
    [
        ({"in": str(256**31 - 1)}, [0x80 + 31] + [0xFF] * 31 + [32]),
        ({"in": str(256**31)}, None),
    ],
)

run(
    "Filter(5)",
    [
        ({"in": 0}, [0, 0, 0, 0, 0]),
        ({"in": 1}, [1, 0, 0, 0, 0]),
        ({"in": 3}, [1, 1, 1, 0, 0]),
        ({"in": 5}, [1, 1, 1, 1, 1]),
        ({"in": 10}, [1, 1, 1, 1, 1]),
    ],
)

run(
    "Mask(5)",
    [
        ({"in": [1, 2, 3, 4, 5], "count": 0}, [0, 0, 0, 0, 0]),
        ({"in": [1, 2, 3, 4, 5], "count": 2}, [1, 2, 0, 0, 0]),
        ({"in": [1, 2, 3, 4, 5], "count": 4}, [1, 2, 3, 4, 0]),
        ({"in": [1, 2, 3, 4, 5], "count": 5}, [1, 2, 3, 4, 5]),
        ({"in": [1, 2, 3, 4, 5], "count": 10}, [1, 2, 3, 4, 5]),
        ({"in": [1, 2, 3, 4, 5], "count": 1000}, [1, 2, 3, 4, 5]),
    ],
)

run(
    "ShiftRight(8, 3)",
    [
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 0},
            [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 1},
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 2},
            [0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 3},
            [0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 4},
            None,
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 100},
            None,
        ),
    ],
)


run(
    "ShiftLeft(8)",
    [
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 0},
            [1, 2, 3, 4, 5, 6, 7, 8],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 1},
            [2, 3, 4, 5, 6, 7, 8, 0],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 4},
            [5, 6, 7, 8, 0, 0, 0, 0],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 7},
            [8, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 8},
            [0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 9},
            None,
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 10},
            None,
        ),
        (
            {"in": [1, 2, 3, 4, 5, 6, 7, 8], "count": 100},
            None,
        ),
    ],
)

run(
    "Nibbles2Bytes(2)",
    [
        ({"nibbles": [1, 2, 3, 4]}, [0x12, 0x34]),
        ({"nibbles": [15, 2, 3, 4]}, [0xF2, 0x34]),
        ({"nibbles": [16, 2, 3, 4]}, None),
        ({"nibbles": [1, 16, 3, 4]}, None),
    ],
)


run(
    "Selector(5)",
    [
        ({"vals": [0, 10, 20, 30, 40], "select": 2}, [20]),
        ({"vals": [0, 10, 20, 30, 40], "select": 0}, [0]),
        ({"vals": [0, 10, 20, 30, 40], "select": 4}, [40]),
        ({"vals": [0, 10, 20, 30, 40], "select": 5}, None),
        ({"vals": [0, 10, 20, 30, 40], "select": 100}, None),
    ],
)


run(
    "SelectorArray1D(4, 5)",
    [
        (
            {
                "arrays": [
                    [11, 21, 31, 41, 51],
                    [12, 22, 32, 42, 52],
                    [13, 23, 33, 43, 53],
                    [14, 24, 34, 44, 54],
                ],
                "select": 0,
            },
            [11, 21, 31, 41, 51],
        ),
        (
            {
                "arrays": [
                    [11, 21, 31, 41, 51],
                    [12, 22, 32, 42, 52],
                    [13, 23, 33, 43, 53],
                    [14, 24, 34, 44, 54],
                ],
                "select": 1,
            },
            [12, 22, 32, 42, 52],
        ),
        (
            {
                "arrays": [
                    [11, 21, 31, 41, 51],
                    [12, 22, 32, 42, 52],
                    [13, 23, 33, 43, 53],
                    [14, 24, 34, 44, 54],
                ],
                "select": 2,
            },
            [13, 23, 33, 43, 53],
        ),
        (
            {
                "arrays": [
                    [11, 21, 31, 41, 51],
                    [12, 22, 32, 42, 52],
                    [13, 23, 33, 43, 53],
                    [14, 24, 34, 44, 54],
                ],
                "select": 3,
            },
            [14, 24, 34, 44, 54],
        ),
        (
            {
                "arrays": [
                    [11, 21, 31, 41, 51],
                    [12, 22, 32, 42, 52],
                    [13, 23, 33, 43, 53],
                    [14, 24, 34, 44, 54],
                ],
                "select": 4,
            },
            None,
        ),
    ],
)

run(
    "Concat(5,5)",
    [
        (
            {
                "a": [1, 2, 3, 4, 5],
                "aLen": 5,
                "b": [10, 20, 30, 40, 50],
                "bLen": 2,
            },
            [1, 2, 3, 4, 5, 10, 20, 0, 0, 0, 7],
        ),
        (
            {
                "a": [1, 2, 3, 4, 5],
                "aLen": 6,
                "b": [10, 20, 30, 40, 50],
                "bLen": 2,
            },
            None,
        ),
    ],
)

run(
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


def keccak(inp):
    return list(web3.Web3.keccak(inp))


def blockify(inp, blks):
    return list(inp) + [0] * (blks * 136 - len(inp))


run(
    "KeccakBytes(1)",
    [
        ({"in": blockify(b"", 1), "inLen": 0}, keccak(b"")),
        ({"in": blockify(b"salam", 1), "inLen": 5}, keccak(b"salam")),
        ({"in": blockify(b"salam", 1), "inLen": 4}, keccak(b"sala")),
        ({"in": blockify(b"a" * 135, 1), "inLen": 135}, keccak(b"a" * 135)),
        ({"in": blockify(b"a" * 136, 1), "inLen": 136}, None),
    ],
)

run(
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
