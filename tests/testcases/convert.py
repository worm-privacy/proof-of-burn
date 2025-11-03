from ..poseidon import FIELD_SIZE, Field


# Number to 256-bit little-endian list
def field_to_be_bytes(elem):
    return list(int.to_bytes(elem, 32, "big"))


def field_to_le_bits(elem, length):
    binary = bin(elem)[2:]
    binary = "0" * (length - len(binary)) + binary
    return [1 if b == "1" else 0 for b in reversed(list(binary))]


test_num_2_bits_safe_32 = (
    "Num2BitsSafe(32)",
    [
        ({"in": 0}, field_to_le_bits(0, 32)),
        ({"in": 123}, field_to_le_bits(123, 32)),
        ({"in": 7**10}, field_to_le_bits(7**10, 32)),
        ({"in": 2**32 - 1}, field_to_le_bits(2**32 - 1, 32)),
        ({"in": 2**32}, None),
        ({"in": 2**32 + 1}, None),
    ],
)

test_num_2_bits_safe_254 = (
    "Num2BitsSafe(254)",
    [
        ({"in": 0}, field_to_le_bits(0, 254)),
        ({"in": 123}, field_to_le_bits(123, 254)),
        ({"in": 7**10}, field_to_le_bits(7**10, 254)),
        ({"in": 2**32 - 1}, field_to_le_bits(2**32 - 1, 254)),
        ({"in": 2**32}, field_to_le_bits(2**32, 254)),
        ({"in": 2**32 + 1}, field_to_le_bits(2**32 + 1, 254)),
        ({"in": str(FIELD_SIZE - 1)}, field_to_le_bits(FIELD_SIZE - 1, 254)),
    ],
)


test_num_2_bits_safe_256 = (
    "Num2BitsSafe(256)",
    [
        ({"in": 0}, field_to_le_bits(0, 256)),
        ({"in": 123}, field_to_le_bits(123, 256)),
        ({"in": 7**10}, field_to_le_bits(7**10, 256)),
        ({"in": str(FIELD_SIZE - 1)}, field_to_le_bits(FIELD_SIZE - 1, 256)),
    ],
)

test_num_2_big_endian_bytes = (
    "Num2BigEndianBytes(32)",
    [
        ({"in": 123}, field_to_be_bytes(123)),
        ({"in": 0}, field_to_be_bytes(0)),
        ({"in": 1}, field_to_be_bytes(1)),
        ({"in": str(3**150)}, field_to_be_bytes(3**150)),
        ({"in": str(FIELD_SIZE - 10)}, field_to_be_bytes(FIELD_SIZE - 10)),
        ({"in": str(FIELD_SIZE - 1)}, field_to_be_bytes(FIELD_SIZE - 1)),
    ],
)

test_bytes_2_nibbles = (
    "Bytes2Nibbles(3)",
    [
        ({"in": [0xAB, 0x12, 0xF5]}, [0xA, 0xB, 0x1, 0x2, 0xF, 0x5]),
    ],
)

test_num_2_little_endian_bytes = (
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


test_little_endian_bytes_2_num = (
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

test_big_endian_bytes_2_num = (
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

test_nibbles_2_bytes = (
    "Nibbles2Bytes(2)",
    [
        ({"nibbles": [1, 2, 3, 4]}, [0x12, 0x34]),
        ({"nibbles": [15, 2, 3, 4]}, [0xF2, 0x34]),
        ({"nibbles": [16, 2, 3, 4]}, None),
        ({"nibbles": [1, 16, 3, 4]}, None),
    ],
)
