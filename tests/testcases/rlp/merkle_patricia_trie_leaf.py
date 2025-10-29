test_truncated_address_hash = (
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

test_is_in_range = (
    "IsInRange(16)",
    [
        ({"lower": 10, "value": 10, "upper": 10}, [1]),
        ({"lower": 10, "value": 10, "upper": 30}, [1]),
        ({"lower": 10, "value": 20, "upper": 30}, [1]),
        ({"lower": 10, "value": 20, "upper": 19}, [0]),
        ({"lower": 21, "value": 20, "upper": 30}, [0]),
        ({"lower": 19, "value": 20, "upper": 21}, [1]),
        ({"lower": 21, "value": 20, "upper": 19}, [0]),
    ],
)

l1 = [0xF8, 12] + [0x83, 1, 2, 3] + [0xB8, 6] + [0xF8, 4] + [1, 2, 3, 4] + [0, 0]
l2 = [0xF8, 12] + [0x82, 1, 2, 3] + [0xB8, 6] + [0xF8, 4] + [1, 2, 3, 4] + [0, 0]
l3 = [0xF8, 12] + [0x82, 1, 2] + [0xB8, 6] + [0xF8, 4] + [1, 2, 3, 4] + [0, 0, 0]
l4 = [0xF8, 11] + [0x82, 1, 2] + [0xB8, 6] + [0xF8, 4] + [1, 2, 3, 4] + [0, 0, 0]
l5 = [0xF8, 12] + [0x83, 1, 2, 3] + [0xB8, 7] + [0xF8, 4] + [1, 2, 3, 4] + [0, 0]
l6 = [0xF8, 12] + [0x83, 1, 2, 3] + [0xB8, 7] + [0xF8, 5] + [1, 2, 3, 4] + [0, 0]
l7 = [0xF8, 13] + [0x83, 1, 2, 3] + [0xB8, 7] + [0xF8, 5] + [1, 2, 3, 4, 5] + [0]
l8 = [0xF8, 12] + [0x83, 1, 2, 3] + [0xB8, 7] + [0xF8, 5] + [1, 2, 3, 4, 5] + [0]

test_leaf_detector_1 = (
    "LeafDetector(16)",
    [
        ({"layer": l1, "layerLen": 14}, [1]),
        ({"layer": l1, "layerLen": 13}, [0]),
        ({"layer": l2, "layerLen": 13}, [0]),
        ({"layer": l3, "layerLen": 13}, [0]),
        ({"layer": l4, "layerLen": 13}, [1]),
        ({"layer": l5, "layerLen": 14}, [0]),
        ({"layer": l5, "layerLen": 15}, [0]),
        ({"layer": l6, "layerLen": 15}, [0]),
        ({"layer": l7, "layerLen": 15}, [1]),
        ({"layer": l8, "layerLen": 14}, [0]),  # isKeyValueLenEqualWithLayerLen
    ],
)

shortest = list(
    bytes.fromhex(
        "f84920b846f8448080a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
)
longest = list(
    bytes.fromhex(
        "f8aaa120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb886f884a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
)
test_leaf_detector_2 = (
    "LeafDetector(544)",
    [
        (
            {
                "layer": shortest + [0] * (544 - len(shortest)),
                "layerLen": len(shortest),
            },
            [1],
        ),
        (
            {
                "layer": longest + [0] * (544 - len(longest)),
                "layerLen": len(longest),
            },
            [1],
        ),
    ],
)
