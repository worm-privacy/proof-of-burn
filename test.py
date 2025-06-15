import io
import subprocess
import json


def run(main, test_cases):
    with io.open("circuits/test.circom", "w") as f:
        imports = """
        pragma circom 2.2.2;
        
        include "utils/concat.circom";
        include "utils/hasher.circom";
        include "utils/leaf.circom";
        include "utils/rlp.circom";
        include "utils/selector.circom";
        include "utils/substring_finder.circom";
        include "utils/utils.circom";
        
        """
        f.write(imports + f"component main = {main};")
    subprocess.run(["circom", "-c", "circuits/test.circom"])
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
    "Shift(8, 3)",
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
    "NibblesToBytes(2)",
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


print(
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
)


run(
    "SubstringCheck(10, 3)",
    [
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 0,
                "subInput": [3, 4, 5],
            },
            None,
        ),
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 2,
                "subInput": [3, 4, 5],
            },
            None,
        ),
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 3,
                "subInput": [1, 2, 3],
            },
            [1],
        ),
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 3,
                "subInput": [3, 4, 5],
            },
            [0],
        ),
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 4,
                "subInput": [3, 4, 5],
            },
            [0],
        ),
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 5,
                "subInput": [3, 4, 5],
            },
            [1],
        ),
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 9,
                "subInput": [8, 9, 10],
            },
            [0],
        ),
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 10,
                "subInput": [8, 9, 10],
            },
            [1],
        ),
        (
            {
                "mainInput": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "mainLen": 11,
                "subInput": [8, 9, 10],
            },
            None,
        ),
    ],
)
