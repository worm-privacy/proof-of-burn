import io
import subprocess
import json


def run(main, input):
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
    subprocess.run(["make"], cwd="test_cpp/")
    with io.open("test_cpp/input.json", "w") as f:
        json.dump(input, f)
    subprocess.run(["./test", "input.json", "witness.wtns"], cwd="test_cpp/")


run(
    "Concat(5,5)",
    {
        "a": [1, 2, 3, 4, 5],
        "aLen": 3,
        "b": [10, 20, 30, 40, 50],
        "bLen": 2,
    },
)
