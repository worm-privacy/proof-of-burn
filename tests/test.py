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


from .testcases.public_commitment import (
    test_public_commitment_1,
    test_public_commitment_2,
    test_public_commitment_6,
)
from .testcases.rlp.merkle_patricia_trie_leaf import (
    test_truncated_address_hash,
    test_is_in_range,
    test_leaf_detector_1,
    test_leaf_detector_2,
)
from .testcases.divide import test_divide
from .testcases.poseidon import test_poseidon
from .testcases.substring_check import test_substring_check
from .testcases.shift import test_shift_left, test_shift_right
from .testcases.concat import test_concat, test_mask
from .testcases.selector import (
    test_selector,
    test_selector_array_1d,
    test_selector_array_2d,
)
from .testcases.convert import (
    test_big_endian_bytes_2_num,
    test_bytes_2_nibbles,
    test_little_endian_bytes_2_num,
    test_num_2_big_endian_bytes,
    test_num_2_little_endian_bytes,
    test_nibbles_2_bytes,
)
from .testcases.keccak import test_pad, test_keccak_1, test_keccak_2
from .testcases.burn_address import test_burn_address_hash
from .testcases.assertion import (
    test_assert_bits,
    test_assert_byte_string,
    test_assert_greater_eq_than,
    test_assert_less_eq_than,
    test_assert_less_than,
)
from .testcases.array import (
    test_fit_1,
    test_fit_2,
    test_reverse,
    test_flatten,
    test_filter,
)
from .testcases.rlp.integer import (
    test_rlp_integer_1,
    test_rlp_integer_2,
    test_count_bytes,
)
from .testcases.proof_of_burn import test_proof_of_burn
from .testcases.rlp.empty_account import (
    test_rlp_empty_account_1,
    test_rlp_empty_account_2,
    test_rlp_empty_account_3,
)

run(*test_public_commitment_1)
run(*test_public_commitment_2)
run(*test_public_commitment_6)
run(*test_poseidon)
run(*test_divide)
run(*test_substring_check)
run(*test_shift_left)
run(*test_shift_right)
run(*test_mask)
run(*test_concat)
run(*test_selector)
run(*test_selector_array_1d)
run(*test_selector_array_2d)
run(*test_big_endian_bytes_2_num)
run(*test_bytes_2_nibbles)
run(*test_little_endian_bytes_2_num)
run(*test_num_2_big_endian_bytes)
run(*test_num_2_little_endian_bytes)
run(*test_nibbles_2_bytes)
run(*test_pad)
run(*test_keccak_1)
run(*test_keccak_2)
run(*test_burn_address_hash)
run(*test_assert_bits)
run(*test_assert_byte_string)
run(*test_assert_less_eq_than)
run(*test_assert_less_than)
run(*test_assert_greater_eq_than)
run(*test_proof_of_burn)
run(*test_filter)
run(*test_fit_1)
run(*test_fit_2)
run(*test_reverse)
run(*test_flatten)
run(*test_rlp_integer_1)
run(*test_rlp_integer_2)
run(*test_count_bytes)
run(*test_rlp_empty_account_1)
run(*test_rlp_empty_account_2)
run(*test_rlp_empty_account_3)
run(*test_truncated_address_hash)
run(*test_is_in_range)
run(*test_leaf_detector_1)
run(*test_leaf_detector_2)
