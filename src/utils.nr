// Returns true when `array` contains a `sub_array`
pub fn contains<let S: u32, let N: u32>(
    sub_array: [u8; S],
    array: [u8; N],
    array_size: u32,
) -> bool {
    let mut powers_of_256: [Field; N] = [0; N];
    powers_of_256[0] = 1;
    for i in 1..N {
        powers_of_256[i] = powers_of_256[i - 1] * 256;
    }

    let mut found = false;

    let mut target = 0;
    for i in 0..S {
        target = target + sub_array[i] as Field * powers_of_256[i];
    }

    let mut vals: [Field; N + 1] = [0; N + 1];
    vals[0] = 0;
    for i in 0..N {
        vals[i + 1] = vals[i] + (array[i] as Field) * powers_of_256[i];
        if i + 1 >= S & i < array_size {
            let val = vals[i + 1] - vals[i + 1 - S];
            let equals = val == target * powers_of_256[i + 1 - S];
            found = found | equals;
        }
    }

    found
}

#[test]
fn test_contains() {
    assert(contains([5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7, 8], 9));
    assert(contains([5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7, 8], 8));
    assert(!contains([5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7, 8], 7));
    assert(!contains([5, 6, 8], [0, 1, 2, 3, 4, 5, 6, 7, 8], 9));
}

// Decompose a u128 into big-endian bytes
pub fn u128_to_be(mut num: u128) -> ([u8; 16], u32) {
    let mut cnt = 0;
    let mut bytes: [u8; 16] = [0; 16];
    for i in 0..16 {
        if num > 0 {
            cnt += 1;
            bytes[i] = (num & 255) as u8;
            num = num >> 8;
        }
    }
    // Convert to big-endian
    let mut rev_bytes: [u8; 16] = [0; 16];
    for i in 0..16 {
        if i < cnt {
            rev_bytes[i] = bytes[cnt - 1 - i];
        }
    }
    (rev_bytes, cnt)
}

// Concat two dynamic arrays
pub fn concat<let M: u32, let N: u32>(a: ([u8; M], u32), b: ([u8; N], u32)) -> ([u8; M + N], u32) {
    assert(a.1 <= M);
    assert(b.1 <= N);
    let mut ret = [0; M + N];
    for i in 0..M + N {
        if i < a.1 {
            ret[i] = a.0[i];
        } else if i < a.1 + b.1 {
            ret[i] = b.0[i - a.1];
        }
    }
    (ret, a.1 + b.1)
}
