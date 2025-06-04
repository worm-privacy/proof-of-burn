pub fn contains<let S: u32, let N: u32>(
    sub_array: [u8; S],
    array: [u8; N],
    array_size: u32,
) -> bool {
    let mut found = false;
    for i in 0..N - S + 1 {
        let mut equals = true;
        for j in 0..S {
            equals = equals & (array[i + j] == sub_array[j]);
        }
        if i + S <= array_size {
            found = found | equals;
        }
    }
    found
}

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
