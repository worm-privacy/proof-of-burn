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
