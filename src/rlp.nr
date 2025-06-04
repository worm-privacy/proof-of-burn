use super::utils::{concat, u128_to_be};

// Rlp of a single integer below 2^128
fn int_rlp(num: u128) -> ([u8; 17], u32) {
    let mut ret: [u8; 17] = [0; 17];
    if num == 0 {
        ret[0] = 0x80;
        (ret, 1)
    } else if num < 128 {
        ret[0] = num as u8;
        (ret, 1)
    } else {
        let (bytes, byte_count) = u128_to_be(num);
        ret[0] = 0x80 + byte_count as u8;
        for i in 0..16 {
            ret[1 + i] = bytes[i]
        }
        (ret, byte_count + 1)
    }
}

// Rlp of an account with empty code/storage and nonce 0 with the given balance
pub fn account_rlp(balance: u128) -> ([u8; 86], u32) {
    let nonce_rlp = ([0x80], 1);
    let balance_rlp = int_rlp(balance);
    let empty_storage_code: ([u8; 66], u32) = (
        [
            160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72,
            224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1,
            134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39,
            59, 123, 250, 216, 4, 93, 133, 164, 112,
        ], 66,
    );
    let nonce_balance = concat(nonce_rlp, balance_rlp);
    let nonce_balance_storage_hash_code_hash = concat(nonce_balance, empty_storage_code);

    let mut finalized = [0; 86];
    finalized[0] = 0xf8;
    finalized[1] = nonce_balance_storage_hash_code_hash.1 as u8;
    for i in 0..84 {
        finalized[2 + i] = nonce_balance_storage_hash_code_hash.0[i];
    }
    (finalized, nonce_balance_storage_hash_code_hash.1 + 2)
}
