global MAX_TRIE_NODE_LENGTH: u32 = 512;
global MAX_LAYER_COUNT: u32 = 10;

fn contains(hash: [u8; 32], layer: [u8; MAX_TRIE_NODE_LENGTH], array_size: u32) -> bool {
    let mut found = false;
    for i in 0..MAX_TRIE_NODE_LENGTH - 32 {
        let mut equals = true;
        for j in 0..32 {
            equals = equals & (layer[i + j] == hash[j]);
        }
        if i + 32 <= array_size {
            found = found | equals;
        }
    }
    found
}

fn to_bytes(mut num: u128) -> ([u8; 16], u32) {
    let mut cnt = 0;
    let mut bytes: [u8; 16] = [0; 16];
    for i in 0..16 {
        if num > 0 {
            cnt += 1;
            bytes[i] = (num % 256) as u8;
            num = num >> 8;
        }
    }
    (bytes, cnt)
}

fn int_rlp(num: u128) -> ([u8; 17], u32) {
    let mut ret: [u8; 17] = [0; 17];
    if num < 128 {
        ret[0] = num as u8;
        (ret, 1)
    } else {
        let (bytes, byte_count) = to_bytes(num);
        ret[0] = 0x80 + byte_count as u8;
        for i in 0..16 {
            ret[1 + i] = bytes[i]
        }
        (ret, byte_count + 1)
    }
}

fn concat<let M: u32, let N: u32>(a: ([u8; M], u32), b: ([u8; N], u32)) -> ([u8; M + N], u32) {
    assert(a.1 <= M);
    assert(b.1 <= N);
    let mut ret = [0; M + N];
    let mut ret_size = 0;
    for i in 0..M + N {
        if i < a.1 {
            ret[i] = a.0[i];
        } else if i < a.1 + b.1 {
            ret[i] = b.0[i - a.1];
        }
    }
    (ret, ret_size)
}

fn bytes32_rlp(bytes: [u8; 32]) -> ([u8; 33], u32) {
    let mut ret = [0; 33];
    ret[0] = 0x80 + 32;
    for i in 0..32 {
        ret[i + 1] = bytes[i];
    }
    (ret, 33)
}

fn account_rlp(
    nonce: u128,
    balance: u128,
    storage_hash: [u8; 32],
    code_hash: [u8; 32],
) -> ([u8; 101], u32) {
    let nonce_rlp = int_rlp(nonce);
    let balance_rlp = int_rlp(balance);
    let storage_hash_rlp = bytes32_rlp(storage_hash);
    let code_hash_rlp = bytes32_rlp(code_hash);
    let nonce_balance = concat(nonce_rlp, balance_rlp);
    let nonce_balance_storage_hash = concat(nonce_balance, storage_hash_rlp);
    let nonce_balance_storage_hash_code_hash = concat(nonce_balance_storage_hash, code_hash_rlp);

    let mut finalized = [0; 101];
    finalized[0] = nonce_balance_storage_hash_code_hash.1 as u8;
    for i in 0..100 {
        finalized[1 + i] = nonce_balance_storage_hash_code_hash.0[i];
    }
    (finalized, nonce_balance_storage_hash_code_hash.1 + 1)
}

fn main(layers: [[u8; MAX_TRIE_NODE_LENGTH]; MAX_LAYER_COUNT], layerSizes: [u32; MAX_LAYER_COUNT]) {
    for i in 0..MAX_LAYER_COUNT - 1 {
        let keccakLayer = keccak256::keccak256(layers[i], layerSizes[i]);
        let con = contains(keccakLayer, layers[i + 1], layerSizes[i + 1]);
    }
}
