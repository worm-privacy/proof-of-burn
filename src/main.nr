pub mod utils;
mod rlp;
use keccak256::keccak256;
use rlp::account_rlp;
use std::hash;
use utils::{concat, contains};

global MAX_LEAF_PREFIX_LENGTH: u32 = 64;
global MAX_TRIE_NODE_LENGTH: u32 = 600;
global MAX_LAYER_COUNT: u32 = 11;
global PREFIX_SECURITY: u32 = 20;

fn compress_to_fields<let B: u32, let C: u32>(inp: [u8; B * C]) -> [Field; C] {
    let mut ret = [0; C];
    for i in 0..C {
        let mut bytes = [0; B];
        for j in 0..B {
            bytes[j] = inp[B * i + j];
        }
        ret[i] = Field::from_be_bytes(bytes);
    }
    ret
}

fn cheap_commit<let B: u32, let C: u32>(layer: [u8; B * C], salt: Field) -> Field {
    let mut fields = compress_to_fields::<B, C>(layer);
    let mut fields_with_salt: [Field; C + 1] = [0; C + 1];
    for i in 0..C {
        fields_with_salt[i] = fields[i];
    }
    fields_with_salt[C] = salt;
    hash::hash_to_field(fields)
}

fn main(
    leaf_prefix: [u8; MAX_LEAF_PREFIX_LENGTH],
    leaf_prefix_len: u32,
    layers: [[u8; MAX_TRIE_NODE_LENGTH]; MAX_LAYER_COUNT],
    layer_lens: [u32; MAX_LAYER_COUNT],
    secret: Field,
    address: [u8; 20],
    balance: pub u128,
    num_layers: u32,
) -> pub (Field, Field) {
    let nullifier = hash::hash_to_field([secret, 123]);

    let hashed_secret: [u8; 32] = hash::hash_to_field([secret]).to_be_bytes();
    for i in 0..20 {
        println(hashed_secret[i] == address[i]);
    }
    let address_hash = keccak256::keccak256(address, 20);
    // The leaf prefix should end with the last `PREFIX_SECURITY` bytes of address hash
    for i in 0..PREFIX_SECURITY {
        assert_eq(leaf_prefix[leaf_prefix_len - 1 - i], address_hash[32 - 1 - i]);
    }
    let burn_rlp = account_rlp(balance);
    let mut prefix2 = [0; 2];
    prefix2[0] = 0xb8;
    prefix2[1] = burn_rlp.1 as u8;

    let leaf = concat(
        concat((leaf_prefix, leaf_prefix_len), (prefix2, 2)),
        burn_rlp,
    );

    // Check if keccak(leaf) is within layer[0]
    assert(contains(keccak256(leaf.0, leaf.1), layers[0], layer_lens[0]));

    // Go through layers and check if `keccak(layer[i])` is within `layer[i+1]`
    let mut last_keccak = [0; 32];
    for i in 0..MAX_LAYER_COUNT - 1 {
        if i < num_layers {
            let keccakLayer = keccak256::keccak256(layers[i], layer_lens[i]);
            last_keccak = keccakLayer;
            if i + 1 < num_layers {
                assert(contains(keccakLayer, layers[i + 1], layer_lens[i + 1]));
            }
        }
    }

    last_keccak[0] = 0;

    (Field::from_be_bytes(last_keccak), nullifier)
}
