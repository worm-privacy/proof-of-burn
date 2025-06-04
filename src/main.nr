pub mod utils;
mod rlp;
use keccak256::keccak256;
use rlp::account_rlp;
use utils::{concat, contains};

global MAX_TRIE_NODE_LENGTH: u32 = 768;
global MAX_LAYER_COUNT: u32 = 10;
global PREFIX_SECURITY: u32 = 20;

fn main(
    leaf_prefix: [u8; MAX_TRIE_NODE_LENGTH],
    leaf_prefix_size: u32,
    address: [u8; 20],
    balance: u128,
    layers: [[u8; MAX_TRIE_NODE_LENGTH]; MAX_LAYER_COUNT],
    layer_sizes: [u32; MAX_LAYER_COUNT],
    num_layers: u32,
) -> pub [u8; 32] {
    let address_hash = keccak256::keccak256(address, 20);
    // The leaf prefix should end with the last `PREFIX_SECURITY` bytes of address hash
    for i in 0..PREFIX_SECURITY {
        assert_eq(leaf_prefix[leaf_prefix_size - 1 - i], address_hash[32 - 1 - i]);
    }
    let burn_rlp = account_rlp(balance);
    let mut prefix2 = [0; 2];
    prefix2[0] = 0xb8;
    prefix2[1] = burn_rlp.1 as u8;

    let leaf = concat(
        concat((leaf_prefix, leaf_prefix_size), (prefix2, 2)),
        burn_rlp,
    );

    let leaf_keccak = keccak256(leaf.0, leaf.1);

    assert(contains(leaf_keccak, layers[0], layer_sizes[0]));

    let mut last_keccak = [0; 32];
    for i in 0..MAX_LAYER_COUNT - 1 {
        if i < num_layers {
            let keccakLayer = keccak256::keccak256(layers[i], layer_sizes[i]);
            last_keccak = keccakLayer;
            if i + 1 < num_layers {
                assert(contains(keccakLayer, layers[i + 1], layer_sizes[i + 1]));
            }
        }
    }

    last_keccak
}
