mod contains;
mod rlp;
use contains::contains;
use rlp::account_rlp;

global MAX_TRIE_NODE_LENGTH: u32 = 512;
global MAX_LAYER_COUNT: u32 = 10;

fn main(
    address: [u8; 20],
    balance: u128,
    layers: [[u8; MAX_TRIE_NODE_LENGTH]; MAX_LAYER_COUNT],
    layerSizes: [u32; MAX_LAYER_COUNT],
) {
    let burn_rlp = account_rlp(balance);
    let address_hash = keccak256::keccak256(address, 20);
    for i in 0..MAX_LAYER_COUNT - 1 {
        let keccakLayer = keccak256::keccak256(layers[i], layerSizes[i]);
        let con = contains(keccakLayer, layers[i + 1], layerSizes[i + 1]);
    }
}
