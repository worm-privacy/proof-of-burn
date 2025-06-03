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

fn main(layers: [[u8; MAX_TRIE_NODE_LENGTH]; MAX_LAYER_COUNT], layerSizes: [u32; MAX_LAYER_COUNT]) {
    for i in 0..MAX_LAYER_COUNT - 1 {
        let keccakLayer = keccak256::keccak256(layers[i], layerSizes[i]);
        let con = contains(keccakLayer, layers[i + 1], layerSizes[i + 1]);
    }
}
