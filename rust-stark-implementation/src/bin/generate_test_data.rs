use proof_of_burn_stark::ProofOfBurnInputs;
use serde_json;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Generating valid MPT test data...");
    
    // Create a simple valid MPT structure
    // For now, we'll create a minimal valid structure
    
    // Generate address hash nibbles from a real address
    let address = [0x90, 0xf8, 0xbf, 0x6a, 0x47, 0x9f, 0x32, 0x0e, 0xad, 0x07, 
                   0x44, 0x11, 0xa4, 0xb0, 0xe7, 0x94, 0x4e, 0xa8, 0xc9, 0xc1];
    
    // Calculate Keccak hash of address
    use tiny_keccak::{Hasher, Keccak};
    let mut keccak = Keccak::v256();
    keccak.update(&address);
    let mut address_hash = [0u8; 32];
    keccak.finalize(&mut address_hash);
    
    // Convert to nibbles
    let mut address_hash_nibbles = [0u8; 64];
    for i in 0..32 {
        address_hash_nibbles[i * 2] = (address_hash[i] >> 4) & 0x0f;
        address_hash_nibbles[i * 2 + 1] = address_hash[i] & 0x0f;
    }
    
    println!("Address hash nibbles: {:?}", &address_hash_nibbles[..16]);
    
    // Create a simple 2-layer MPT structure
    // Layer 0: Branch node (root)
    // Layer 1: Leaf node with account
    
    // Create account RLP: [nonce, balance, storageRoot, codeHash]
    use rlp::RlpStream;
    let mut account_rlp = RlpStream::new_list(4);
    account_rlp.append(&0u8); // nonce
    account_rlp.append(&1000000000000000000u64); // balance (1 ETH)
    account_rlp.append(&vec![0u8; 32]); // empty storage root
    account_rlp.append(&vec![0u8; 32]); // empty code hash
    let account_bytes = account_rlp.out();
    
    // Create leaf node with compact encoding
    let mut leaf_rlp = RlpStream::new_list(2);
    // Compact encode the remaining path (assuming we follow nibble 9)
    let remaining_path = &address_hash_nibbles[1..40]; // Skip first nibble, use 39 more
    let mut compact_path = vec![0x20]; // Even length, terminating
    for i in 0..(remaining_path.len() / 2) {
        compact_path.push((remaining_path[i * 2] << 4) | remaining_path[i * 2 + 1]);
    }
    leaf_rlp.append(&compact_path);
    leaf_rlp.append(&account_bytes);
    let leaf_bytes = leaf_rlp.out();
    
    // Calculate leaf hash
    let mut keccak = Keccak::v256();
    keccak.update(&leaf_bytes);
    let mut leaf_hash = [0u8; 32];
    keccak.finalize(&mut leaf_hash);
    
    // Create branch node with leaf hash at position of first nibble
    let mut branch_rlp = RlpStream::new_list(17);
    for i in 0..16 {
        if i == (address_hash_nibbles[0] as usize) {
            branch_rlp.append(&leaf_hash.to_vec());
        } else {
            branch_rlp.append_empty_data();
        }
    }
    branch_rlp.append_empty_data(); // No value at branch
    let branch_bytes = branch_rlp.out();
    
    // Calculate branch hash (this will be our state root)
    let mut keccak = Keccak::v256();
    keccak.update(&branch_bytes);
    let mut state_root = [0u8; 32];
    keccak.finalize(&mut state_root);
    
    println!("Generated state root: {:02x?}", state_root);
    
    // Create simplified block header with our state root
    let mut header_rlp = RlpStream::new_list(15);
    header_rlp.append(&vec![0u8; 32]); // parent hash
    header_rlp.append(&vec![0u8; 32]); // uncles hash
    header_rlp.append(&vec![0u8; 20]); // coinbase
    header_rlp.append(&state_root.to_vec()); // state root (field 3)
    header_rlp.append(&vec![0u8; 32]); // transactions root
    header_rlp.append(&vec![0u8; 32]); // receipts root
    header_rlp.append(&vec![0u8; 256]); // bloom
    header_rlp.append(&0u64); // difficulty
    header_rlp.append(&19000000u64); // block number
    header_rlp.append(&3000000u64); // gas limit
    header_rlp.append(&1000000u64); // gas used
    header_rlp.append(&1700000000u64); // timestamp
    header_rlp.append(&Vec::<u8>::new()); // extra data
    header_rlp.append(&vec![0u8; 32]); // mix hash
    header_rlp.append(&0u64); // nonce
    let header_bytes = header_rlp.out();
    
    // Prepare layers for JSON
    let layers = vec![
        branch_bytes.to_vec(),
        leaf_bytes.to_vec(),
    ];
    
    let layer_lens = vec![branch_bytes.len(), leaf_bytes.len()];
    
    // Create test input
    let test_input = ProofOfBurnInputs {
        burn_key: [124, 205, 203, 162, 0, 135, 117, 167, 218, 84, 221, 75, 47, 81, 236, 218, 
                   102, 162, 21, 189, 45, 124, 203, 208, 0, 70, 15, 201, 79, 96, 8, 24],
        balance: 1000000000000000000,
        fee: 123,
        spend: 234,
        receiver_address: address,
        num_leaf_address_nibbles: 40, // Using 40 nibbles for the leaf
        layers,
        layer_lens,
        num_layers: 2,
        block_header: {
            let mut bh = vec![0u8; 1024];
            bh[..header_bytes.len()].copy_from_slice(&header_bytes);
            bh
        },
        block_header_len: header_bytes.len(),
        state_root,
        address_hash_nibbles,
        byte_security_relax: 0,
    };
    
    // Save to file
    let json = serde_json::to_string_pretty(&test_input)?;
    fs::write("valid_test_input.json", json)?;
    
    println!("✅ Valid test data saved to valid_test_input.json");
    println!("   State root: {:02x?}", &state_root[..8]);
    println!("   First nibble: {}", address_hash_nibbles[0]);
    
    Ok(())
}
