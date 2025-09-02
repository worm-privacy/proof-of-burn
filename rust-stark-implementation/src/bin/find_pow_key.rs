//! Utility to find a burn key that satisfies Proof-of-Work requirements

use proof_of_burn_stark::crypto::keccak::KeccakHasher;
use rand::Rng;
use std::time::Instant;

fn main() {
    let receiver = [144, 248, 191, 106, 71, 159, 50, 14, 173, 7, 68, 17, 164, 176, 231, 148, 78, 168, 201, 193];
    let fee = 123u64;
    let min_zero_bytes = 2; // Production requirement
    
    println!("🔍 Finding burn key with {} zero bytes for Proof-of-Work...", min_zero_bytes);
    println!("Receiver: {:?}", hex::encode(&receiver));
    println!("Fee: {}", fee);
    
    let start = Instant::now();
    let mut rng = rand::thread_rng();
    let mut attempts = 0u64;
    let hasher = KeccakHasher::new();
    
    loop {
        attempts += 1;
        
        // Generate random burn key
        let mut burn_key = [0u8; 32];
        rng.fill(&mut burn_key[..]);
        
        // Calculate PoW (must match ProofOfWorkComponent)
        let mut pow_input = Vec::new();
        
        // Add burn key
        pow_input.extend_from_slice(&burn_key);
        
        // Add receiver address (20 bytes)
        pow_input.extend_from_slice(&receiver);
        
        // Add fee as 32-byte big-endian
        let fee_bytes = fee.to_be_bytes();
        let mut fee_32 = [0u8; 32];
        fee_32[24..].copy_from_slice(&fee_bytes);
        pow_input.extend_from_slice(&fee_32);
        
        // Add EIP-7503 suffix
        const EIP_7503_SUFFIX: &[u8] = b"WormBurn";
        pow_input.extend_from_slice(EIP_7503_SUFFIX);
        
        let hash = hasher.keccak256(&pow_input);
        
        // Check if it has enough leading zeros
        let mut zero_bytes = 0;
        for byte in hash.iter() {
            if *byte == 0 {
                zero_bytes += 1;
            } else {
                break;
            }
        }
        
        if zero_bytes >= min_zero_bytes {
            let elapsed = start.elapsed();
            println!("\n✅ Found valid burn key after {} attempts in {:.2?}", attempts, elapsed);
            println!("Burn key: {:?}", burn_key);
            println!("Burn key (hex): 0x{}", hex::encode(&burn_key));
            println!("Hash: 0x{}", hex::encode(&hash));
            println!("Zero bytes: {}", zero_bytes);
            
            // Create JSON for test input
            println!("\n📋 Update your test input with:");
            println!("\"burn_key\": {:?},", burn_key.to_vec());
            break;
        }
        
        if attempts % 100000 == 0 {
            println!("... {} attempts, still searching...", attempts);
        }
    }
}
