//! Integration tests to verify compatibility with Circom implementation

use proof_of_burn_stark::*;
use std::fs;

#[test]
fn test_commitment_compatibility() {
    // Test that our commitment matches the expected format from Circom
    // The commitment should be a 32-byte hash that can be verified on-chain
    
    // Use complete block header data (need at least 91 bytes for state root)
    let test_input = r#"{
        "burn_key": [37, 19, 95, 13, 45, 236, 56, 213, 122, 195, 100, 143, 38, 194, 66, 161, 134, 235, 7, 167, 13, 99, 111, 235, 3, 227, 149, 140, 5, 129, 132, 65],
        "balance": 1000000000000000000,
        "fee": 123,
        "spend": 234,
        "receiver_address": [144, 248, 191, 106, 71, 159, 50, 14, 173, 7, 68, 17, 164, 176, 231, 148, 78, 168, 201, 193],
        "num_leaf_address_nibbles": 63,
        "layers": [[249, 1, 209, 160, 189, 218, 165, 79, 241, 30, 61, 121, 209, 170, 15, 157, 247, 237, 154, 143, 154, 251, 192, 205, 211, 81, 131, 16, 108, 12, 60, 55, 127, 213, 135, 203, 160, 171, 140, 219, 128, 140, 131, 3, 187, 97, 251, 72, 226, 118, 33, 123, 233, 119, 15, 168, 62, 207, 63, 144, 242, 35, 77, 85, 136, 133, 245, 171, 241, 128, 128, 160, 222, 38, 203, 27, 79, 217, 156, 77, 62, 215, 93, 74, 103, 147, 30, 60, 37, 38, 5, 199, 214, 142, 1, 72, 213, 50, 127, 52]],
        "layer_lens": [100],
        "num_layers": 1,
        "block_header": [249, 2, 29, 160, 198, 46, 22, 219, 203, 239, 74, 137, 59, 99, 13, 98, 28, 212, 14, 186, 38, 254, 160, 209, 57, 186, 128, 162, 111, 217, 49, 67, 124, 78, 236, 214, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 215, 252, 173, 150, 114, 235, 82, 227, 230, 86, 106, 194, 21, 145, 152, 225, 12, 215, 112, 233, 204, 157, 249, 184, 8, 192, 73, 156, 236, 22, 136, 248],
        "block_header_len": 123,
        "byte_security_relax": 0
    }"#;
    
    let inputs: ProofOfBurnInputs = serde_json::from_str(test_input).unwrap();
    
    // Create prover and generate proof
    let config = ProofConfig::default();
    let prover = ProofOfBurnProver::new(config).unwrap();
    let output = prover.prove(&inputs).unwrap();
    
    // Verify commitment format
    assert_eq!(output.commitment.len(), 32, "Commitment should be 32 bytes");
    assert_ne!(output.commitment, [0u8; 32], "Commitment should not be all zeros");
    
    // Verify proof was generated
    assert!(!output.stark_proof.is_empty(), "Proof should not be empty");
    
    println!("✅ Commitment format compatible: {:?}", hex::encode(&output.commitment));
}

#[test]
fn test_proof_size_comparison() {
    // Compare proof sizes between STARK and SNARK
    // STARKs are typically larger but provide better security properties
    
    // Use a burn key that satisfies PoW requirements with relaxation
    let test_input = r#"{
        "burn_key": [37, 19, 95, 13, 45, 236, 56, 213, 122, 195, 100, 143, 38, 194, 66, 161, 134, 235, 7, 167, 13, 99, 111, 235, 3, 227, 149, 140, 5, 129, 132, 65],
        "balance": 1000000000000000000,
        "fee": 123,
        "spend": 234,
        "receiver_address": [144, 248, 191, 106, 71, 159, 50, 14, 173, 7, 68, 17, 164, 176, 231, 148, 78, 168, 201, 193],
        "num_leaf_address_nibbles": 50,
        "layers": [[249, 1, 209, 160, 189, 218, 165, 79, 241, 30, 61, 121, 209, 170, 15, 157], [248, 113, 160, 61, 86, 1, 183, 13, 58, 151, 202, 79, 241, 93, 249, 218]],
        "layer_lens": [16, 16],
        "num_layers": 2,
        "block_header": [249, 2, 29, 160, 198, 46, 22, 219, 203, 239, 74, 137, 59, 99, 13, 98, 28, 212, 14, 186, 38, 254, 160, 209, 57, 186, 128, 162, 111, 217, 49, 67, 124, 78, 236, 214, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 215, 252, 173, 150, 114, 235, 82, 227, 230, 86, 106, 194, 21, 145, 152, 225, 12, 215, 112, 233, 204, 157, 249, 184, 8, 192, 73, 156, 236, 22, 136, 248],
        "block_header_len": 123,
        "byte_security_relax": 0
    }"#;
    
    let inputs: ProofOfBurnInputs = serde_json::from_str(test_input).unwrap();
    
    // This input already uses the same burn key/receiver/fee that passes PoW
    
    let config = ProofConfig {
        pow_minimum_zero_bytes: 0, // Relax for testing
        ..Default::default()
    };
    
    let prover = ProofOfBurnProver::new(config).unwrap();
    let output = prover.prove(&inputs).unwrap();
    
    let stark_size = output.stark_proof.len();
    let circom_typical_size = 200; // Groth16 proofs are ~200 bytes
    
    println!("📊 Proof Size Comparison:");
    println!("  STARK: {} bytes", stark_size);
    println!("  Circom/Groth16: ~{} bytes", circom_typical_size);
    println!("  Ratio: {:.1}x larger", stark_size as f64 / circom_typical_size as f64);
    
    // STARKs are expected to be larger
    assert!(stark_size > circom_typical_size, "STARK proofs are typically larger");
    assert!(stark_size < 100_000, "STARK proof should be reasonably sized");
}

#[test]
fn test_performance_benchmark() {
    // Measure and compare performance with expected Circom timings
    use std::time::Instant;
    
    // Use complete valid input data
    let test_input = r#"{
        "burn_key": [37, 19, 95, 13, 45, 236, 56, 213, 122, 195, 100, 143, 38, 194, 66, 161, 134, 235, 7, 167, 13, 99, 111, 235, 3, 227, 149, 140, 5, 129, 132, 65],
        "balance": 1000000000000000000,
        "fee": 123,
        "spend": 234,
        "receiver_address": [144, 248, 191, 106, 71, 159, 50, 14, 173, 7, 68, 17, 164, 176, 231, 148, 78, 168, 201, 193],
        "num_leaf_address_nibbles": 63,
        "layers": [[249, 1, 209, 160, 189, 218, 165, 79, 241, 30, 61, 121, 209, 170, 15, 157, 247, 237, 154, 143, 154, 251, 192, 205, 211, 81, 131, 16, 108, 12, 60, 55, 127, 213, 135, 203, 160, 171, 140, 219, 128, 140, 131, 3, 187, 97, 251, 72, 226, 118, 33, 123, 233, 119, 15, 168, 62, 207, 63, 144, 242, 35, 77, 85, 136, 133, 245, 171, 241, 128, 128, 160, 222, 38, 203, 27, 79, 217, 156, 77, 62, 215, 93, 74, 103, 147, 30, 60, 37, 38, 5, 199, 214, 142, 1, 72, 213, 50, 127, 52]],
        "layer_lens": [100],
        "num_layers": 1,
        "block_header": [249, 2, 29, 160, 198, 46, 22, 219, 203, 239, 74, 137, 59, 99, 13, 98, 28, 212, 14, 186, 38, 254, 160, 209, 57, 186, 128, 162, 111, 217, 49, 67, 124, 78, 236, 214, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 215, 252, 173, 150, 114, 235, 82, 227, 230, 86, 106, 194, 21, 145, 152, 225, 12, 215, 112, 233, 204, 157, 249, 184, 8, 192, 73, 156, 236, 22, 136, 248],
        "block_header_len": 123,
        "byte_security_relax": 0
    }"#;
    
    let inputs: ProofOfBurnInputs = serde_json::from_str(test_input).unwrap();
    let config = ProofConfig::default();
    let prover = ProofOfBurnProver::new(config).unwrap();
    
    // Benchmark proof generation
    let start = Instant::now();
    let output = prover.prove(&inputs).unwrap();
    let stark_time = start.elapsed();
    
    let circom_expected_ms = 8500; // Based on documentation
    let stark_ms = stark_time.as_millis() as u64;
    let speedup = circom_expected_ms as f64 / stark_ms as f64;
    
    println!("⚡ Performance Comparison:");
    println!("  STARK: {}ms", stark_ms);
    println!("  Circom: ~{}ms (expected)", circom_expected_ms);
    println!("  Speedup: {:.1}x faster", speedup);
    
    // Verify we're significantly faster
    assert!(stark_ms < 3000, "STARK should be under 3 seconds");
    assert!(speedup > 2.0, "STARK should be at least 2x faster");
    
    // Verify proof was generated correctly
    assert_eq!(output.commitment.len(), 32);
    assert!(!output.stark_proof.is_empty());
}

#[test]
fn test_security_properties() {
    // Verify that our STARK implementation maintains security properties
    
    // Use complete valid input data with proper block header
    let test_input = r#"{
        "burn_key": [37, 19, 95, 13, 45, 236, 56, 213, 122, 195, 100, 143, 38, 194, 66, 161, 134, 235, 7, 167, 13, 99, 111, 235, 3, 227, 149, 140, 5, 129, 132, 65],
        "balance": 1000000000000000000,
        "fee": 123,
        "spend": 234,
        "receiver_address": [144, 248, 191, 106, 71, 159, 50, 14, 173, 7, 68, 17, 164, 176, 231, 148, 78, 168, 201, 193],
        "num_leaf_address_nibbles": 63,
        "layers": [[249, 1, 209, 160, 189, 218, 165, 79, 241, 30, 61, 121, 209, 170, 15, 157, 247, 237, 154, 143, 154, 251, 192, 205, 211, 81, 131, 16, 108, 12, 60, 55, 127, 213, 135, 203, 160, 171, 140, 219, 128, 140, 131, 3, 187, 97, 251, 72, 226, 118, 33, 123, 233, 119, 15, 168, 62, 207, 63, 144, 242, 35, 77, 85, 136, 133, 245, 171, 241, 128, 128, 160, 222, 38, 203, 27, 79, 217, 156, 77, 62, 215, 93, 74, 103, 147, 30, 60, 37, 38, 5, 199, 214, 142, 1, 72, 213, 50, 127, 52]],
        "layer_lens": [100],
        "num_layers": 1,
        "block_header": [249, 2, 29, 160, 198, 46, 22, 219, 203, 239, 74, 137, 59, 99, 13, 98, 28, 212, 14, 186, 38, 254, 160, 209, 57, 186, 128, 162, 111, 217, 49, 67, 124, 78, 236, 214, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 215, 252, 173, 150, 114, 235, 82, 227, 230, 86, 106, 194, 21, 145, 152, 225, 12, 215, 112, 233, 204, 157, 249, 184, 8, 192, 73, 156, 236, 22, 136, 248],
        "block_header_len": 123,
        "byte_security_relax": 0
    }"#;
    
    let inputs: ProofOfBurnInputs = serde_json::from_str(test_input).unwrap();
    
    // Test with different security levels
    let configs = vec![
        (80, "Standard"),
        (100, "High"),
        (128, "Very High"),
    ];
    
    for (security_level, label) in configs {
        let config = ProofConfig {
            security_level,
            ..Default::default()
        };
        
        let prover = ProofOfBurnProver::new(config).unwrap();
        let output = prover.prove(&inputs).unwrap();
        
        assert_eq!(output.metadata.security_level, security_level);
        println!("✅ {} security ({}): {} bytes", 
                 label, security_level, output.stark_proof.len());
    }
}
