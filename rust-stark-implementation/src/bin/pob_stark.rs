//! Proof-of-Burn Circle STARK CLI Tool
//! 
//! Command-line interface for generating and verifying proof-of-burn proofs
//! using Circle STARKs instead of Circom/Groth16.

use proof_of_burn_stark::{
    ProofOfBurnProver, ProofConfig, ProofOfBurnInputs, ProofOfBurnOutput, Result, ProofOfBurnError
};
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use std::fs;
use serde_json;

#[derive(Parser)]
#[command(name = "pob-stark")]
#[command(about = "Proof-of-Burn using Circle STARKs - Alternative to Circom")]
#[command(version = proof_of_burn_stark::VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a proof-of-burn proof from input file
    Prove {
        /// Input JSON file with proof-of-burn data
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output file for the generated proof
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Enable proof compression
        #[arg(long)]
        compress: bool,
        
        /// Security level (bits)
        #[arg(long, default_value = "80")]
        security: usize,
    },
    
    /// Verify a proof-of-burn proof
    Verify {
        /// Proof file to verify
        #[arg(short, long)]
        proof: PathBuf,
        
        /// Original input file for verification
        #[arg(short, long)]
        input: PathBuf,
    },
    
    /// Get information about a proof file
    Info {
        /// Proof file to analyze
        #[arg(short, long)]
        proof: PathBuf,
    },
    
    /// Benchmark proof generation performance
    Benchmark {
        /// Number of iterations to run
        #[arg(long, default_value = "10")]
        iterations: usize,
        
        /// Input file for benchmarking
        #[arg(short, long)]
        input: PathBuf,
    },
    
    /// Convert Circom input to Circle STARK format
    Convert {
        /// Circom input JSON file
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output file for Circle STARK format
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    // Show banner
    println!("🔥 WORM Proof-of-Burn - Circle STARK Edition");
    println!("⚡ Powered by Zyrkom: https://github.com/Zyra-V23/zyrkom");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    
    let cli = Cli::parse();

    match &cli.command {
        Commands::Prove { input, output, compress, security } => {
            prove_command(input, output.as_ref(), *compress, *security)
        }
        Commands::Verify { proof, input } => {
            verify_command(proof, input)
        }
        Commands::Info { proof } => {
            info_command(proof)
        }
        Commands::Benchmark { iterations, input } => {
            benchmark_command(*iterations, input)
        }
        Commands::Convert { input, output } => {
            convert_command(input, output)
        }
    }
}

fn prove_command(
    input_path: &PathBuf,
    output_path: Option<&PathBuf>,
    compress: bool,
    security: usize,
) -> Result<()> {
    println!("{}", "🔥 Proof-of-Burn Circle STARK Prover".bright_red().bold());
    println!("📁 Input: {}", input_path.display());
    
    // Read input file
    let input_data = fs::read_to_string(input_path)
        .map_err(|e| ProofOfBurnError::IoError(e))?;
    
    let inputs: ProofOfBurnInputs = serde_json::from_str(&input_data)?;
    
    // Configure prover
    let mut config = ProofConfig::default();
    config.enable_compression = compress;
    config.security_level = security;
    
    let prover = ProofOfBurnProver::new(config)?;
    
    // Generate proof
    println!("⚡ Generating Circle STARK proof...");
    let start_time = std::time::Instant::now();
    
    let proof_output = prover.prove(&inputs)?;
    
    let generation_time = start_time.elapsed();
    
    // Determine output path
    let output_file = output_path
        .cloned()
        .unwrap_or_else(|| {
            let mut path = input_path.clone();
            path.set_extension("stark.proof");
            path
        });
    
    // Save complete proof output (not just the stark_proof bytes)
    let serialized_output = bincode::serialize(&proof_output)
        .map_err(|e| ProofOfBurnError::SerializationError(format!("Failed to serialize output: {}", e)))?;
    fs::write(&output_file, &serialized_output)
        .map_err(|e| ProofOfBurnError::IoError(e))?;
    
    // Save commitment
    let mut commitment_file = output_file.clone();
    commitment_file.set_extension("commitment");
    fs::write(&commitment_file, &proof_output.commitment)
        .map_err(|e| ProofOfBurnError::IoError(e))?;
    
    println!("✅ {}", "Proof generated successfully!".bright_green().bold());
    println!("📄 Proof: {}", output_file.display());
    println!("🔑 Commitment: {}", commitment_file.display());
    println!("⏱️  Generation time: {}ms", generation_time.as_millis());
    println!("📊 Proof size: {} bytes", serialized_output.len());
    println!("🔒 Security level: {} bits", proof_output.metadata.security_level);
    
    if compress {
        println!("📦 Compression: {}", "Enabled".bright_blue());
    }
    
    Ok(())
}

fn verify_command(proof_path: &PathBuf, input_path: &PathBuf) -> Result<()> {
    println!("{}", "🔍 Proof-of-Burn Circle STARK Verifier".bright_blue().bold());
    println!("📁 Proof: {}", proof_path.display());
    println!("📁 Input: {}", input_path.display());
    
    // Load proof data
    let proof_data = std::fs::read(proof_path)?;
    let proof_output: ProofOfBurnOutput = bincode::deserialize(&proof_data)
        .map_err(|e| ProofOfBurnError::SerializationError(format!("Failed to deserialize proof: {}", e)))?;
    
    // Load input data for verification
    let input_data = std::fs::read_to_string(input_path)?;
    let inputs: ProofOfBurnInputs = serde_json::from_str(&input_data)?;
    
    // Display proof information
    println!("Verifying proof...");
    println!("📊 Proof size: {} bytes", proof_output.stark_proof.len());
    println!("⏱️  Generation time: {}ms", proof_output.metadata.generation_time_ms);
    println!("🔒 Security level: {} bits", proof_output.metadata.security_level);
    
    // Create a prover instance for verification
    let config = ProofConfig {
        security_level: proof_output.metadata.security_level,
        enable_compression: proof_output.metadata.compressed,
        ..Default::default()
    };
    
    let prover = ProofOfBurnProver::new(config)?;
    
    // Perform actual verification
    let verification_start = std::time::Instant::now();
    let is_valid = prover.verify_proof(&proof_output, &inputs)?;
    let verification_time = verification_start.elapsed();
    
    if is_valid {
        println!("✅ {}", "Proof verification successful!".bright_green().bold());
        println!("🔑 Public commitment: 0x{}", hex::encode(&proof_output.commitment));
        println!("⏱️  Verification time: {}ms", verification_time.as_millis());
        
        // Additional validation info
        println!("\n📋 Verification Details:");
        println!("  • Commitment matches expected value");
        println!("  • Proof structure is valid");
        println!("  • Metadata consistency verified");
        
        if proof_output.metadata.compressed {
            println!("  • Proof was compressed");
        }
    } else {
        return Err(ProofOfBurnError::VerificationError { 
            reason: "Proof verification failed".to_string() 
        });
    }
    
    Ok(())
}

fn info_command(proof_path: &PathBuf) -> Result<()> {
    println!("{}", "ℹ️  Proof Information".bright_cyan().bold());
    println!("📁 File: {}", proof_path.display());
    
    // Read proof file
    let proof_data = fs::read(proof_path)
        .map_err(|e| ProofOfBurnError::IoError(e))?;
    
    println!("📊 Size: {} bytes", proof_data.len());
    
    // Parse and display proof information
    let proof_data = std::fs::read(proof_path)?;
    let proof_output: ProofOfBurnOutput = bincode::deserialize(&proof_data)
        .map_err(|e| ProofOfBurnError::SerializationError(format!("Failed to deserialize proof: {}", e)))?;
    
    println!("🔍 Proof Information");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Proof Size: {} bytes", proof_output.stark_proof.len());
    println!("Generation Time: {}ms", proof_output.metadata.generation_time_ms);
    println!("Security Level: {} bits", proof_output.metadata.security_level);
    println!("Compressed: {}", if proof_output.metadata.compressed { "Yes" } else { "No" });
    println!("Timestamp: {}", proof_output.metadata.timestamp);
    println!("Public Commitment: 0x{}", hex::encode(&proof_output.commitment));
    
    // Display proof structure info
    println!("\n📊 Proof Structure");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("STARK Proof Length: {} bytes", proof_output.stark_proof.len());
    println!("Commitment Length: {} bytes", proof_output.commitment.len());
    println!("⚠️  Detailed proof parsing not yet implemented");
    
    Ok(())
}

fn benchmark_command(iterations: usize, input_path: &PathBuf) -> Result<()> {
    println!("{}", "🚀 Proof-of-Burn Performance Benchmark".bright_magenta().bold());
    println!("🔄 Iterations: {}", iterations);
    println!("📁 Input: {}", input_path.display());
    
    // Read input
    let input_data = fs::read_to_string(input_path)
        .map_err(|e| ProofOfBurnError::IoError(e))?;
    let inputs: ProofOfBurnInputs = serde_json::from_str(&input_data)?;
    
    let config = ProofConfig::default();
    let prover = ProofOfBurnProver::new(config)?;
    
    let mut total_time = std::time::Duration::new(0, 0);
    let mut successful_proofs = 0;
    
    println!("⚡ Running benchmark...");
    
    for i in 1..=iterations {
        print!("Iteration {}/{}: ", i, iterations);
        
        let start = std::time::Instant::now();
        match prover.prove(&inputs) {
            Ok(_proof) => {
                let duration = start.elapsed();
                total_time += duration;
                successful_proofs += 1;
                println!("{}ms ✅", duration.as_millis());
            }
            Err(e) => {
                println!("{} ❌", format!("Failed: {}", e).bright_red());
            }
        }
    }
    
    println!("\n📊 {}", "Benchmark Results".bright_yellow().bold());
    println!("✅ Successful proofs: {}/{}", successful_proofs, iterations);
    
    if successful_proofs > 0 {
        let avg_time = total_time / successful_proofs as u32;
        println!("⏱️  Average time: {}ms", avg_time.as_millis());
        println!("🚀 Throughput: {:.2} proofs/second", 
            1000.0 / avg_time.as_millis() as f64);
    }
    
    Ok(())
}

fn convert_command(input_path: &PathBuf, output_path: &PathBuf) -> Result<()> {
    println!("{}", "🔄 Converting Circom input to Circle STARK format".bright_yellow().bold());
    println!("📁 Input: {}", input_path.display());
    println!("📁 Output: {}", output_path.display());
    
    // Read Circom input
    let circom_data = fs::read_to_string(input_path)
        .map_err(|e| ProofOfBurnError::IoError(e))?;
    
    let circom_input: serde_json::Value = serde_json::from_str(&circom_data)?;
    
    // Convert to our format
    let stark_input = convert_circom_to_stark(&circom_input)?;
    
    // Save converted input
    let stark_json = serde_json::to_string_pretty(&stark_input)?;
    fs::write(output_path, stark_json)
        .map_err(|e| ProofOfBurnError::IoError(e))?;
    
    println!("✅ {}", "Conversion completed!".bright_green().bold());
    
    Ok(())
}

fn convert_circom_to_stark(circom_input: &serde_json::Value) -> Result<ProofOfBurnInputs> {
    // Extract values from Circom format
    let burn_key_str = circom_input["burnKey"].as_str()
        .ok_or_else(|| ProofOfBurnError::InvalidInput {
            reason: "Missing burnKey in Circom input".to_string(),
        })?;
    
    let balance = circom_input["balance"].as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ProofOfBurnError::InvalidInput {
            reason: "Invalid balance in Circom input".to_string(),
        })?;
    
    let fee = circom_input["fee"].as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ProofOfBurnError::InvalidInput {
            reason: "Invalid fee in Circom input".to_string(),
        })?;
    
    let spend = circom_input["spend"].as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ProofOfBurnError::InvalidInput {
            reason: "Invalid spend in Circom input".to_string(),
        })?;
    
    // Convert burn key from string to bytes
    let burn_key_num = burn_key_str.parse::<u64>()
        .map_err(|_| ProofOfBurnError::InvalidInput {
            reason: "Invalid burnKey format".to_string(),
        })?;
    
    let mut burn_key = [0u8; 32];
    burn_key[24..].copy_from_slice(&burn_key_num.to_be_bytes());
    
    // Extract receiver address (hex string to bytes)
    let receiver_hex = circom_input["receiverAddress"].as_str()
        .ok_or_else(|| ProofOfBurnError::InvalidInput { 
            reason: "Missing receiverAddress".to_string() 
        })?;
    let receiver_bytes = hex::decode(receiver_hex.trim_start_matches("0x"))
        .map_err(|_| ProofOfBurnError::InvalidInput { 
            reason: "Invalid receiverAddress hex".to_string() 
        })?;
    let mut receiver_address = [0u8; 20];
    if receiver_bytes.len() >= 20 {
        receiver_address.copy_from_slice(&receiver_bytes[..20]);
    }
    
    // Extract MPT layers
    let layers_array = circom_input["layers"].as_array()
        .ok_or_else(|| ProofOfBurnError::InvalidInput { 
            reason: "Missing layers array".to_string() 
        })?;
    let mut layers = Vec::new();
    for layer in layers_array {
        let layer_array = layer.as_array()
            .ok_or_else(|| ProofOfBurnError::InvalidInput { 
                reason: "Invalid layer format".to_string() 
            })?;
        let mut layer_bytes = Vec::new();
        for byte_val in layer_array {
            let byte = byte_val.as_u64().unwrap_or(0) as u8;
            layer_bytes.push(byte);
        }
        layers.push(layer_bytes);
    }
    
    // Extract layer lengths
    let layer_lens_array = circom_input["layerLens"].as_array()
        .ok_or_else(|| ProofOfBurnError::InvalidInput { 
            reason: "Missing layerLens".to_string() 
        })?;
    let layer_lens: Vec<usize> = layer_lens_array.iter()
        .map(|v| v.as_u64().unwrap_or(0) as usize)
        .collect();
    
    // Extract block header
    let block_header_array = circom_input["blockHeader"].as_array()
        .ok_or_else(|| ProofOfBurnError::InvalidInput { 
            reason: "Missing blockHeader".to_string() 
        })?;
    let block_header: Vec<u8> = block_header_array.iter()
        .map(|v| v.as_u64().unwrap_or(0) as u8)
        .collect();
    
    // Extract other fields
    let num_leaf_address_nibbles = circom_input["numLeafAddressNibbles"]
        .as_str().and_then(|s| s.parse().ok()).unwrap_or(50);
    let num_layers = circom_input["numLayers"].as_u64().unwrap_or(0) as usize;
    let block_header_len = circom_input["blockHeaderLen"].as_u64().unwrap_or(0) as usize;
    let byte_security_relax = circom_input["byteSecurityRelax"].as_u64().unwrap_or(0) as u8;
    
    // Extract state_root from input
    let state_root_array = circom_input["stateRoot"].as_array()
        .ok_or_else(|| ProofOfBurnError::InvalidInput { reason: "Missing stateRoot field".to_string() })?;
    let mut state_root = [0u8; 32];
    for (i, value) in state_root_array.iter().enumerate().take(32) {
        state_root[i] = value.as_u64().unwrap_or(0) as u8;
    }
    
    // Extract address_hash_nibbles from input
    let address_nibbles_array = circom_input["addressHashNibbles"].as_array()
        .ok_or_else(|| ProofOfBurnError::InvalidInput { reason: "Missing addressHashNibbles field".to_string() })?;
    let mut address_hash_nibbles = [0u8; 64];
    for (i, value) in address_nibbles_array.iter().enumerate().take(64) {
        address_hash_nibbles[i] = value.as_u64().unwrap_or(0) as u8;
    }
    
    Ok(ProofOfBurnInputs {
        burn_key,
        balance,
        fee,
        spend,
        receiver_address,
        num_leaf_address_nibbles,
        layers,
        layer_lens,
        num_layers,
        block_header,
        block_header_len,
        state_root,
        address_hash_nibbles,
        byte_security_relax: byte_security_relax as usize,
    })
}
