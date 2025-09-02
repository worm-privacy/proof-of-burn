use criterion::{black_box, criterion_group, criterion_main, Criterion};
use proof_of_burn_stark::{ProofOfBurnProver, ProofConfig, ProofOfBurnInputs};

fn benchmark_proof_generation(c: &mut Criterion) {
    let config = ProofConfig::default();
    let prover = ProofOfBurnProver::new(config).expect("Failed to create prover");
    
    let inputs = ProofOfBurnInputs {
        burn_key: [1u8; 32],
        balance: 1000000000000000000u64, // 1 ETH
        fee: 50000000000000000u64,       // 0.05 ETH
        spend: 100000000000000000u64,    // 0.1 ETH
        receiver_address: [2u8; 20],
        num_leaf_address_nibbles: 50,
        layers: vec![vec![0u8; 100]; 4],
        layer_lens: vec![100; 4],
        num_layers: 4,
        block_header: vec![0u8; 500],
        block_header_len: 500,
        byte_security_relax: 0,
    };
    
    c.bench_function("proof_generation", |b| {
        b.iter(|| {
            prover.prove(black_box(&inputs))
        })
    });
}

criterion_group!(benches, benchmark_proof_generation);
criterion_main!(benches);
