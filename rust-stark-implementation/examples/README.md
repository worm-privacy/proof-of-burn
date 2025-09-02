# Examples Directory

This directory contains example inputs and generated proofs for the Proof-of-Burn Circle STARK implementation.

## Structure

```
examples/
├── inputs/          # Test input files
│   ├── test_input.json              # Basic test case
│   ├── real_test_input.json         # Real Ethereum data test
│   ├── valid_test_input.json        # Valid MPT proof test
│   └── production_test_input.json   # Production-ready test
└── proofs/          # Generated proof files
    ├── *.stark      # STARK proof files (~20KB each)
    └── *.commitment # Commitment files (~32 bytes each)
```

## Input Files

### `test_input.json`
Basic test case with minimal data for quick testing.

### `real_test_input.json` 
Contains real Ethereum block data for MPT validation testing.

### `valid_test_input.json`
Generated test case with valid MPT proof structure.

### `production_test_input.json`
Production-ready test case with:
- Valid 16-bit PoW burn key
- Real Ethereum block header
- Complete MPT proof
- All validation components

## Proof Files

Generated proof files are organized by test case:

- `production_proof.*` - From production_test_input.json
- `valid_test.*` - From valid_test_input.json  
- `test_proof.*` - From test_input.json
- `test_constraints.*` - Constraint validation test
- `test_poseidon_real.*` - Real Poseidon implementation test
- `test_proof_no_pow.*` - Test without PoW validation

## Usage

Generate a new proof:
```bash
cd ../
./target/release/pob-stark prove \
  --input examples/inputs/production_test_input.json \
  --output examples/proofs/my_proof.stark \
  --commitment examples/proofs/my_proof.commitment
```

Verify an existing proof:
```bash
./target/release/pob-stark verify \
  --proof examples/proofs/production_proof.stark \
  --input examples/inputs/production_test_input.json
```

## Status

⚠️ **Note**: Current proofs are generated with placeholder constraints. 
Real mathematical validation is pending STARK constraint implementation.
