//! Keccak hash utilities

use tiny_keccak::{Hasher, Keccak};

/// Keccak utilities for Circle STARK constraints
pub struct KeccakHasher;

impl KeccakHasher {
    pub fn new() -> Self {
        Self
    }
    
    /// Keccak256 hash
    pub fn keccak256(&self, input: &[u8]) -> [u8; 32] {
        let mut keccak = Keccak::v256();
        let mut output = [0u8; 32];
        keccak.update(input);
        keccak.finalize(&mut output);
        output
    }
    
    /// Hash multiple inputs concatenated
    pub fn keccak256_concat(&self, inputs: &[&[u8]]) -> [u8; 32] {
        let mut keccak = Keccak::v256();
        for input in inputs {
            keccak.update(input);
        }
        let mut output = [0u8; 32];
        keccak.finalize(&mut output);
        output
    }
    
    /// Validate proof-of-work by checking leading zero bytes
    pub fn validate_pow(&self, hash: &[u8; 32], required_zeros: usize) -> bool {
        if required_zeros > 32 {
            return false;
        }
        
        for i in 0..required_zeros {
            if hash[i] != 0 {
                return false;
            }
        }
        
        true
    }
}

impl Default for KeccakHasher {
    fn default() -> Self {
        Self::new()
    }
}
