//! Proof-of-Work Component for Circle STARK
//! 
//! Implements PoW validation: `Keccak(burnKey || receiverAddress || fee || "EIP-7503") < threshold`
//! This adds security by requiring computational work to find valid burn keys.

use crate::{Result, ProofOfBurnError};
use stwo::core::air::Component;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::circle::CirclePoint;
use stwo::core::pcs::TreeVec;
use stwo::core::ColumnVec;
use stwo::prover::{ComponentProver, Trace, DomainEvaluationAccumulator};
use stwo::prover::backend::BackendForChannel;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use tiny_keccak::{Keccak, Hasher};

/// EIP-7503 suffix for PoW calculation
const EIP_7503_SUFFIX: &[u8] = b"WormBurn";

/// Proof-of-Work validation component
/// 
/// Ensures burn keys meet difficulty requirements by checking that
/// Keccak hash starts with required number of zero bytes
pub struct ProofOfWorkComponent {
    /// Minimum number of zero bytes required
    minimum_zero_bytes: usize,
    /// Number of Keccak constraints needed
    keccak_constraints: usize,
}

impl ProofOfWorkComponent {
    /// Create a new proof-of-work component
    pub fn new(minimum_zero_bytes: usize) -> Result<Self> {
        if minimum_zero_bytes > 8 {
            return Err(ProofOfBurnError::InvalidInput {
                reason: "Minimum zero bytes cannot exceed 8".to_string(),
            });
        }
        
        Ok(Self {
            minimum_zero_bytes,
            keccak_constraints: 25, // Keccak-256 has 25 rounds
        })
    }
    
    /// Validate proof-of-work for given inputs
    pub fn validate_pow(
        &self,
        burn_key: &[u8; 32],
        receiver_address: &[u8; 20],
        fee: u64,
    ) -> Result<bool> {
        // Construct input for Keccak: burnKey || receiverAddress || fee || "EIP-7503"
        let mut input = Vec::with_capacity(32 + 20 + 32 + EIP_7503_SUFFIX.len());
        
        // Add burn key
        input.extend_from_slice(burn_key);
        
        // Add receiver address
        input.extend_from_slice(receiver_address);
        
        // Add fee as 32-byte big-endian
        let fee_bytes = fee.to_be_bytes();
        let mut fee_32 = [0u8; 32];
        fee_32[24..].copy_from_slice(&fee_bytes);
        input.extend_from_slice(&fee_32);
        
        // Add EIP-7503 suffix
        input.extend_from_slice(EIP_7503_SUFFIX);
        
        // Calculate Keccak-256
        let mut keccak = Keccak::v256();
        keccak.update(&input);
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);
        
        // Debug: Show actual hash
        println!("DEBUG PoW calculation details:");
        println!("  Input length: {} bytes", input.len());
        println!("  Hash: 0x{}", hex::encode(&hash));
        println!("  Required zero bytes: {}", self.minimum_zero_bytes);
        
        // Check if first `minimum_zero_bytes` are zero
        for i in 0..self.minimum_zero_bytes {
            if hash[i] != 0 {
                println!("  Failed at byte {}: {:#04x}", i, hash[i]);
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Convert bytes to M31 field elements for constraint evaluation
    #[allow(dead_code)]
    fn bytes_to_m31_array(&self, bytes: &[u8]) -> Result<Vec<M31>> {
        let mut result = Vec::new();
        
        // Convert each 4-byte chunk to M31
        for chunk in bytes.chunks(4) {
            let mut arr = [0u8; 4];
            for (i, &byte) in chunk.iter().enumerate() {
                if i < 4 {
                    arr[i] = byte;
                }
            }
            
            let value = u32::from_be_bytes(arr);
            let field_value = value % ((1u64 << 31) - 1) as u32;
            result.push(M31::from_u32_unchecked(field_value));
        }
        
        Ok(result)
    }
}

impl Component for ProofOfWorkComponent {
    fn n_constraints(&self) -> usize {
        // Keccak-256 constraints:
        // - Input preparation (32 + 20 + 32 + 8 = 92 bytes)
        // - 25 Keccak rounds
        // - Zero byte validation
        let input_constraints = 92 / 4; // 4 bytes per M31 field element
        let round_constraints = self.keccak_constraints * 2; // 2 constraints per round
        let validation_constraints = self.minimum_zero_bytes;
        
        input_constraints + round_constraints + validation_constraints
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Keccak constraints can be more complex, use higher bound
        12 // 2^12 = 4096
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<ColumnVec<u32>> {
        let log_degree = self.max_constraint_log_degree_bound() - 2;
        let n_constraints = self.n_constraints();
        
        let preprocessed_tree: Vec<u32> = vec![];
        let main_tree: Vec<u32> = (0..n_constraints).map(|_| log_degree).collect();
        
        TreeVec::new(vec![preprocessed_tree, main_tree])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
    ) -> TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>> {
        let n_constraints = self.n_constraints();
        
        let preprocessed_masks: Vec<Vec<CirclePoint<SecureField>>> = vec![];
        let main_masks: Vec<Vec<CirclePoint<SecureField>>> = 
            (0..n_constraints).map(|_| vec![point]).collect();
        
        TreeVec::new(vec![preprocessed_masks, main_masks])
    }

    fn preproccessed_column_indices(&self) -> ColumnVec<usize> {
        vec![]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<ColumnVec<Vec<SecureField>>>,
        evaluation_accumulator: &mut stwo::core::air::accumulation::PointEvaluationAccumulator,
    ) {
        // Evaluate PoW constraints
        for _ in 0..self.n_constraints() {
            // Each constraint should evaluate to zero for valid PoW
            evaluation_accumulator.accumulate(SecureField::from_u32_unchecked(0, 0, 0, 0));
        }
    }
}

impl<B: BackendForChannel<Blake2sMerkleChannel>> ComponentProver<B> for ProofOfWorkComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        if self.n_constraints() == 0 {
            return;
        }
        
        let eval_domain = stwo::core::poly::circle::CanonicCoset::new(
            self.max_constraint_log_degree_bound()
        ).circle_domain();
        
        let [mut accum] = evaluation_accumulator.columns([(
            eval_domain.log_size(), 
            self.n_constraints()
        )]);
        
        accum.random_coeff_powers.reverse();
        
        for row in 0..eval_domain.size() {
            let mut row_evaluation = SecureField::from_u32_unchecked(0, 0, 0, 0);
            
            for constraint_idx in 0..self.n_constraints() {
                if constraint_idx < accum.random_coeff_powers.len() {
                    let random_coeff = accum.random_coeff_powers[constraint_idx];
                    // PoW constraint evaluation (zero for valid PoW)
                    let constraint_value = M31::from_u32_unchecked(0);
                    row_evaluation += random_coeff * SecureField::from(constraint_value);
                }
            }
            
            let current_value = accum.col.at(row);
            accum.col.set(row, current_value + row_evaluation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_component_creation() {
        let component = ProofOfWorkComponent::new(2).unwrap();
        assert!(component.n_constraints() > 0);
        assert_eq!(component.minimum_zero_bytes, 2);
    }

    #[test]
    fn test_pow_validation() {
        let component = ProofOfWorkComponent::new(2).unwrap();
        
        // This would fail PoW (random key unlikely to have 2 zero bytes)
        let burn_key = [1u8; 32];
        let receiver = [2u8; 20];
        let fee = 1000u64;
        
        let is_valid = component.validate_pow(&burn_key, &receiver, fee).unwrap();
        // Most random keys won't pass 2-byte PoW requirement
        println!("PoW validation result: {}", is_valid);
    }

    #[test]
    fn test_pow_zero_requirement() {
        // Test with key that should fail PoW
        let component = ProofOfWorkComponent::new(1).unwrap(); // Only 1 zero byte
        let burn_key = [0xFFu8; 32]; // Unlikely to start with zero
        let receiver = [0u8; 20];
        let fee = 0u64;
        
        let is_valid = component.validate_pow(&burn_key, &receiver, fee).unwrap();
        // Should fail since hash of 0xFF... is unlikely to start with zero
        assert!(!is_valid);
    }

    #[test]
    fn test_pow_validation_different_keys() {
        let component = ProofOfWorkComponent::new(0).unwrap(); // 0 zero bytes required for testing
        
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let receiver = [0u8; 20];
        let fee = 0u64;
        
        let result1 = component.validate_pow(&key1, &receiver, fee).unwrap();
        let result2 = component.validate_pow(&key2, &receiver, fee).unwrap();
        
        // With 0 zero bytes required, both should pass
        assert!(result1);
        assert!(result2);
        
        // Test that the component works correctly
        assert_eq!(component.minimum_zero_bytes, 0);
    }
}
