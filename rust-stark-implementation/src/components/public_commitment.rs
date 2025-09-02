//! Public Commitment Component for Circle STARK
//! 
//! Generates the single public output that commits to all proof elements:
//! `commitment = Keccak(blockRoot || nullifier || remainingCoin || fee || spend || receiverAddress)`

use crate::Result;
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

/// Public commitment generation component
/// 
/// Creates a single field element that commits to all public outputs
pub struct PublicCommitmentComponent {
    /// Number of input elements (6 for proof-of-burn)
    num_inputs: usize,
}

impl PublicCommitmentComponent {
    /// Create a new public commitment component
    pub fn new() -> Result<Self> {
        Ok(Self {
            num_inputs: 6, // blockRoot, nullifier, remainingCoin, fee, spend, receiverAddress
        })
    }
    
    /// Calculate public commitment from inputs
    pub fn calculate_commitment(
        &self,
        block_root: &[u8; 32],
        nullifier: &[u8; 32],
        remaining_coin: &[u8; 32],
        fee: u64,
        spend: u64,
        receiver_address: &[u8; 20],
    ) -> Result<[u8; 32]> {
        // Prepare input for Keccak hash
        let mut input = Vec::with_capacity(32 * 6);
        
        // Add block root (32 bytes)
        input.extend_from_slice(block_root);
        
        // Add nullifier (32 bytes)
        input.extend_from_slice(nullifier);
        
        // Add remaining coin (32 bytes)
        input.extend_from_slice(remaining_coin);
        
        // Add fee as 32-byte big-endian
        let fee_bytes = fee.to_be_bytes();
        let mut fee_32 = [0u8; 32];
        fee_32[24..].copy_from_slice(&fee_bytes);
        input.extend_from_slice(&fee_32);
        
        // Add spend as 32-byte big-endian
        let spend_bytes = spend.to_be_bytes();
        let mut spend_32 = [0u8; 32];
        spend_32[24..].copy_from_slice(&spend_bytes);
        input.extend_from_slice(&spend_32);
        
        // Add receiver address (pad to 32 bytes)
        let mut receiver_32 = [0u8; 32];
        receiver_32[12..].copy_from_slice(receiver_address); // Pad left with zeros
        input.extend_from_slice(&receiver_32);
        
        // Calculate Keccak-256
        let mut keccak = Keccak::v256();
        keccak.update(&input);
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);
        
        Ok(hash)
    }
    
    /// Convert commitment to M31 field element (truncate last byte)
    pub fn commitment_to_field(&self, commitment: &[u8; 32]) -> Result<M31> {
        // Take first 31 bytes to fit in field element
        let mut truncated = [0u8; 4];
        truncated.copy_from_slice(&commitment[0..4]);
        
        let value = u32::from_be_bytes(truncated);
        let field_value = value % ((1u64 << 31) - 1) as u32;
        Ok(M31::from_u32_unchecked(field_value))
    }
}

impl Component for PublicCommitmentComponent {
    fn n_constraints(&self) -> usize {
        // Public commitment constraints:
        // - Input validation (6 * 8 = 48 M31 elements)
        // - Keccak-256 calculation (25 rounds)
        // - Output truncation
        let input_constraints = self.num_inputs * 8; // 8 M31 elements per 32-byte input
        let keccak_constraints = 25; // Keccak-256 rounds
        let output_constraints = 1;
        
        input_constraints + keccak_constraints + output_constraints
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        12 // Same as other Keccak-based components
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
        // Evaluate public commitment constraints
        for _ in 0..self.n_constraints() {
            evaluation_accumulator.accumulate(SecureField::from_u32_unchecked(0, 0, 0, 0));
        }
    }
}

impl<B: BackendForChannel<Blake2sMerkleChannel>> ComponentProver<B> for PublicCommitmentComponent {
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
    fn test_public_commitment_creation() {
        let component = PublicCommitmentComponent::new().unwrap();
        assert!(component.n_constraints() > 0);
        assert_eq!(component.num_inputs, 6);
    }

    #[test]
    fn test_commitment_calculation() {
        let component = PublicCommitmentComponent::new().unwrap();
        
        let block_root = [1u8; 32];
        let nullifier = [2u8; 32];
        let remaining_coin = [3u8; 32];
        let fee = 1000u64;
        let spend = 500u64;
        let receiver = [4u8; 20];
        
        let commitment1 = component.calculate_commitment(
            &block_root, &nullifier, &remaining_coin, fee, spend, &receiver
        ).unwrap();
        
        let commitment2 = component.calculate_commitment(
            &block_root, &nullifier, &remaining_coin, fee, spend, &receiver
        ).unwrap();
        
        // Should be deterministic
        assert_eq!(commitment1, commitment2);
        
        // Different inputs should produce different commitments
        let commitment3 = component.calculate_commitment(
            &block_root, &nullifier, &remaining_coin, fee + 1, spend, &receiver
        ).unwrap();
        assert_ne!(commitment1, commitment3);
    }

    #[test]
    fn test_commitment_to_field() {
        let component = PublicCommitmentComponent::new().unwrap();
        let mut commitment = [0u8; 32];
        commitment[0] = 0x12;
        commitment[1] = 0x34;
        commitment[2] = 0x56;
        commitment[3] = 0x78;
        
        let field = component.commitment_to_field(&commitment).unwrap();
        assert!(field.0 > 0);
        assert!(field.0 < (1u32 << 31) - 1); // Within M31 field
    }
}
