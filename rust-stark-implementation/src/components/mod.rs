//! Circle STARK components for Proof-of-Burn verification
//! 
//! This module contains all the constraint components needed to implement
//! proof-of-burn using Circle STARKs, following the Zyrkom framework patterns.

pub mod burn_address;
pub mod mpt_proof;
pub mod proof_of_work;
pub mod nullifier;
pub mod public_commitment;
pub mod prover;

pub use burn_address::*;
pub use mpt_proof::*;
pub use proof_of_work::*;
pub use nullifier::*;
pub use public_commitment::*;
pub use prover::*;

use crate::Result;
use stwo::core::air::Component;
use stwo::core::fields::qm31::SecureField;
use stwo::core::circle::CirclePoint;
use stwo::core::pcs::TreeVec;
use stwo::core::ColumnVec;
use stwo::prover::{ComponentProver, Trace, DomainEvaluationAccumulator};
use stwo::prover::backend::BackendForChannel;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;

/// Main Proof-of-Burn component that orchestrates all sub-components
pub struct ProofOfBurnComponent {
    /// Burn address calculation component
    pub burn_address: BurnAddressComponent,
    /// MPT proof verification component
    pub mpt_proof: MPTProofComponent,
    /// Proof-of-work validation component
    pub proof_of_work: ProofOfWorkComponent,
    /// Nullifier generation component
    pub nullifier: NullifierComponent,
    /// Public commitment component
    pub public_commitment: PublicCommitmentComponent,
}

impl ProofOfBurnComponent {
    /// Create a new Proof-of-Burn component with all sub-components
    pub fn new(
        max_num_layers: usize,
        max_node_blocks: usize,
        _max_header_blocks: usize,
        min_leaf_address_nibbles: usize,
        _amount_bytes: usize,
        pow_minimum_zero_bytes: usize,
        _max_balance: u64,
    ) -> Result<Self> {
        Ok(Self {
            burn_address: BurnAddressComponent::new()?,
            mpt_proof: MPTProofComponent::new(
                max_num_layers,
                max_node_blocks,
                min_leaf_address_nibbles,
            )?,
            proof_of_work: ProofOfWorkComponent::new(pow_minimum_zero_bytes)?,
            nullifier: NullifierComponent::new()?,
            public_commitment: PublicCommitmentComponent::new()?,
        })
    }
    
    /// Get total number of constraints across all components
    pub fn total_constraints(&self) -> usize {
        self.burn_address.n_constraints() +
        self.mpt_proof.n_constraints() +
        self.proof_of_work.n_constraints() +
        self.nullifier.n_constraints() +
        self.public_commitment.n_constraints()
    }
}

impl Component for ProofOfBurnComponent {
    fn n_constraints(&self) -> usize {
        self.total_constraints()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Take the maximum across all components
        [
            self.burn_address.max_constraint_log_degree_bound(),
            self.mpt_proof.max_constraint_log_degree_bound(),
            self.proof_of_work.max_constraint_log_degree_bound(),
            self.nullifier.max_constraint_log_degree_bound(),
            self.public_commitment.max_constraint_log_degree_bound(),
        ].iter().max().copied().unwrap_or(10)
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<ColumnVec<u32>> {
        let log_degree = self.max_constraint_log_degree_bound() - 2;
        let total_constraints = self.total_constraints();
        
        // Tree 0: Preprocessed (empty)
        // Tree 1: Main trace with all constraints
        let preprocessed_tree: Vec<u32> = vec![];
        let main_tree: Vec<u32> = (0..total_constraints).map(|_| log_degree).collect();
        
        TreeVec::new(vec![preprocessed_tree, main_tree])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
    ) -> TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>> {
        let total_constraints = self.total_constraints();
        
        let preprocessed_masks: Vec<Vec<CirclePoint<SecureField>>> = vec![];
        let main_masks: Vec<Vec<CirclePoint<SecureField>>> = 
            (0..total_constraints).map(|_| vec![point]).collect();
        
        TreeVec::new(vec![preprocessed_masks, main_masks])
    }

    fn preproccessed_column_indices(&self) -> ColumnVec<usize> {
        vec![]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &TreeVec<ColumnVec<Vec<SecureField>>>,
        evaluation_accumulator: &mut stwo::core::air::accumulation::PointEvaluationAccumulator,
    ) {
        // Evaluate constraints from all components
        self.burn_address.evaluate_constraint_quotients_at_point(point, mask, evaluation_accumulator);
        self.mpt_proof.evaluate_constraint_quotients_at_point(point, mask, evaluation_accumulator);
        self.proof_of_work.evaluate_constraint_quotients_at_point(point, mask, evaluation_accumulator);
        self.nullifier.evaluate_constraint_quotients_at_point(point, mask, evaluation_accumulator);
        self.public_commitment.evaluate_constraint_quotients_at_point(point, mask, evaluation_accumulator);
    }
}

impl<B: BackendForChannel<Blake2sMerkleChannel>> ComponentProver<B> for ProofOfBurnComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        // Each component evaluates its constraints on the domain
        self.burn_address.evaluate_constraint_quotients_on_domain(trace, evaluation_accumulator);
        self.mpt_proof.evaluate_constraint_quotients_on_domain(trace, evaluation_accumulator);
        self.proof_of_work.evaluate_constraint_quotients_on_domain(trace, evaluation_accumulator);
        self.nullifier.evaluate_constraint_quotients_on_domain(trace, evaluation_accumulator);
        self.public_commitment.evaluate_constraint_quotients_on_domain(trace, evaluation_accumulator);
    }
}
