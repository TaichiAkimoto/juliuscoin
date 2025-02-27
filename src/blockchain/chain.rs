//! Core blockchain data structures and operations.
//! 
//! This module implements the fundamental blockchain structures including:
//! - UTXO (Unspent Transaction Output) management
//! - Transaction processing
//! - Block creation and validation
//! - Chain management
//! 
//! The implementation uses post-quantum cryptography for transaction signatures
//! and block validation.

use serde::{Serialize, Deserialize};
use crate::cryptography::crypto::{verify_signature, derive_address_from_pk};
use crate::blockchain::consensus::{PoSState, Staker};
use crate::blockchain::consensus::staking::finalization::FinalizationProcessor;
use crate::blockchain::consensus::staking::validator::ValidatorOperations;
use crate::blockchain::consensus::staking::types::{ValidatorVote, EpochInfo, FinalizationState};
use crate::blockchain::consensus::staking::withdrawal::WithdrawalProcessor;
use crate::governance::Governance;
use log::info;
use std::time::{SystemTime, UNIX_EPOCH};
use vrf::openssl::{ECVRF, CipherSuite, Error as VRFError};
use vrf::VRF;
use anyhow::{Result, anyhow, Error};
use std::error::Error as StdError;
use std::fmt;
use sha2::{Sha256, Digest};
use crate::blockchain::consensus::slashing::SlashingReason;
use crate::blockchain::utxo::{UTXO, UtxoId};
use crate::blockchain::script::Script;
use std::collections::HashMap;
use openssl::error::ErrorStack;

/// Transaction types supported by the blockchain
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum TxType {
    Regular,
    Stake,
    Unstake,
    BlockReward,
}

/// Represents a complete transaction in the blockchain.
/// 
/// A transaction consumes existing UTXOs as inputs and creates new UTXOs as outputs.
/// The total value of inputs must equal the total value of outputs.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transaction {
    /// Type of transaction (regular, stake, or unstake)
    pub tx_type: TxType,
    /// List of UTXOs to be consumed
    pub inputs: Vec<TxInput>,
    /// List of new UTXOs to be created
    pub outputs: Vec<TxOutput>,
    /// Minimum lock period for staking (in blocks), only used for Stake transactions
    pub lock_period: Option<u64>,
    /// Gas limit set by the transaction sender
    pub gas_limit: u64,
    /// Gas price the sender is willing to pay above base fee
    pub max_priority_fee: u64,
    /// Actual gas used by the transaction
    pub gas_used: u64,
}

/// Represents an input to a transaction.
/// 
/// Transaction inputs reference existing UTXOs and include cryptographic proof
/// that the sender has the right to spend them.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxInput {
    /// Reference to the UTXO being spent
    pub utxo_id: UtxoId,
    /// Script that unlocks the referenced UTXO
    pub unlocking_script: Script,
}

/// Represents an output of a transaction.
/// 
/// Transaction outputs create new UTXOs that can be spent in future transactions.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxOutput {
    /// Amount of coins to transfer
    pub amount: u64,
    /// Script that must be satisfied to spend this output
    pub locking_script: Script,
}

/// Represents a block in the blockchain.
/// 
/// Each block contains a list of transactions and is cryptographically linked
/// to the previous block through its hash. Blocks are signed by their proposer
/// using post-quantum signatures.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Block {
    /// Block height in the chain
    pub index: u64,
    /// Hash of the previous block
    pub prev_hash: Vec<u8>,
    /// Unix timestamp of block creation
    pub timestamp: u64,
    /// List of transactions included in this block
    pub transactions: Vec<Transaction>,
    /// Hash of the proposer's Dilithium public key
    pub proposer_address: Vec<u8>,
    /// Dilithium signature of the block by the proposer
    pub block_signature: Vec<u8>,
    /// VRF proof for proposer selection
    pub vrf_proof: Vec<u8>,
    /// Base fee per gas unit (EIP-1559 style)
    pub base_fee: u64,
    /// Target gas usage per block
    pub gas_target: u64,
    /// Actual gas used in this block
    pub gas_used: u64,
}

// Helper struct for fork detection
#[derive(Debug, Clone)]
struct ForkInfo {
    height: u64,
    hash: Vec<u8>,
}

/// Handle for managing Proof of Stake state independently
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PosStateHandle {
    inner: PoSState,
}

impl PosStateHandle {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: PoSState::new()?
        })
    }

    pub fn get_finalized_height(&self) -> u64 {
        self.inner.get_finalized_height()
    }

    pub fn is_key_allowed_to_stake(&self, public_key: &[u8], height: u64) -> bool {
        self.inner.is_key_allowed_to_stake(public_key, height)
    }

    pub fn get_staker(&self, address: &[u8]) -> Option<&Staker> {
        self.inner.stakers.get(address)
    }

    pub fn record_proposal(&mut self, height: u64, proposer: &[u8], block_hash: &[u8]) {
        self.inner.record_proposal(height, proposer, block_hash)
    }

    pub fn create_checkpoint(&mut self, height: u64) {
        self.inner.create_checkpoint(height);
    }

    pub fn should_create_checkpoint(&self, height: u64) -> bool {
        height > self.inner.last_checkpoint_height + self.inner.checkpoint_interval
    }

    pub fn validate_unstake(&self, staker_hash: &[u8]) -> bool {
        self.inner.is_validator(staker_hash)
    }

    pub fn process_unstake(&mut self, staker_hash: &[u8], amount: u64, height: u64) -> Result<(), String> {
        self.inner.request_unstake(staker_hash, amount, height)
    }

    pub fn process_withdrawals(&mut self, height: u64) -> Vec<(Vec<u8>, u64)> {
        self.inner.process_withdrawals(height)
    }

    /// Generate VRF proof and output using the provided seed
    fn generate_vrf_proof_and_output(&mut self, seed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let vrf = self.inner.vrf.as_mut()?;
        
        // Generate VRF proof
        let proof = vrf.prove(seed, seed).ok()?;
        
        // Convert proof to hash
        let hash = vrf.proof_to_hash(&proof).ok()?;
        
        Some((proof, hash))
    }

    /// Verify a VRF proof
    pub fn verify_vrf_proof(&self, seed: &[u8], proof: &[u8], expected_hash: &[u8]) -> bool {
        if let Some(vrf) = &self.inner.vrf {
            // Create a new VRF instance for verification
            if let Ok(mut verify_vrf) = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI) {
                if let Ok(computed_hash) = verify_vrf.verify(seed, seed, proof) {
                    return computed_hash == expected_hash;
                }
            }
        }
        false
    }

    /// Select a proposer using VRF output and optionally VDF
    pub fn prepare_block_proposal(&mut self, prev_hash: &[u8]) -> Option<(Staker, Vec<u8>)> {
        // Get VRF proof and output
        let (vrf_proof, vrf_output) = self.generate_vrf_proof_and_output(prev_hash)?;

        // Optionally apply VDF if enabled
        let (final_output, final_proof) = if self.inner.use_vdf {
            // Generate VDF proof using VRF output as input
            match self.inner.generate_vdf_proof(&vrf_output) {
                Ok(vdf_proof) => (vdf_proof.output, vrf_proof),
                Err(_) => {
                    // Fallback to VRF only if VDF fails
                    info!("VDF generation failed, falling back to VRF only");
                    (vrf_output.clone(), vrf_proof)
                }
            }
        } else {
            (vrf_output.clone(), vrf_proof)
        };

        // Convert final output to a random value between 0 and 1
        let random_value = {
            let mut value = 0u64;
            for (i, byte) in final_output.iter().take(8).enumerate() {
                value |= (*byte as u64) << (i * 8);
            }
            value as f64 / u64::MAX as f64
        };

        // Get stakers and calculate total stake
        let stakers: Vec<&Staker> = self.inner.stakers.values().collect();
        let total_stake: u64 = stakers.iter().map(|s| s.stake_amount).sum();
        
        if total_stake == 0 {
            return None;
        }

        // Select proposer based on weighted random selection
        let mut best_score = 0.0;
        let mut selected = None;

        for staker in stakers {
            let weighted_score = random_value * (staker.stake_amount as f64 / total_stake as f64);
            if weighted_score > best_score {
                best_score = weighted_score;
                selected = Some(staker.clone());
            }
        }

        selected.map(|s| (s, final_proof))
    }

    pub fn initialize_vrf(&mut self) -> Result<(), VRFError> {
        if self.inner.vrf.is_none() {
            self.inner.vrf = Some(ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)?);
        }
        Ok(())
    }

    pub fn stake(&mut self, address_hash: Vec<u8>, amount: u64, public_key: Vec<u8>) -> Result<(), String> {
        self.inner.stake(address_hash, amount, public_key)
    }

    /// Computes the hash of a block
    /// 
    /// # Arguments
    /// * `block` - The block to hash
    /// 
    /// # Returns
    /// * `Vec<u8>` - The SHA-256 hash of the block
    pub fn compute_block_hash(&self, block: &Block) -> Vec<u8> {
        let encoded = bincode::serialize(block).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().to_vec()
    }

    pub fn get_epoch_length(&self) -> u64 {
        self.inner.finalization.epoch_length
    }

    pub fn is_safe_to_build_on(&self, height: u64, current_height: u64) -> bool {
        self.inner.is_safe_to_build_on(height, current_height)
    }

    pub fn get_stake_amount(&self, address: &[u8]) -> u64 {
        self.inner.get_stake_amount(address)
    }

    pub fn was_staker_at_height(&self, address: &[u8], height: u64) -> bool {
        // Check if the address was a staker at the given height by looking at historical records
        if let Some(staker) = self.inner.stakers.get(address) {
            // If they have a last_proposal_height before or at the target height, they were a staker
            if let Some(last_proposal) = staker.last_proposal_height {
                return last_proposal <= height;
            }
        }
        false
    }
}

impl FinalizationProcessor for PosStateHandle {
    fn submit_finalization_vote(&mut self, validator_address: &[u8], vote_height: u64, current_height: u64) -> Result<(), String> {
        self.inner.submit_finalization_vote(validator_address, vote_height, current_height)
    }

    fn try_justify_and_finalize(&mut self, current_height: u64) {
        self.inner.try_justify_and_finalize(current_height)
    }

    fn cleanup_old_votes(&mut self, current_height: u64) {
        self.inner.cleanup_old_votes(current_height)
    }

    fn get_voting_status(&self, height: u64) -> (u64, u64) {
        self.inner.get_voting_status(height)
    }

    fn is_safe_to_build_on(&self, height: u64, current_height: u64) -> bool {
        self.inner.is_safe_to_build_on(height, current_height)
    }

    fn get_finalized_height(&self) -> u64 {
        self.inner.get_finalized_height()
    }

    fn is_height_finalized(&self, height: u64) -> bool {
        self.inner.is_height_finalized(height)
    }

    fn get_epoch_length(&self) -> u64 {
        self.inner.get_epoch_length()
    }

    fn is_epoch_justified(&self, epoch_num: u64) -> bool {
        self.inner.is_epoch_justified(epoch_num)
    }

    fn is_epoch_finalized(&self, epoch_num: u64) -> bool {
        self.inner.is_epoch_finalized(epoch_num)
    }
}

/// The main blockchain structure that manages the chain of blocks and UTXO set.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Blockchain {
    /// Ordered list of blocks in the chain
    pub blocks: Vec<Block>,
    /// Map of UTXO IDs to their corresponding UTXO data
    pub utxos: HashMap<UtxoId, UTXO>,
    /// Handle to the Proof of Stake state
    pub pos_handle: Option<PosStateHandle>,
    /// Target gas usage per block
    pub gas_target: u64,
    /// Current base fee for transactions
    pub base_fee: u64,
    /// Total amount of fees burned since chain start
    pub total_burned_fees: u64,
}

#[derive(Debug)]
pub enum BlockValidationError {
    InvalidConnection(String),
    InvalidFork(String),
    BelowFinalizedHeight(u64),
    InvalidProposer(String),
    InvalidReward(String),
    InvalidTransaction(String),
}

impl fmt::Display for BlockValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConnection(msg) => write!(f, "Invalid connection: {}", msg),
            Self::InvalidFork(msg) => write!(f, "Invalid fork: {}", msg),
            Self::BelowFinalizedHeight(height) => write!(f, "Block below finalized height {}", height),
            Self::InvalidProposer(msg) => write!(f, "Invalid proposer: {}", msg),
            Self::InvalidReward(msg) => write!(f, "Invalid reward: {}", msg),
            Self::InvalidTransaction(msg) => write!(f, "Invalid transaction: {}", msg),
        }
    }
}

impl StdError for BlockValidationError {}

/// Result of block validation containing metadata about the validation process
#[derive(Debug, Default)]
pub struct BlockValidationResult {
    pub fork_point: Option<u64>,
    pub block_hash: Vec<u8>,
    pub total_fees: u64,
    pub checkpoint_needed: bool,
    pub slashing_events: Vec<(Vec<u8>, SlashingReason, u64)>, // (address, reason, height)
}

impl BlockValidationResult {
    fn new(block_hash: Vec<u8>) -> Self {
        Self {
            fork_point: None,
            block_hash,
            total_fees: 0,
            checkpoint_needed: false,
            slashing_events: Vec::new(),
        }
    }
}

impl Blockchain {
    /// Creates a new blockchain with a genesis block
    pub fn new() -> Self {
        let genesis_block = Block {
            index: 0,
            prev_hash: vec![],
            timestamp: 0,
            transactions: vec![],
            proposer_address: vec![],
            block_signature: vec![],
            vrf_proof: Vec::new(),
            base_fee: 21000, // Initial base fee (similar to Ethereum)
            gas_target: 15_000_000, // Target gas per block (similar to Ethereum)
            gas_used: 0,
        };
        Self {
            blocks: vec![genesis_block],
            utxos: HashMap::new(),
            pos_handle: PosStateHandle::new().ok(),
            gas_target: 15_000_000,
            base_fee: 21000,
            total_burned_fees: 0,
        }
    }

    /// Calculate the priority fee portion of a transaction
    fn calculate_priority_fee(&self, tx: &Transaction, block: &Block) -> u64 {
        let base_fee_portion = block.base_fee * tx.gas_used;
        let total_fee = tx.inputs.iter()
            .map(|inp| self.utxos.get(&inp.utxo_id).map(|u| u.amount).unwrap_or(0))
            .sum::<u64>()
            .saturating_sub(tx.outputs.iter().map(|o| o.amount).sum::<u64>());
        
        total_fee.saturating_sub(base_fee_portion)
    }

    /// Estimate gas cost for a transaction
    fn estimate_transaction_gas(&self, tx: &Transaction) -> u64 {
        let mut gas = match tx.tx_type {
            TxType::Regular => 21000, // Base cost for regular transactions
            TxType::Stake => 40000,   // Higher cost for staking operations
            TxType::Unstake => 40000, // Higher cost for unstaking
            TxType::BlockReward => 0, // No gas cost for block rewards
        };

        // Add cost for inputs
        gas += tx.inputs.len() as u64 * 16000; // Cost per input

        // Add cost for outputs
        gas += tx.outputs.len() as u64 * 8000; // Cost per output

        // Add cost for data
        let tx_data_size = bincode::serialize(tx).unwrap().len() as u64;
        gas += tx_data_size * 16; // 16 gas per byte of transaction data

        gas
    }

    /// Process a block with the PoS state
    fn process_block_with_pos(&mut self, block: Block) -> Result<(), BlockValidationError> {
        let pos_handle = match &mut self.pos_handle {
            Some(handle) => handle,
            None => return Err(BlockValidationError::InvalidProposer("PoS state not initialized".to_string())),
        };

        // Calculate and set the base fee for this block
        let base_fee = {
            let prev_block = self.blocks.last().unwrap();
            self.calculate_next_base_fee(prev_block)
        };

        let mut block = block;
        block.base_fee = base_fee;
        block.gas_target = self.blocks.last().unwrap().gas_target; // Maintain the same target
        
        // Calculate gas usage for all transactions
        let mut total_gas_used = 0;
        
        // First pass: estimate gas and validate limits
        for tx in &mut block.transactions {
            // Use the improved gas estimation
            tx.gas_used = self.estimate_transaction_gas(tx);
            
            if tx.gas_used > tx.gas_limit {
                return Err(BlockValidationError::InvalidTransaction(
                    "Transaction exceeds gas limit".to_string()
                ));
            }
            
            total_gas_used += tx.gas_used;
        }
        
        // Set actual gas used in block
        block.gas_used = total_gas_used;
        
        // Second pass: validate priority fees
        for tx in &block.transactions {
            let priority_fee = self.calculate_priority_fee(tx, &block);
            if priority_fee < tx.max_priority_fee {
                return Err(BlockValidationError::InvalidTransaction(
                    "Insufficient priority fee".to_string()
                ));
            }
        }
        
        // Handle fees
        self.handle_block_fees(&block)?;

        // Add the block to the chain
        self.blocks.push(block);
        
        Ok(())
    }

    /// Calculates the total coin supply up to the current block
    pub fn get_total_supply(&self) -> u64 {
        self.utxos.values().map(|utxo| utxo.amount).sum()
    }

    /// Validates and applies a transaction to the UTXO set
    /// 
    /// # Arguments
    /// * `tx` - The transaction to apply
    /// 
    /// # Returns
    /// * `bool` - True if the transaction was successfully applied
    pub fn apply_transaction(&mut self, tx: &Transaction) -> bool {
        // Special validation for block rewards
        if matches!(tx.tx_type, TxType::BlockReward) {
            if !tx.inputs.is_empty() {
                info!("Block reward transaction cannot have inputs");
                return false;
            }
            if tx.outputs.len() != 1 {
                info!("Block reward transaction must have exactly one output");
                return false;
            }
        }

        let mut total_in = 0;
        let mut total_out = 0;

        // Skip input validation for block rewards
        if !matches!(tx.tx_type, TxType::BlockReward) {
            for inp in &tx.inputs {
                let utxo = match self.utxos.get(&inp.utxo_id) {
                    Some(u) => u,
                    None => {
                        info!("UTXO does not exist: {:?}", inp.utxo_id);
                        return false;
                    }
                };

                // Validate the unlocking script
                match utxo.validate_spend(&inp.unlocking_script, self.blocks.len() as u64) {
                    Ok(valid) => {
                        if !valid {
                            info!("Invalid unlocking script");
                            return false;
                        }
                    },
                    Err(e) => {
                        info!("Script execution failed: {}", e);
                        return false;
                    }
                }

                total_in += utxo.amount;
            }
        }

        // Calculate total output
        for outp in &tx.outputs {
            total_out += outp.amount;
        }

        // Skip input/output validation for block rewards
        if !matches!(tx.tx_type, TxType::BlockReward) && total_in < total_out {
            info!("Invalid amount. Total input < total output");
            return false;
        }

        match tx.tx_type {
            TxType::Regular | TxType::BlockReward => {
                // Remove existing UTXOs
                for inp in &tx.inputs {
                    self.utxos.remove(&inp.utxo_id);
                }

                // Create new UTXOs
                for (i, outp) in tx.outputs.iter().enumerate() {
                    let new_id = if matches!(tx.tx_type, TxType::BlockReward) {
                        UtxoId::new(self.blocks.len() as u64, 0, i as u32)
                    } else {
                        UtxoId::new(self.blocks.len() as u64, tx.inputs.len() as u32, i as u32)
                    };
                    
                    self.utxos.insert(new_id, UTXO {
                        amount: outp.amount,
                        owner_hash: outp.locking_script.code.clone(),
                        locking_script: outp.locking_script.clone(),
                        metadata: None,
                    });
                }
            },
            TxType::Stake => {
                // Remove input UTXOs
                for inp in &tx.inputs {
                    self.utxos.remove(&inp.utxo_id);
                }

                // Create staking entry
                let staker_hash = derive_address_from_pk(&tx.inputs[0].unlocking_script.code);
                
                // Update PoS state
                if let Some(pos_handle) = &mut self.pos_handle {
                    if let Err(e) = pos_handle.stake(staker_hash, total_in, tx.inputs[0].unlocking_script.code.clone()) {
                        info!("Staking failed: {}", e);
                        return false;
                    }
                } else {
                    info!("PoS state not initialized");
                    return false;
                }
            },
            TxType::Unstake => {
                // Validate unstaking
                let staker_hash = derive_address_from_pk(&tx.inputs[0].unlocking_script.code);
                let current_height = self.blocks.len() as u64;
                
                let pos_handle = match &mut self.pos_handle {
                    Some(state) => state,
                    None => {
                        info!("PoS state not initialized");
                        return false;
                    }
                };

                // Request unstake
                if let Err(e) = pos_handle.process_unstake(&staker_hash, total_in, current_height) {
                    info!("Unstaking request failed: {}", e);
                    return false;
                }

                // Process any mature withdrawals
                let processed_withdrawals = pos_handle.process_withdrawals(current_height);
                
                // Create UTXOs for processed withdrawals
                for (address, amount) in processed_withdrawals {
                    let mut script = Script::create_empty();
                    script.code = address.clone();
                    let new_utxo = UTXO {
                        amount,
                        owner_hash: address.clone(),
                        locking_script: script,
                        metadata: None,
                    };
                    let new_id = UtxoId::new(current_height, address.len() as u32, 0);
                    self.utxos.insert(new_id, new_utxo);
                }
            }
        }

        true
    }

    /// Validate all transactions in a block and return total fees
    pub fn validate_transactions(&self, block: &Block) -> Result<u64, BlockValidationError> {
        let mut total_fees = 0;
        let mut total_gas_used = 0;

        for tx in &block.transactions {
            // Validate gas usage
            if tx.gas_used > tx.gas_limit {
                return Err(BlockValidationError::InvalidTransaction(
                    "Transaction exceeds gas limit".to_string()
                ));
            }
            total_gas_used += tx.gas_used;

            // Special handling for block reward
            if matches!(tx.tx_type, TxType::BlockReward) {
                if !tx.inputs.is_empty() {
                    return Err(BlockValidationError::InvalidTransaction(
                        "Block reward cannot have inputs".to_string()
                    ));
                }
                if tx.outputs.len() != 1 {
                    return Err(BlockValidationError::InvalidTransaction(
                        "Block reward must have exactly one output".to_string()
                    ));
                }
                
                // Validate reward amount
                let expected_reward = self.compute_block_reward(block.index);
                if tx.outputs[0].amount != expected_reward {
                    return Err(BlockValidationError::InvalidTransaction(
                        "Invalid block reward amount".to_string()
                    ));
                }
                continue;
            }

            // Validate transaction based on type
            match tx.tx_type {
                TxType::Regular => {
                    let (fee, valid) = self.validate_regular_transaction(tx, block)?;
                    if !valid {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid regular transaction".to_string()
                        ));
                    }
                    total_fees += fee;
                }
                TxType::Stake => {
                    if !self.validate_stake_transaction(tx)? {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid stake transaction".to_string()
                        ));
                    }
                }
                TxType::Unstake => {
                    if !self.validate_unstake_transaction(tx)? {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid unstake transaction".to_string()
                        ));
                    }
                }
                TxType::BlockReward => {} // Already handled above
            }
        }

        // Verify total gas used matches block
        if total_gas_used != block.gas_used {
            return Err(BlockValidationError::InvalidTransaction(
                "Block gas used mismatch".to_string()
            ));
        }

        Ok(total_fees)
    }

    /// Handle block fees by creating burn and reward UTXOs
    fn handle_block_fees(&mut self, block: &Block) -> Result<(), BlockValidationError> {
        let (total_fees, burned_fees) = self.calculate_tx_fees(block);
        let proposer_reward = total_fees.saturating_sub(burned_fees);
        
        // Create burn UTXO (effectively removing coins from circulation)
        if burned_fees > 0 {
            let burn_script = Script::create_unspendable(); // Use the correct method for creating unspendable script
            let burn_utxo = UTXO {
                amount: burned_fees,
                owner_hash: [0; 32].to_vec(), // Burn address (all zeros)
                locking_script: burn_script,
                metadata: Some("EIP1559_BURN".to_string()),
            };
            let burn_utxo_id = UtxoId::new(block.index, 0, 0);
            self.utxos.insert(burn_utxo_id, burn_utxo);
            
            // Update total burned amount in chain state
            self.total_burned_fees += burned_fees;
        }
        
        // Add remaining fees to proposer reward
        if proposer_reward > 0 {
            let mut reward_script = Script::new();
            reward_script.code = block.proposer_address.clone();
            let reward_utxo = UTXO {
                amount: proposer_reward,
                owner_hash: block.proposer_address.clone(),
                locking_script: reward_script,
                metadata: Some("PROPOSER_FEE".to_string()),
            };
            let reward_utxo_id = UtxoId::new(block.index, 0, 1);
            self.utxos.insert(reward_utxo_id, reward_utxo);
        }
        
        Ok(())
    }

    /// Calculate transaction fees for a block
    fn calculate_tx_fees(&self, block: &Block) -> (u64, u64) {
        let mut total_fees = 0;
        let mut burned_fees = 0;
        
        for tx in &block.transactions {
            let mut total_in = 0;
            let mut total_out = 0;

            // Skip fee calculation for block rewards
            if matches!(tx.tx_type, TxType::BlockReward) {
                continue;
            }

            // Calculate input amount
            for input in &tx.inputs {
                if let Some(utxo) = self.utxos.get(&input.utxo_id) {
                    total_in += utxo.amount;
                }
            }

            // Calculate output amount
            for output in &tx.outputs {
                total_out += output.amount;
            }

            let tx_fee = total_in.saturating_sub(total_out);
            
            // Calculate burn amount based on base fee
            let base_fee_burn = block.base_fee.saturating_mul(tx.gas_used);
            let burn_amount = std::cmp::min(tx_fee, base_fee_burn);
            
            burned_fees += burn_amount;
            total_fees += tx_fee;
        }
        
        (total_fees, burned_fees)
    }

    /// Get total amount of fees burned since chain start
    pub fn get_total_burned_fees(&self) -> u64 {
        self.total_burned_fees
    }

    /// Get current base fee
    pub fn get_current_base_fee(&self) -> u64 {
        self.blocks.last().map(|b| b.base_fee).unwrap_or(self.base_fee)
    }

    pub fn propose_block(&mut self) -> Option<Block> {
        // Get PoS handle
        let pos_handle = self.pos_handle.as_mut()?;

        // Initialize VRF if needed
        if let Err(e) = pos_handle.initialize_vrf() {
            info!("Failed to initialize VRF: {}", e);
            return None;
        }

        // Get block data
        let last_block = self.blocks.last()?;
        let next_index = last_block.index + 1;
        let prev_hash = {
            use sha2::{Sha256, Digest};
            let encoded = bincode::serialize(last_block).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&encoded);
            hasher.finalize().to_vec()
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Select proposer using VRF and get proof
        let (proposer, vrf_proof) = pos_handle.prepare_block_proposal(&prev_hash)?;

        // Create block
        let block = Block {
            index: next_index,
            prev_hash: prev_hash.clone(),
            timestamp,
            transactions: Vec::new(),
            proposer_address: proposer.address_hash.clone(),
            block_signature: Vec::new(),
            vrf_proof,
            base_fee: 0,
            gas_target: 0,
            gas_used: 0,
        };

        // Record proposal
        let block_hash = pos_handle.compute_block_hash(&block);
        pos_handle.record_proposal(block.index, &block.proposer_address, &block_hash);

        Some(block)
    }

    /// Returns the current height of the blockchain as the number of blocks.
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Returns a range of blocks from start (inclusive) to end (exclusive).
    /// Returns an error if the range is invalid.
    pub fn get_blocks_range(&self, start: u64, end: u64) -> anyhow::Result<Vec<Block>> {
        if start > end || end > self.blocks.len() as u64 {
            Err(anyhow::anyhow!("Invalid block range: start={}, end={}, height={}", start, end, self.blocks.len()))
        } else {
            Ok(self.blocks[start as usize..end as usize].to_vec())
        }
    }

    /// Add a block to the chain with full validation and PoS state updates
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        // First compute block hash since we'll need it multiple times
        let block_ref = &block;
        let block_hash = block_ref.compute_hash();
        
        // Validate the block
        let total_fees = self.validate_transactions(block_ref)?;

        // Handle PoS updates
        if let Some(pos_handle) = &mut self.pos_handle {
            let finalized_height = pos_handle.get_finalized_height();
            
            // Double check finalization (in case it changed during validation)
            if block.index <= finalized_height {
                return Err(anyhow!("Block height below finalized height"));
            }

            // Record the proposal for slashing detection
            pos_handle.record_proposal(
                block.index,
                &block.proposer_address,
                &block_hash
            );

            // Update epoch tracking if needed
            if block.index % pos_handle.get_epoch_length() == 0 {
                pos_handle.create_checkpoint(block.index);
            }
        }

        // Add block to chain
        self.blocks.push(block);
        Ok(())
    }

    /// Process a block with validation
    pub fn process_block(&mut self, block: Block) -> Result<(), BlockValidationError> {
        // Validate block structure
        self.validate_block_structure(&block)?;

        // Validate block timing
        self.validate_block_timing(&block)?;

        // Validate PoS consensus if enabled
        if let Some(pos_handle) = &self.pos_handle {
            // Verify block is not below finalized height
            let finalized_height = pos_handle.get_finalized_height();
            if block.index <= finalized_height {
                return Err(BlockValidationError::InvalidConnection("Block height below finalized height".to_string()));
            }

            // Verify proposer is allowed to propose
            if !pos_handle.is_key_allowed_to_stake(&block.proposer_address, block.index) {
                return Err(BlockValidationError::InvalidProposer("Proposer not allowed to create block".to_string()));
            }

            // Verify VRF proof
            let prev_block = self.blocks.last().unwrap();
            let prev_hash = prev_block.compute_hash();
            if !pos_handle.verify_vrf_proof(&prev_hash, &block.vrf_proof, &block.compute_hash()) {
                return Err(BlockValidationError::InvalidProposer("Invalid VRF proof".to_string()));
            }
        }

        // Validate and process each transaction
        let mut total_fees = 0;
        let mut total_gas_used = 0;

        for tx in &block.transactions {
            // Validate gas usage
            if tx.gas_used > tx.gas_limit {
                return Err(BlockValidationError::InvalidTransaction(
                    "Transaction exceeds gas limit".to_string()
                ));
            }
            total_gas_used += tx.gas_used;

            // Validate transaction based on type
            match tx.tx_type {
                TxType::Regular => {
                    let (fee, valid) = self.validate_regular_transaction(tx, &block)?;
                    if !valid {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid regular transaction".to_string()
                        ));
                    }
                    total_fees += fee;
                }
                TxType::Stake => {
                    if !self.validate_stake_transaction(tx)? {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid stake transaction".to_string()
                        ));
                    }
                }
                TxType::Unstake => {
                    if !self.validate_unstake_transaction(tx)? {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid unstake transaction".to_string()
                        ));
                    }
                }
                TxType::BlockReward => {
                    // Validate block reward
                    if !tx.inputs.is_empty() || tx.outputs.len() != 1 {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid block reward structure".to_string()
                        ));
                    }
                    let expected_reward = self.compute_block_reward(block.index);
                    if tx.outputs[0].amount != expected_reward {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid block reward amount".to_string()
                        ));
                    }
                }
            }
        }

        // Verify total gas used matches block
        if total_gas_used != block.gas_used {
            return Err(BlockValidationError::InvalidTransaction(
                "Block gas used mismatch".to_string()
            ));
        }

        // Handle fees
        self.handle_block_fees(&block)?;

        // Add block to chain
        self.blocks.push(block);
        Ok(())
    }

    /// Calculate the next base fee based on current block's gas usage
    pub fn calculate_next_base_fee(&self, current_block: &Block) -> u64 {
        const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8; // Maximum 12.5% change per block
        
        if current_block.gas_used == current_block.gas_target {
            return current_block.base_fee;
        }
        
        let gas_used_delta = if current_block.gas_used > current_block.gas_target {
            current_block.gas_used - current_block.gas_target
        } else {
            current_block.gas_target - current_block.gas_used
        };
        
        let base_fee_per_gas_delta = std::cmp::max(
            1,
            current_block.base_fee * gas_used_delta / current_block.gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR
        );
        
        if current_block.gas_used > current_block.gas_target {
            current_block.base_fee + base_fee_per_gas_delta
        } else {
            current_block.base_fee.saturating_sub(base_fee_per_gas_delta)
        }
    }

    /// Validate block structure
    pub fn validate_block_structure(&self, block: &Block) -> Result<(), BlockValidationError> {
        // Validate block index
        if block.index != self.height() + 1 {
            return Err(BlockValidationError::InvalidConnection("Invalid block index".to_string()));
        }

        // Validate previous block hash
        if let Some(prev_block) = self.blocks.last() {
            let prev_hash = prev_block.compute_hash();
            if block.prev_hash != prev_hash {
                return Err(BlockValidationError::InvalidConnection("Invalid previous block hash".to_string()));
            }
        } else if !block.prev_hash.is_empty() {
            return Err(BlockValidationError::InvalidConnection("Genesis block must have empty previous hash".to_string()));
        }

        // Validate gas parameters
        if block.gas_target != self.gas_target {
            return Err(BlockValidationError::InvalidTransaction("Invalid gas target".to_string()));
        }

        // Get the previous block for base fee calculation
        let prev_block = self.blocks.last()
            .ok_or_else(|| BlockValidationError::InvalidConnection("No previous block".to_string()))?;

        if block.base_fee != self.calculate_next_base_fee(prev_block) {
            return Err(BlockValidationError::InvalidTransaction("Invalid base fee".to_string()));
        }

        Ok(())
    }

    /// Validate block timing
    pub fn validate_block_timing(&self, block: &Block) -> Result<(), BlockValidationError> {
        // Ensure block timestamp is not in the future
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if block.timestamp > current_time + 120 { // Allow 2 minutes future drift
            return Err(BlockValidationError::InvalidConnection("Block timestamp too far in the future".to_string()));
        }

        // Ensure block timestamp is after previous block
        if let Some(prev_block) = self.blocks.last() {
            if block.timestamp <= prev_block.timestamp {
                return Err(BlockValidationError::InvalidConnection("Block timestamp must be after previous block".to_string()));
            }
        }

        Ok(())
    }

    /// Revert the blockchain to a specific height by removing blocks after that height
    /// 
    /// # Arguments
    /// * `height` - The height to revert to (inclusive)
    /// 
    /// # Returns
    /// * `Result<()>` - Ok if successful, Err if height is invalid
    pub fn revert_to_height(&mut self, height: u64) -> Result<()> {
        if height >= self.blocks.len() as u64 {
            return Err(anyhow!("Cannot revert to height {} as it exceeds current height {}", height, self.blocks.len() - 1));
        }

        // Remove blocks after the specified height
        self.blocks.truncate((height + 1) as usize);

        // Reset UTXOs - remove any that were created after this height
        self.utxos.retain(|utxo_id, _| utxo_id.block_index <= height);

        // If we have a PoS handle, update its state
        if let Some(pos_handle) = &mut self.pos_handle {
            // Create a checkpoint at the revert height to ensure consistency
            pos_handle.create_checkpoint(height);
        }

        Ok(())
    }

    /// Calculate the total work (cumulative difficulty) of the chain
    pub fn get_chain_work(&self) -> u64 {
        // For now, we'll use a simple measure where each block contributes its gas_used
        // plus a constant base difficulty. In a more sophisticated implementation,
        // this could incorporate actual proof-of-work difficulty or stake-weighted difficulty.
        const BASE_DIFFICULTY: u64 = 1_000_000;  // Base difficulty per block
        
        self.blocks.iter().map(|block| {
            BASE_DIFFICULTY + block.gas_used
        }).sum()
    }

    /// Computes the block reward for a given block height
    /// The reward halves every 210,000 blocks (approximately every 4 years at 1 block/minute)
    /// Starting with 50 coins per block
    fn compute_block_reward(&self, block_height: u64) -> u64 {
        const INITIAL_REWARD: u64 = 50_000_000_000; // 50 coins in smallest units
        const HALVING_INTERVAL: u64 = 210_000; // Blocks between each halving
        
        let halvings = block_height / HALVING_INTERVAL;
        if halvings >= 64 { // After 64 halvings the reward would be 0
            return 0;
        }
        
        INITIAL_REWARD >> halvings // Right shift operator divides by 2 for each halving
    }

    /// Validate a regular transaction and return (fee, is_valid)
    fn validate_regular_transaction(&self, tx: &Transaction, block: &Block) -> Result<(u64, bool), BlockValidationError> {
        let mut total_in = 0;
        let mut total_out = 0;

        // Validate inputs
        for input in &tx.inputs {
            let utxo = self.utxos.get(&input.utxo_id)
                .ok_or_else(|| {
                    BlockValidationError::InvalidTransaction(format!("UTXO not found: {:?}", input.utxo_id))
                })?;

            // Validate the unlocking script
            match utxo.validate_spend(&input.unlocking_script, block.index) {
                Ok(valid) => {
                    if !valid {
                        return Ok((0, false));
                    }
                },
                Err(e) => {
                    return Err(BlockValidationError::InvalidTransaction(format!("Script execution failed: {}", e)));
                }
            }

            total_in += utxo.amount;
        }

        // Calculate total output
        for output in &tx.outputs {
            total_out += output.amount;
        }

        if total_in < total_out {
            return Ok((0, false));
        }

        // Calculate fee
        let fee = total_in - total_out;
        
        // Validate gas and fee
        if tx.gas_used > tx.gas_limit {
            return Ok((0, false));
        }

        // Ensure fee covers base fee plus priority fee
        let min_required_fee = block.base_fee * tx.gas_used;
        if fee < min_required_fee {
            return Ok((0, false));
        }

        Ok((fee, true))
    }

    /// Validate a stake transaction
    fn validate_stake_transaction(&self, tx: &Transaction) -> Result<bool, BlockValidationError> {
        if tx.lock_period.is_none() || tx.lock_period.unwrap() < 100 {
            return Ok(false);
        }

        // Validate staking script
        for input in &tx.inputs {
            if let Some(utxo) = self.utxos.get(&input.utxo_id) {
                match utxo.validate_spend(&input.unlocking_script, self.blocks.len() as u64) {
                    Ok(valid) => {
                        if !valid {
                            return Ok(false);
                        }
                    },
                    Err(e) => {
                        return Err(BlockValidationError::InvalidTransaction(format!("Script execution failed: {}", e)));
                    }
                }
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate an unstake transaction
    fn validate_unstake_transaction(&self, tx: &Transaction) -> Result<bool, BlockValidationError> {
        if let Some(pos_handle) = &self.pos_handle {
            // Validate unstaking script
            for input in &tx.inputs {
                if let Some(utxo) = self.utxos.get(&input.utxo_id) {
                    match utxo.validate_spend(&input.unlocking_script, self.blocks.len() as u64) {
                        Ok(valid) => {
                            if !valid {
                                return Ok(false);
                            }
                        },
                        Err(e) => {
                            return Err(BlockValidationError::InvalidTransaction(format!("Script execution failed: {}", e)));
                        }
                    }
                } else {
                    return Ok(false);
                }
            }

            // Verify staker status
            let staker_hash = derive_address_from_pk(&tx.inputs[0].unlocking_script.code);
            if !pos_handle.validate_unstake(&staker_hash) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub trait BlockChain {
    /// Get the current chain height
    fn height(&self) -> u64;

    /// Get a block by its height
    fn get_block_by_height(&self, height: u64) -> Option<Block>;

    /// Validate a block before adding it to the chain
    fn validate_block(&self, block: &Block) -> Result<BlockValidationResult>;

    /// Add a validated block to the chain
    fn add_block(&mut self, block: Block) -> Result<()>;
}

/// Implementation of the blockchain
pub struct Chain {
    /// Ordered list of blocks in the chain
    blocks: Vec<Block>,
    /// Map of UTXO IDs to their corresponding UTXO data
    utxos: std::collections::HashMap<UtxoId, UTXO>,
    /// Handle to the Proof of Stake state
    pos_handle: Option<PosStateHandle>,
    /// Current base fee for transactions
    base_fee: u64,
    /// Target gas usage per block
    gas_target: u64,
}

impl Chain {
    pub fn new() -> Self {
        let genesis_block = Block {
            index: 0,
            prev_hash: vec![],
            timestamp: 0,
            transactions: vec![],
            proposer_address: vec![],
            block_signature: vec![],
            vrf_proof: Vec::new(),
            base_fee: 21000, // Initial base fee
            gas_target: 15_000_000, // Target gas per block
            gas_used: 0,
        };

        Self {
            blocks: vec![genesis_block],
            utxos: std::collections::HashMap::new(),
            pos_handle: PosStateHandle::new().ok(),
            base_fee: 21000,
            gas_target: 15_000_000,
        }
    }

    /// Calculate the next base fee based on current block's gas usage
    pub fn calculate_next_base_fee(&self, current_block: &Block) -> u64 {
        const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8; // Maximum 12.5% change per block
        
        if current_block.gas_used == current_block.gas_target {
            return current_block.base_fee;
        }
        
        let gas_used_delta = if current_block.gas_used > current_block.gas_target {
            current_block.gas_used - current_block.gas_target
        } else {
            current_block.gas_target - current_block.gas_used
        };
        
        let base_fee_per_gas_delta = std::cmp::max(
            1,
            current_block.base_fee * gas_used_delta / current_block.gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR
        );
        
        if current_block.gas_used > current_block.gas_target {
            current_block.base_fee + base_fee_per_gas_delta
        } else {
            current_block.base_fee.saturating_sub(base_fee_per_gas_delta)
        }
    }

    /// Validate block structure
    pub fn validate_block_structure(&self, block: &Block) -> Result<(), BlockValidationError> {
        // Validate block index
        if block.index != self.height() + 1 {
            return Err(BlockValidationError::InvalidConnection("Invalid block index".to_string()));
        }

        // Validate previous block hash
        if let Some(prev_block) = self.blocks.last() {
            let prev_hash = prev_block.compute_hash();
            if block.prev_hash != prev_hash {
                return Err(BlockValidationError::InvalidConnection("Invalid previous block hash".to_string()));
            }
        } else if !block.prev_hash.is_empty() {
            return Err(BlockValidationError::InvalidConnection("Genesis block must have empty previous hash".to_string()));
        }

        // Validate gas parameters
        if block.gas_target != self.gas_target {
            return Err(BlockValidationError::InvalidTransaction("Invalid gas target".to_string()));
        }

        // Get the previous block for base fee calculation
        let prev_block = self.blocks.last()
            .ok_or_else(|| BlockValidationError::InvalidConnection("No previous block".to_string()))?;

        if block.base_fee != self.calculate_next_base_fee(prev_block) {
            return Err(BlockValidationError::InvalidTransaction("Invalid base fee".to_string()));
        }

        Ok(())
    }

    /// Validate block timing
    pub fn validate_block_timing(&self, block: &Block) -> Result<(), BlockValidationError> {
        // Ensure block timestamp is not in the future
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if block.timestamp > current_time + 120 { // Allow 2 minutes future drift
            return Err(BlockValidationError::InvalidConnection("Block timestamp too far in the future".to_string()));
        }

        // Ensure block timestamp is after previous block
        if let Some(prev_block) = self.blocks.last() {
            if block.timestamp <= prev_block.timestamp {
                return Err(BlockValidationError::InvalidConnection("Block timestamp must be after previous block".to_string()));
            }
        }

        Ok(())
    }

    /// Get the current chain height
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Computes the hash of a block
    pub fn compute_block_hash(&self, block: &Block) -> Vec<u8> {
        let encoded = bincode::serialize(block).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().to_vec()
    }

    /// Computes the block reward for a given block height
    /// The reward halves every 210,000 blocks (approximately every 4 years at 1 block/minute)
    /// Starting with 50 coins per block
    fn compute_block_reward(&self, block_height: u64) -> u64 {
        const INITIAL_REWARD: u64 = 50_000_000_000; // 50 coins in smallest units
        const HALVING_INTERVAL: u64 = 210_000; // Blocks between each halving
        
        let halvings = block_height / HALVING_INTERVAL;
        if halvings >= 64 { // After 64 halvings the reward would be 0
            return 0;
        }
        
        INITIAL_REWARD >> halvings // Right shift operator divides by 2 for each halving
    }

    /// Validate a regular transaction and return (fee, is_valid)
    fn validate_regular_transaction(&self, tx: &Transaction, block: &Block) -> Result<(u64, bool), BlockValidationError> {
        let mut total_in = 0;
        let mut total_out = 0;

        // Validate inputs
        for input in &tx.inputs {
            let utxo = self.utxos.get(&input.utxo_id)
                .ok_or_else(|| {
                    BlockValidationError::InvalidTransaction(format!("UTXO not found: {:?}", input.utxo_id))
                })?;

            // Validate the unlocking script
            match utxo.validate_spend(&input.unlocking_script, block.index) {
                Ok(valid) => {
                    if !valid {
                        return Ok((0, false));
                    }
                },
                Err(e) => {
                    return Err(BlockValidationError::InvalidTransaction(format!("Script execution failed: {}", e)));
                }
            }

            total_in += utxo.amount;
        }

        // Calculate total output
        for output in &tx.outputs {
            total_out += output.amount;
        }

        if total_in < total_out {
            return Ok((0, false));
        }

        // Calculate fee
        let fee = total_in - total_out;
        
        // Validate gas and fee
        if tx.gas_used > tx.gas_limit {
            return Ok((0, false));
        }

        // Ensure fee covers base fee plus priority fee
        let min_required_fee = block.base_fee * tx.gas_used;
        if fee < min_required_fee {
            return Ok((0, false));
        }

        Ok((fee, true))
    }

    /// Validate a stake transaction
    fn validate_stake_transaction(&self, tx: &Transaction) -> Result<bool, BlockValidationError> {
        if tx.lock_period.is_none() || tx.lock_period.unwrap() < 100 {
            return Ok(false);
        }

        // Validate staking script
        for input in &tx.inputs {
            if let Some(utxo) = self.utxos.get(&input.utxo_id) {
                match utxo.validate_spend(&input.unlocking_script, self.blocks.len() as u64) {
                    Ok(valid) => {
                        if !valid {
                            return Ok(false);
                        }
                    },
                    Err(e) => {
                        return Err(BlockValidationError::InvalidTransaction(format!("Script execution failed: {}", e)));
                    }
                }
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate an unstake transaction
    fn validate_unstake_transaction(&self, tx: &Transaction) -> Result<bool, BlockValidationError> {
        if let Some(pos_handle) = &self.pos_handle {
            // Validate unstaking script
            for input in &tx.inputs {
                if let Some(utxo) = self.utxos.get(&input.utxo_id) {
                    match utxo.validate_spend(&input.unlocking_script, self.blocks.len() as u64) {
                        Ok(valid) => {
                            if !valid {
                                return Ok(false);
                            }
                        },
                        Err(e) => {
                            return Err(BlockValidationError::InvalidTransaction(format!("Script execution failed: {}", e)));
                        }
                    }
                } else {
                    return Ok(false);
                }
            }

            // Verify staker status
            let staker_hash = derive_address_from_pk(&tx.inputs[0].unlocking_script.code);
            if !pos_handle.validate_unstake(&staker_hash) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Validate all transactions in a block and return total fees
    pub fn validate_transactions(&self, block: &Block) -> Result<u64, BlockValidationError> {
        let mut total_fees = 0;
        let mut total_gas_used = 0;

        for tx in &block.transactions {
            // Validate gas usage
            if tx.gas_used > tx.gas_limit {
                return Err(BlockValidationError::InvalidTransaction(
                    "Transaction exceeds gas limit".to_string()
                ));
            }
            total_gas_used += tx.gas_used;

            // Special handling for block reward
            if matches!(tx.tx_type, TxType::BlockReward) {
                if !tx.inputs.is_empty() {
                    return Err(BlockValidationError::InvalidTransaction(
                        "Block reward cannot have inputs".to_string()
                    ));
                }
                if tx.outputs.len() != 1 {
                    return Err(BlockValidationError::InvalidTransaction(
                        "Block reward must have exactly one output".to_string()
                    ));
                }
                
                // Validate reward amount
                let expected_reward = self.compute_block_reward(block.index);
                if tx.outputs[0].amount != expected_reward {
                    return Err(BlockValidationError::InvalidTransaction(
                        "Invalid block reward amount".to_string()
                    ));
                }
                continue;
            }

            // Validate transaction based on type
            match tx.tx_type {
                TxType::Regular => {
                    let (fee, valid) = self.validate_regular_transaction(tx, block)?;
                    if !valid {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid regular transaction".to_string()
                        ));
                    }
                    total_fees += fee;
                }
                TxType::Stake => {
                    if !self.validate_stake_transaction(tx)? {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid stake transaction".to_string()
                        ));
                    }
                }
                TxType::Unstake => {
                    if !self.validate_unstake_transaction(tx)? {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid unstake transaction".to_string()
                        ));
                    }
                }
                TxType::BlockReward => {} // Already handled above
            }
        }

        // Verify total gas used matches block
        if total_gas_used != block.gas_used {
            return Err(BlockValidationError::InvalidTransaction(
                "Block gas used mismatch".to_string()
            ));
        }

        Ok(total_fees)
    }
}

impl BlockChain for Chain {
    fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn get_block_by_height(&self, height: u64) -> Option<Block> {
        self.blocks.get(height as usize).cloned()
    }

    fn validate_block(&self, block: &Block) -> Result<BlockValidationResult> {
        // Compute block hash using Block's compute_hash method
        let block_hash = block.compute_hash();
        let mut result = BlockValidationResult::new(block_hash);
        
        // Validate block structure
        self.validate_block_structure(block)
            .map_err(|e| anyhow!(e.to_string()))?;
        
        // Validate block timing
        self.validate_block_timing(block)
            .map_err(|e| anyhow!(e.to_string()))?;
        
        // Validate transactions and get total fees
        let total_fees = self.validate_transactions(block)
            .map_err(|e| anyhow!(e.to_string()))?;
        result.total_fees = total_fees;

        // Check for checkpoint
        if let Some(pos_handle) = &self.pos_handle {
            result.checkpoint_needed = pos_handle.should_create_checkpoint(block.index);
        }

        Ok(result)
    }

    fn add_block(&mut self, block: Block) -> Result<()> {
        // Delegate to the existing add_block method
        self.add_block(block)
    }
}

/// Apply VDF to the input using the SimpleVDF implementation
/// This is a placeholder for the actual VDF implementation in the consensus module
fn apply_vdf(input: &[u8], iterations: u64) -> Vec<u8> {
    use crate::blockchain::consensus::vdf::SimpleVDF;
    
    let vdf = SimpleVDF::new(iterations);
    let proof = vdf.generate(input);
    proof.output
}

impl Chain {
    /// Updates PoS state for a new block, recording proposal and creating a checkpoint if needed
    pub fn update_pos_state(&self, pos_handle: &mut PosStateHandle, block_index: u64, proposer_address: &[u8], block_hash: &[u8], checkpoint_needed: bool) {
        pos_handle.record_proposal(block_index, proposer_address, block_hash);
        if checkpoint_needed {
            pos_handle.create_checkpoint(block_index);
        }
    }
}

impl Block {
    /// Validates all transactions in the block
    pub fn validate_transactions(&self, utxo_set: &HashMap<UtxoId, UTXO>) -> Result<bool, String> {
        for tx in &self.transactions {
            if !tx.validate(utxo_set, self.index)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Computes the block hash
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(self.timestamp.to_be_bytes());
        
        // Hash transactions
        for tx in &self.transactions {
            for input in &tx.inputs {
                hasher.update(input.utxo_id.to_hash().as_bytes());
                hasher.update(&input.unlocking_script.code);
            }
            for output in &tx.outputs {
                hasher.update(output.amount.to_be_bytes());
                hasher.update(&output.locking_script.code);
            }
        }
        
        hasher.update(&self.proposer_address);
        hasher.update(&self.vrf_proof);
        hasher.update(self.base_fee.to_be_bytes());
        hasher.update(self.gas_target.to_be_bytes());
        hasher.update(self.gas_used.to_be_bytes());
        
        hasher.finalize().to_vec()
    }

    /// Validates the block's structure and transactions
    pub fn validate(&self, utxo_set: &HashMap<UtxoId, UTXO>, prev_block: Option<&Block>) -> Result<bool, String> {
        // Check previous block connection
        if let Some(prev) = prev_block {
            if self.prev_hash != prev.compute_hash() {
                return Ok(false);
            }
            if self.index != prev.index + 1 {
                return Ok(false);
            }
            if self.timestamp <= prev.timestamp {
                return Ok(false);
            }
        } else if self.index != 0 {
            return Ok(false);
        }

        // Validate all transactions
        if !self.validate_transactions(utxo_set)? {
            return Ok(false);
        }

        Ok(true)
    }
}

impl Transaction {
    /// Validates the transaction against a UTXO set
    /// 
    /// # Arguments
    /// * `utxo_set` - Map of UTXO IDs to their corresponding UTXOs
    /// * `block_height` - Current block height for timelock validation
    /// 
    /// # Returns
    /// * `Result<bool, String>` - Ok(true) if valid, Ok(false) if invalid, Err if error
    pub fn validate(&self, utxo_set: &HashMap<UtxoId, UTXO>, block_height: u64) -> Result<bool, String> {
        // Skip validation for block rewards
        if matches!(self.tx_type, TxType::BlockReward) {
            return Ok(true);
        }

        let mut total_in = 0;
        let mut total_out = 0;

        // Validate inputs
        for input in &self.inputs {
            let utxo = match utxo_set.get(&input.utxo_id) {
                Some(u) => u,
                None => return Ok(false),
            };

            // Validate the unlocking script
            match utxo.validate_spend(&input.unlocking_script, block_height) {
                Ok(valid) => {
                    if !valid {
                        return Ok(false);
                    }
                },
                Err(e) => return Err(e),
            }

            total_in += utxo.amount;
        }

        // Calculate total output
        for output in &self.outputs {
            total_out += output.amount;
        }

        // Ensure inputs >= outputs
        if total_in < total_out {
            return Ok(false);
        }

        // Additional validation based on transaction type
        match self.tx_type {
            TxType::Stake => {
                // Ensure there is a lock period
                if self.lock_period.is_none() || self.lock_period.unwrap() < 100 {
                    return Ok(false);
                }
            },
            TxType::Unstake => {
                // Ensure the transaction has inputs
                if self.inputs.is_empty() {
                    return Ok(false);
                }
            },
            _ => {}
        }

        Ok(true)
    }
}

impl BlockChain for Blockchain {
    fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn get_block_by_height(&self, height: u64) -> Option<Block> {
        self.blocks.get(height as usize).cloned()
    }

    fn validate_block(&self, block: &Block) -> Result<BlockValidationResult> {
        // Compute block hash using Block's compute_hash method
        let block_hash = block.compute_hash();
        let mut result = BlockValidationResult::new(block_hash);
        
        // Validate block structure
        self.validate_block_structure(block)
            .map_err(|e| anyhow!(e.to_string()))?;
        
        // Validate block timing
        self.validate_block_timing(block)
            .map_err(|e| anyhow!(e.to_string()))?;
        
        // Validate transactions and get total fees
        let total_fees = self.validate_transactions(block)
            .map_err(|e| anyhow!(e.to_string()))?;
        result.total_fees = total_fees;

        // Check for checkpoint
        if let Some(pos_handle) = &self.pos_handle {
            result.checkpoint_needed = pos_handle.should_create_checkpoint(block.index);
        }

        Ok(result)
    }

    fn add_block(&mut self, block: Block) -> Result<()> {
        // Delegate to the existing add_block method
        self.add_block(block)
    }
}
