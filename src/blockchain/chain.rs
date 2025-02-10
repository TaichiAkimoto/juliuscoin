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
use crate::governance::Governance;
use log::info;
use std::time::{SystemTime, UNIX_EPOCH};
use vrf::openssl::{ECVRF, CipherSuite, Error as VRFError};
use vrf::VRF;
use anyhow::{Result, anyhow, Error};
use std::error::Error as StdError;
use std::fmt;
use sha2::{Sha256, Digest};

/// Represents an Unspent Transaction Output (UTXO) in the blockchain.
/// 
/// UTXOs are the fundamental unit of value in the blockchain, representing
/// coins that can be spent in future transactions.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UTXO {
    /// The amount of coins in this UTXO
    pub amount: u64,
    /// Hash of the owner's post-quantum address
    pub owner_hash: Vec<u8>, // PQAddress.hash
}

/// Represents an input to a transaction.
/// 
/// Transaction inputs reference existing UTXOs and include cryptographic proof
/// that the sender has the right to spend them.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxInput {
    /// Unique identifier for the UTXO being spent (format: "block_number-tx_number-output_index")
    pub utxo_id: String,       // UTXOを特定するID (例: "ブロック番号-トランザクション番号-outIndex"など)
    /// Dilithium signature proving ownership of the UTXO
    pub sig: Vec<u8>,          // 署名(Dilithium)
    /// Dilithium public key of the UTXO owner
    pub pub_key: Vec<u8>,      // 公開鍵(Dilithium)
}

/// Represents an output of a transaction.
/// 
/// Transaction outputs create new UTXOs that can be spent in future transactions.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxOutput {
    /// Amount of coins to transfer
    pub amount: u64,
    /// Hash of the recipient's address
    pub recipient_hash: Vec<u8>,
}

/// Represents a complete transaction in the blockchain.
/// 
/// A transaction consumes existing UTXOs as inputs and creates new UTXOs as outputs.
/// The total value of inputs must equal the total value of outputs.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum TxType {
    Regular,
    Stake,
    Unstake,
    BlockReward, // New variant for block rewards
}

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
    pub fn new() -> Result<Self, VRFError> {
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

    /// Select a proposer using VRF output
    pub fn prepare_block_proposal(&mut self, prev_hash: &[u8]) -> Option<(Staker, Vec<u8>)> {
        // Get VRF proof and output
        let (proof, vrf_output) = self.generate_vrf_proof_and_output(prev_hash)?;
        
        // Convert VRF output to a random value between 0 and 1
        let random_value = {
            let mut value = 0u64;
            for (i, byte) in vrf_output.iter().take(8).enumerate() {
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

        selected.map(|s| (s, proof))
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
}

/// The main blockchain structure that manages the chain of blocks and UTXO set.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Blockchain {
    /// Ordered list of blocks in the chain
    pub blocks: Vec<Block>,
    /// Map of UTXO IDs to their corresponding UTXO data
    pub utxos: std::collections::HashMap<String, UTXO>,
    /// Handle to the Proof of Stake state
    pub pos_handle: Option<PosStateHandle>,
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
            utxos: std::collections::HashMap::new(),
            pos_handle: PosStateHandle::new().ok(),
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
        
        let reward = INITIAL_REWARD >> halvings; // Right shift operator divides by 2 for each halving
        info!("Block reward for height {} is {} coins", block_height, reward as f64 / 1_000_000_000.0);
        reward
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
            // Existing input validation code...
            for inp in &tx.inputs {
                let utxo = match self.utxos.get(&inp.utxo_id) {
                    Some(u) => u,
                    None => {
                        info!("UTXO does not exist: {}", inp.utxo_id);
                        return false;
                    }
                };
                let tx_hash = bincode::serialize(&tx).unwrap(); 
                if !verify_signature(&tx_hash, &inp.sig, &inp.pub_key) {
                    info!("Invalid signature");
                    return false;
                }
                let pk_hash = derive_address_from_pk(&inp.pub_key);
                if pk_hash != utxo.owner_hash {
                    info!("Owner hash mismatch");
                    return false;
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
                        format!("reward-{}-{}", self.blocks.len(), i)
                    } else {
                        format!("pending-txoutput-{}-{}", tx.inputs.len(), i)
                    };
                    
                    self.utxos.insert(new_id, UTXO {
                        amount: outp.amount,
                        owner_hash: outp.recipient_hash.clone(),
                    });
                }
            },
            TxType::Stake => {
                // Validate staking requirements
                if tx.lock_period.is_none() || tx.lock_period.unwrap() < 100 { // Minimum 100 blocks lock period
                    info!("Invalid staking lock period");
                    return false;
                }

                // Remove input UTXOs
                for inp in &tx.inputs {
                    self.utxos.remove(&inp.utxo_id);
                }

                // Create staking entry
                let staker_hash = derive_address_from_pk(&tx.inputs[0].pub_key);
                
                // Update PoS state
                if let Some(pos_handle) = &mut self.pos_handle {
                    if let Err(e) = pos_handle.process_unstake(&staker_hash, total_in, self.blocks.len() as u64) {
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
                let staker_hash = derive_address_from_pk(&tx.inputs[0].pub_key);
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
                    let new_utxo = UTXO {
                        amount,
                        owner_hash: address.clone(),
                    };
                    let new_id = format!("unstake-{}-{}", current_height, address.len());
                    self.utxos.insert(new_id, new_utxo);
                }
            }
        }

        true
    }

    /// Validate all transactions in a block and return total fees
    fn validate_transactions(&self, block: &Block) -> Result<u64, BlockValidationError> {
        let mut total_fees = 0;

        for tx in &block.transactions {
            match tx.tx_type {
                TxType::Regular => {
                    let (fee, valid) = self.validate_regular_transaction(tx)?;
                    if !valid {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid regular transaction".to_string()
                        ));
                    }
                    total_fees += fee;
                },
                TxType::Stake => {
                    if !self.validate_stake_transaction(tx)? {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid stake transaction".to_string()
                        ));
                    }
                },
                TxType::Unstake => {
                    if !self.validate_unstake_transaction(tx)? {
                        return Err(BlockValidationError::InvalidTransaction(
                            "Invalid unstake transaction".to_string()
                        ));
                    }
                },
                TxType::BlockReward => {
                    // Block rewards are handled separately
                    continue;
                }
            }
        }

        Ok(total_fees)
    }

    /// Validates a block without modifying any state
    pub fn validate_block(&self, block: &Block) -> Result<BlockValidationResult, BlockValidationError> {
        let mut result = BlockValidationResult::default();

        // Compute and store block hash early
        result.block_hash = self.compute_block_hash(block);

        // Verify block connects to previous block
        let last_block = self.blocks.last().unwrap();
        let prev_hash = self.compute_block_hash(last_block);
        if block.prev_hash != prev_hash {
            return Err(BlockValidationError::InvalidConnection("Block does not connect to blockchain".to_string()));
        }

        // Check finalization rules and slashing conditions
        if let Some(pos_handle) = &self.pos_handle {
            let finalized_height = pos_handle.get_finalized_height();
            
            // Verify VRF proof
            if !pos_handle.verify_vrf_proof(&prev_hash, &block.vrf_proof, &result.block_hash) {
                return Err(BlockValidationError::InvalidProposer("Invalid VRF proof".to_string()));
            }

            // Find the fork point
            match self.find_fork_point(block) {
                Ok(fork_info) => {
                    // Check if fork is below finalized height
                    if fork_info.height <= finalized_height {
                        return Err(BlockValidationError::BelowFinalizedHeight(finalized_height));
                    }
                    result.fork_point = Some(fork_info.height);
                },
                Err(e) => return Err(e),
            }

            // Optionally, check proposer's key if available
            if let Some(staker) = pos_handle.get_staker(&block.proposer_address) {
                if !pos_handle.is_key_allowed_to_stake(&staker.public_key, block.index) {
                    return Err(BlockValidationError::InvalidProposer("Proposer's key is not allowed to stake at this height".to_string()));
                }
            }

            result.checkpoint_needed = pos_handle.should_create_checkpoint(block.index);
        }

        // Validate transactions
        match self.validate_transactions(block) {
            Ok(fees) => {
                result.total_fees = fees;
                Ok(result)
            },
            Err(e) => return Err(BlockValidationError::InvalidTransaction(e.to_string())),
        }
    }

    /// Find the fork point of a new block
    pub fn find_fork_point(&self, block: &Block) -> Result<ForkInfo, BlockValidationError> {
        let mut current_hash = block.prev_hash.clone();
        let block_hashes: Vec<_> = self.blocks.iter()
            .map(|b| (b.index, self.compute_block_hash(b)))
            .collect();

        for (block_height, hash) in block_hashes.iter().rev() {
            if *hash == current_hash {
                return Ok(ForkInfo {
                    height: *block_height,
                    hash: hash.clone(),
                });
            }
        }

        Err(BlockValidationError::InvalidFork("Could not find fork point".to_string()))
    }

    /// Validate a regular transaction and return (fee, is_valid)
    fn validate_regular_transaction(&self, tx: &Transaction) -> Result<(u64, bool), BlockValidationError> {
        let mut total_in = 0;
        let mut total_out = 0;

        // Validate inputs
        for inp in &tx.inputs {
            let utxo = self.utxos.get(&inp.utxo_id).ok_or_else(|| {
                BlockValidationError::InvalidTransaction(format!("UTXO does not exist: {}", inp.utxo_id))
            })?;

            let tx_hash = bincode::serialize(&tx).unwrap();
            if !verify_signature(&tx_hash, &inp.sig, &inp.pub_key) {
                return Ok((0, false));
            }

            let pk_hash = derive_address_from_pk(&inp.pub_key);
            if pk_hash != utxo.owner_hash {
                return Ok((0, false));
            }

            total_in += utxo.amount;
        }

        // Calculate total output
        for outp in &tx.outputs {
            total_out += outp.amount;
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
        let last_block = self.blocks.last().unwrap();
        let min_required_fee = last_block.base_fee * tx.gas_used;
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
        // Additional stake validation logic here
        Ok(true)
    }

    /// Validate an unstake transaction
    fn validate_unstake_transaction(&self, tx: &Transaction) -> Result<bool, BlockValidationError> {
        if let Some(pos_handle) = &self.pos_handle {
            let staker_hash = derive_address_from_pk(&tx.inputs[0].pub_key);
            if !pos_handle.validate_unstake(&staker_hash) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Updates PoS state for a new block
    pub fn update_pos_state(pos_handle: &mut PosStateHandle, block_index: u64, proposer_address: &[u8], block_hash: &[u8], checkpoint_needed: bool) {
        pos_handle.record_proposal(block_index, proposer_address, block_hash);
        if checkpoint_needed {
            pos_handle.create_checkpoint(block_index);
        }
    }

    /// Calculate and apply fees for a block
    fn handle_block_fees(&mut self, block: &Block) -> Result<(), BlockValidationError> {
        let (total_fees, burned_fees) = self.calculate_tx_fees(block);
        let proposer_reward = total_fees.saturating_sub(burned_fees);
        
        // Create burn UTXO (effectively removing coins from circulation)
        if burned_fees > 0 {
            let burn_utxo = UTXO {
                amount: burned_fees,
                owner_hash: vec![0; 32], // Burn address (all zeros)
            };
            let burn_utxo_id = format!("burn-{}-{}", block.index, burned_fees);
            self.utxos.insert(burn_utxo_id, burn_utxo);
        }
        
        // Add remaining fees to proposer reward
        if proposer_reward > 0 {
            let reward_utxo = UTXO {
                amount: proposer_reward,
                owner_hash: block.proposer_address.clone(),
            };
            let reward_utxo_id = format!("fee-reward-{}-{}", block.index, proposer_reward);
            self.utxos.insert(reward_utxo_id, reward_utxo);
        }
        
        Ok(())
    }

    /// Calculate the base fee for the next block based on current block's gas usage
    fn calculate_next_base_fee(&self, current_block: &Block) -> u64 {
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

    /// Calculate transaction fees for a block
    fn calculate_tx_fees(&self, block: &Block) -> (u64, u64) {
        let mut total_fees = 0;
        let mut burned_fees = 0;
        
        for tx in &block.transactions {
            let in_sum = tx.inputs.iter().map(|inp| {
                self.utxos.get(&inp.utxo_id).map(|u| u.amount).unwrap_or(0)
            }).sum::<u64>();
            let out_sum = tx.outputs.iter().map(|o| o.amount).sum::<u64>();
            let tx_fee = in_sum.saturating_sub(out_sum);
            
            // Base fee is burned, remainder goes to proposer
            let burn_amount = std::cmp::min(tx_fee, block.base_fee * tx.gas_used);
            burned_fees += burn_amount;
            total_fees += tx_fee;
        }
        
        (total_fees, burned_fees)
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
}

pub trait BlockChain {
    /// Get the current chain height
    fn height(&self) -> u64;

    /// Get a block by its height
    fn get_block_by_height(&self, height: u64) -> Option<Block>;

    /// Validate a block before adding it to the chain
    fn validate_block(&self, block: &Block) -> Result<()>;

    /// Add a validated block to the chain
    fn add_block(&mut self, block: Block) -> Result<()>;
}

/// Implementation of the blockchain
pub struct Chain {
    /// Ordered list of blocks in the chain
    blocks: Vec<Block>,
    /// Map of UTXO IDs to their corresponding UTXO data
    utxos: std::collections::HashMap<String, UTXO>,
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

    /// Calculate the hash of a block
    fn calculate_block_hash(&self, block: &Block) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let encoded = bincode::serialize(&(
            block.index,
            &block.prev_hash,
            block.timestamp,
            &block.transactions,
            &block.proposer_address,
            &block.vrf_proof,
            block.base_fee,
            block.gas_target,
            block.gas_used,
        )).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().to_vec()
    }

    /// Validate block timing
    fn validate_block_timing(&self, block: &Block) -> Result<()> {
        // Ensure block timestamp is not in the future
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if block.timestamp > current_time + 120 { // Allow 2 minutes future drift
            return Err(anyhow!("Block timestamp too far in the future"));
        }

        // Ensure block timestamp is after previous block
        if let Some(prev_block) = self.blocks.last() {
            if block.timestamp <= prev_block.timestamp {
                return Err(anyhow!("Block timestamp must be after previous block"));
            }
        }

        Ok(())
    }

    /// Validate block structure
    fn validate_block_structure(&self, block: &Block) -> Result<()> {
        // Validate block index
        if block.index != self.height() + 1 {
            return Err(anyhow!("Invalid block index"));
        }

        // Validate previous block hash
        if let Some(prev_block) = self.blocks.last() {
            let prev_hash = self.calculate_block_hash(prev_block);
            if block.prev_hash != prev_hash {
                return Err(anyhow!("Invalid previous block hash"));
            }
        } else if !block.prev_hash.is_empty() {
            return Err(anyhow!("Genesis block must have empty previous hash"));
        }

        // Validate gas parameters
        if block.gas_target != self.gas_target {
            return Err(anyhow!("Invalid gas target"));
        }

        if block.base_fee != self.calculate_next_base_fee() {
            return Err(anyhow!("Invalid base fee"));
        }

        Ok(())
    }

    /// Calculate the next base fee based on current block's gas usage
    fn calculate_next_base_fee(&self) -> u64 {
        if let Some(current_block) = self.blocks.last() {
            let gas_used_delta = if current_block.gas_used > self.gas_target {
                current_block.gas_used - self.gas_target
            } else {
                self.gas_target - current_block.gas_used
            };

            let base_fee_delta = std::cmp::max(
                1,
                self.base_fee * gas_used_delta / self.gas_target / 8
            );

            if current_block.gas_used > self.gas_target {
                self.base_fee + base_fee_delta
            } else {
                self.base_fee.saturating_sub(base_fee_delta)
            }
        } else {
            self.base_fee
        }
    }

    /// Validate a single transaction
    fn validate_transaction(&self, tx: &Transaction, block: &Block) -> Result<u64> {
        let mut total_in = 0;
        let mut total_out = 0;

        // Skip input validation for block rewards
        if !matches!(tx.tx_type, TxType::BlockReward) {
            // Validate inputs
            for input in &tx.inputs {
                let utxo = self.utxos.get(&input.utxo_id)
                    .ok_or_else(|| anyhow!("UTXO not found: {}", input.utxo_id))?;

                // Verify signature
                let tx_hash = bincode::serialize(&tx)?;
                if !verify_signature(&tx_hash, &input.sig, &input.pub_key) {
                    return Err(anyhow!("Invalid transaction signature"));
                }

                // Verify ownership
                let pk_hash = derive_address_from_pk(&input.pub_key);
                if pk_hash != utxo.owner_hash {
                    return Err(anyhow!("Invalid UTXO ownership"));
                }

                total_in += utxo.amount;
            }
        }

        // Calculate total output
        for output in &tx.outputs {
            total_out += output.amount;
        }

        // Validate amounts
        if !matches!(tx.tx_type, TxType::BlockReward) && total_in < total_out {
            return Err(anyhow!("Invalid amount: inputs < outputs"));
        }

        // Calculate and validate fees
        let fee = total_in.saturating_sub(total_out);
        let min_fee = block.base_fee * tx.gas_used;
        
        if fee < min_fee {
            return Err(anyhow!("Insufficient fee"));
        }

        Ok(fee)
    }

    /// Validate all transactions in a block
    fn validate_transactions(&self, block: &Block) -> Result<u64> {
        let mut total_fees = 0;
        let mut total_gas_used = 0;
        let mut has_reward = false;

        for tx in &block.transactions {
            // Validate gas usage
            if tx.gas_used > tx.gas_limit {
                return Err(anyhow!("Transaction exceeds gas limit"));
            }
            total_gas_used += tx.gas_used;

            // Special handling for block reward
            if matches!(tx.tx_type, TxType::BlockReward) {
                if has_reward {
                    return Err(anyhow!("Multiple block rewards in block"));
                }
                has_reward = true;
                
                // Validate reward amount
                let expected_reward = self.compute_block_reward(block.index);
                if tx.outputs.len() != 1 || tx.outputs[0].amount != expected_reward {
                    return Err(anyhow!("Invalid block reward amount"));
                }
                continue;
            }

            // Validate regular transaction
            let fee = self.validate_transaction(tx, block)?;
            total_fees += fee;
        }

        // Verify total gas used matches block
        if total_gas_used != block.gas_used {
            return Err(anyhow!("Block gas used mismatch"));
        }

        Ok(total_fees)
    }

    /// Compute block reward for given height
    fn compute_block_reward(&self, height: u64) -> u64 {
        const INITIAL_REWARD: u64 = 50_000_000_000; // 50 coins
        const HALVING_INTERVAL: u64 = 210_000;
        
        let halvings = height / HALVING_INTERVAL;
        if halvings >= 64 {
            return 0;
        }
        
        INITIAL_REWARD >> halvings
    }

    /// Get the current chain height
    pub fn get_height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Get the total chain work (sum of all block difficulties)
    pub fn get_chain_work(&self) -> u64 {
        self.blocks.iter().map(|block| block.base_fee).sum()
    }

    /// Get blocks in a specific range
    pub fn get_blocks_range(&self, start: u64, end: u64) -> Result<Vec<Block>> {
        if start > end || end >= self.blocks.len() as u64 {
            return Err(anyhow!("Invalid block range"));
        }
        Ok(self.blocks[start as usize..=end as usize].to_vec())
    }

    /// Revert chain to a specific height
    pub fn revert_to_height(&mut self, height: u64) -> Result<()> {
        if height >= self.blocks.len() as u64 {
            return Err(anyhow!("Cannot revert to future height"));
        }
        self.blocks.truncate(height as usize + 1);
        Ok(())
    }

    /// Validate a block and return validation result
    pub fn validate_block(&self, block: &Block) -> Result<BlockValidationResult, BlockValidationError> {
        let mut result = BlockValidationResult::default();

        // Compute and store block hash early
        result.block_hash = self.calculate_block_hash(block);

        // Verify block connects to previous block
        let last_block = self.blocks.last().unwrap();
        let prev_hash = self.calculate_block_hash(last_block);
        if block.prev_hash != prev_hash {
            return Err(BlockValidationError::InvalidConnection(
                "Block does not connect to blockchain".to_string()
            ));
        }

        // Check finalization rules and slashing conditions
        if let Some(pos_handle) = &self.pos_handle {
            let finalized_height = pos_handle.get_finalized_height();
            
            // Verify VRF proof
            if !pos_handle.verify_vrf_proof(&prev_hash, &block.vrf_proof, &result.block_hash) {
                return Err(BlockValidationError::InvalidProposer(
                    "Invalid VRF proof".to_string()
                ));
            }

            // Find the fork point
            match self.find_fork_point(block) {
                Ok(fork_info) => {
                    // Check if fork is below finalized height
                    if fork_info.height <= finalized_height {
                        return Err(BlockValidationError::BelowFinalizedHeight(finalized_height));
                    }
                    result.fork_point = Some(fork_info.height);
                },
                Err(e) => return Err(e),
            }

            result.checkpoint_needed = pos_handle.should_create_checkpoint(block.index);
        }

        // Validate transactions
        match self.validate_transactions(block) {
            Ok(fees) => {
                result.total_fees = fees;
                Ok(result)
            },
            Err(e) => Err(BlockValidationError::InvalidTransaction(e.to_string())),
        }
    }

    /// Add a block to the chain
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        // 1. Basic validation
        if block.index != self.blocks.len() as u64 {
            return Err(anyhow!("Invalid block index"));
        }

        // 2. Verify block connects to previous block
        let prev_block = self.blocks.last().unwrap();
        let prev_hash = self.calculate_block_hash(prev_block);
        if block.prev_hash != prev_hash {
            return Err(anyhow!("Block does not connect to previous block"));
        }

        // 3. Validate PoS consensus
        if let Some(pos_handle) = &self.pos_handle {
            // Verify block is not below finalized height
            let finalized_height = pos_handle.get_finalized_height();
            if block.index <= finalized_height {
                return Err(anyhow!("Block height below finalized height"));
            }

            // Verify proposer is allowed to propose
            if !pos_handle.is_key_allowed_to_stake(&block.proposer_address, block.index) {
                return Err(anyhow!("Proposer not allowed to create block"));
            }

            // Verify VRF proof
            let prev_hash = self.calculate_block_hash(prev_block);
            if !pos_handle.verify_vrf_proof(&prev_hash, &block.vrf_proof, &self.calculate_block_hash(&block)) {
                return Err(anyhow!("Invalid VRF proof"));
            }
        }

        // 4. Validate transactions
        let total_fees = self.validate_transactions(&block)?;

        // 5. Update PoS state if needed
        if let Some(pos_handle) = &mut self.pos_handle {
            let checkpoint_needed = pos_handle.should_create_checkpoint(block.index);
            Self::update_pos_state(
                pos_handle,
                block.index,
                &block.proposer_address,
                &self.calculate_block_hash(&block),
                checkpoint_needed,
            );
        }

        // 6. Add block to chain
        self.blocks.push(block);

        Ok(())
    }
}

impl BlockChain for Chain {
    fn height(&self) -> u64 {
        self.blocks.len() as u64 - 1 // Subtract 1 for genesis block
    }

    fn get_block_by_height(&self, height: u64) -> Option<Block> {
        self.blocks.get(height as usize).cloned()
    }

    fn validate_block(&self, block: &Block) -> Result<()> {
        // 1. Validate block structure
        self.validate_block_structure(block)?;

        // 2. Validate block timing
        self.validate_block_timing(block)?;

        // 3. Validate PoS consensus
        if let Some(pos_handle) = &self.pos_handle {
            // Verify block is not below finalized height
            let finalized_height = pos_handle.get_finalized_height();
            if block.index <= finalized_height {
                return Err(anyhow!("Block height below finalized height"));
            }

            // Verify proposer is allowed to propose
            if !pos_handle.is_key_allowed_to_stake(&block.proposer_address, block.index) {
                return Err(anyhow!("Proposer not allowed to create block"));
            }

            // Verify VRF proof
            let prev_hash = self.calculate_block_hash(self.blocks.last().unwrap());
            if !pos_handle.verify_vrf_proof(&prev_hash, &block.vrf_proof, &self.calculate_block_hash(block)) {
                return Err(anyhow!("Invalid VRF proof"));
            }
        }

        // 4. Validate transactions and fees
        self.validate_transactions(block)?;

        Ok(())
    }

    fn add_block(&mut self, block: Block) -> Result<()> {
        // 1. Validate block
        self.validate_block(&block)?;

        // 2. Apply transactions
        let mut new_utxos = std::collections::HashMap::new();
        let mut remove_utxos = Vec::new();

        for tx in &block.transactions {
            // Remove spent UTXOs
            for input in &tx.inputs {
                remove_utxos.push(input.utxo_id.clone());
            }

            // Create new UTXOs
            for (i, output) in tx.outputs.iter().enumerate() {
                let utxo_id = format!("{}-{}-{}", block.index, tx.inputs.len(), i);
                new_utxos.insert(utxo_id, UTXO {
                    amount: output.amount,
                    owner_hash: output.recipient_hash.clone(),
                });
            }
        }

        // 3. Update chain state
        for utxo_id in remove_utxos {
            self.utxos.remove(&utxo_id);
        }
        self.utxos.extend(new_utxos);

        // 4. Update PoS state if needed
        if let Some(pos_handle) = &mut self.pos_handle {
            pos_handle.record_proposal(
                block.index,
                &block.proposer_address,
                &self.calculate_block_hash(&block)
            );

            if pos_handle.should_create_checkpoint(block.index) {
                pos_handle.create_checkpoint(block.index);
            }
        }

        // 5. Update chain parameters
        self.base_fee = block.base_fee;
        self.blocks.push(block);

        Ok(())
    }
}

