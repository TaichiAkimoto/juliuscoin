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

    pub fn compute_block_hash(&self, block: &Block) -> Vec<u8> {
        use sha2::{Sha256, Digest};
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

/// Validation result for a block
#[derive(Debug)]
struct BlockValidationResult {
    validation: Result<(), BlockValidationError>,
    checkpoint_needed: bool,
    block_hash: Vec<u8>,
    fork_point: Option<u64>,
    total_fees: u64,
}

impl Default for BlockValidationResult {
    fn default() -> Self {
        Self {
            validation: Ok(()),
            checkpoint_needed: false,
            block_hash: Vec::new(),
            fork_point: None,
            total_fees: 0,
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
        };
        Self {
            blocks: vec![genesis_block],
            utxos: std::collections::HashMap::new(),
            pos_handle: PosStateHandle::new().ok(),
        }
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
    fn validate_block(&self, block: &Block) -> BlockValidationResult {
        let mut result = BlockValidationResult::default();

        // Compute and store block hash early
        result.block_hash = self.hash_block(block);

        // Block signature verification
        let _block_data = bincode::serialize(&(
            block.index,
            block.prev_hash.clone(),
            block.timestamp,
            block.transactions.clone(),
            block.proposer_address.clone(),
        )).unwrap();

        // Verify block connects to previous block
        let last_block = self.blocks.last().unwrap();
        let prev_hash = self.hash_block(last_block);
        if block.prev_hash != prev_hash {
            result.validation = Err(BlockValidationError::InvalidConnection(
                "Block does not connect to blockchain".to_string()
            ));
            return result;
        }

        // Check finalization rules and slashing conditions
        if let Some(pos_handle) = &self.pos_handle {
            let finalized_height = pos_handle.get_finalized_height();
            
            // Verify VRF proof
            if !pos_handle.verify_vrf_proof(&prev_hash, &block.vrf_proof, &result.block_hash) {
                result.validation = Err(BlockValidationError::InvalidProposer(
                    "Invalid VRF proof".to_string()
                ));
                return result;
            }

            // Find the fork point with improved logic
            match self.find_fork_point(block, &mut result) {
                Ok(fork_info) => {
                    // Check if fork is below finalized height
                    if fork_info.height <= finalized_height {
                        result.validation = Err(BlockValidationError::BelowFinalizedHeight(finalized_height));
                        return result;
                    }
                },
                Err(e) => {
                    result.validation = Err(e);
                    return result;
                }
            }

            // Check if proposer's key is allowed to stake
            if let Some(staker) = pos_handle.get_staker(&block.proposer_address) {
                if !pos_handle.is_key_allowed_to_stake(&staker.public_key, block.index) {
                    result.validation = Err(BlockValidationError::InvalidProposer(
                        "Proposer's key is not allowed to stake at this height".to_string()
                    ));
                    return result;
                }
            }

            result.checkpoint_needed = pos_handle.should_create_checkpoint(block.index);
        }

        // Validate transactions
        match self.validate_transactions(block) {
            Ok(fees) => {
                result.total_fees = fees;
            },
            Err(e) => {
                result.validation = Err(e);
                return result;
            }
        }

        // Verify no existing block reward transaction
        if block.transactions.iter().any(|tx| matches!(tx.tx_type, TxType::BlockReward)) {
            result.validation = Err(BlockValidationError::InvalidReward(
                "Block already contains a reward transaction".to_string()
            ));
            return result;
        }

        result
    }

    /// Find the fork point of a new block
    fn find_fork_point(&self, block: &Block, result: &mut BlockValidationResult) 
        -> Result<ForkInfo, BlockValidationError> {
        let mut height = block.index;
        let mut current_hash = block.prev_hash.clone();
        
        // Create a temporary vec of block hashes with their heights
        let block_hashes: Vec<_> = self.blocks.iter()
            .map(|b| (b.index, self.hash_block(b)))
            .collect();

        for (block_height, hash) in block_hashes.iter().rev() {
            if *hash == current_hash {
                result.fork_point = Some(*block_height);
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
    fn update_pos_state(pos_handle: &mut PosStateHandle, block_index: u64, proposer_address: &[u8], block_hash: &[u8], checkpoint_needed: bool) {
        // Record the proposal
        pos_handle.record_proposal(block_index, proposer_address, block_hash);
        
        // Create checkpoint if needed
        if checkpoint_needed {
            pos_handle.create_checkpoint(block_index);
        }
    }

    /// Adds a new block to the chain after validation
    pub fn add_block(&mut self, block: Block, governance: &mut Governance) -> Result<(), BlockValidationError> {
        // First validate the block without modifying state
        let validation = self.validate_block(&block);
        validation.validation?;

        // Clone block for modification
        let mut block_to_add = block.clone();

        // Apply all regular transactions first
        for tx in &block.transactions {
            if !self.apply_transaction(tx) {
                return Err(BlockValidationError::InvalidTransaction(
                    "Failed to apply transaction".to_string()
                ));
            }
        }

        // Calculate treasury fee
        let treasury_fee = (validation.total_fees * governance.get_treasury_fee_rate()) / 10000;
        let proposer_fee = validation.total_fees - treasury_fee;

        // Add block reward transaction with fees (minus treasury portion)
        let block_reward = self.compute_block_reward(block.index) + proposer_fee;
        if block_reward > 0 {
            let reward_tx = Transaction {
                tx_type: TxType::BlockReward,
                inputs: vec![],
                outputs: vec![TxOutput {
                    amount: block_reward,
                    recipient_hash: block.proposer_address.clone(),
                }],
                lock_period: None,
            };

            if !self.apply_transaction(&reward_tx) {
                return Err(BlockValidationError::InvalidReward(
                    "Failed to apply block reward transaction".to_string()
                ));
            }

            block_to_add.transactions.push(reward_tx);
            info!("Added block reward of {} coins to proposer", block_reward as f64 / 1_000_000_000.0);
        }

        // Add treasury fee
        if treasury_fee > 0 {
            governance.collect_treasury_fees(treasury_fee);
            info!("Added {} coins to governance treasury", treasury_fee as f64 / 1_000_000_000.0);
        }

        // Update PoS state if needed
        if let Some(pos_handle) = &mut self.pos_handle {
            Self::update_pos_state(
                pos_handle,
                block.index,
                &block.proposer_address,
                &validation.block_hash,
                validation.checkpoint_needed,
            );
        }

        // Finally add the block
        self.blocks.push(block_to_add);
        Ok(())
    }

    /// Computes the hash of a block
    /// 
    /// # Arguments
    /// * `block` - The block to hash
    /// 
    /// # Returns
    /// * `Vec<u8>` - The SHA-256 hash of the block
    pub fn hash_block(&self, block: &Block) -> Vec<u8> {
        use sha2::{Sha256, Digest};
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
        };

        // Record proposal
        let block_hash = pos_handle.compute_block_hash(&block);
        pos_handle.record_proposal(block.index, &block.proposer_address, &block_hash);

        Some(block)
    }
}

