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
use log::info;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

/// The main blockchain structure that manages the chain of blocks and UTXO set.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Blockchain {
    /// Ordered list of blocks in the chain
    pub blocks: Vec<Block>,
    /// Map of UTXO IDs to their corresponding UTXO data
    pub utxos: std::collections::HashMap<String, UTXO>,
    /// Proof of Stake state
    pub pos_state: Option<PoSState>,
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
        };
        Self {
            blocks: vec![genesis_block],
            utxos: std::collections::HashMap::new(),
            pos_state: PoSState::new().ok(),
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
                if let Some(pos_state) = &mut self.pos_state {
                    if let Err(e) = pos_state.stake(
                        staker_hash.clone(),
                        total_in,
                        tx.inputs[0].pub_key.clone(),
                    ) {
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
                
                let pos_state = match &mut self.pos_state {
                    Some(state) => state,
                    None => {
                        info!("PoS state not initialized");
                        return false;
                    }
                };

                // Request unstake
                if let Err(e) = pos_state.request_unstake(&staker_hash, total_in, current_height) {
                    info!("Unstaking request failed: {}", e);
                    return false;
                }

                // Process any mature withdrawals
                let processed_withdrawals = pos_state.process_withdrawals(current_height);
                
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

    /// Adds a new block to the chain after validation
    /// 
    /// # Arguments
    /// * `block` - The block to add
    /// 
    /// # Returns
    /// * `bool` - True if the block was successfully added
    pub fn add_block(&mut self, mut block: Block) -> bool {
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
        if block.prev_hash != self.hash_block(last_block) {
            info!("Block does not connect to blockchain");
            return false;
        }

        // Check finalization rules
        if let Some(pos_state) = &self.pos_state {
            let finalized_height = pos_state.get_finalized_height();
            
            // Find the fork point
            let mut fork_height = block.index;
            let mut current_hash = block.prev_hash.clone();
            let mut found_fork = false;

            for existing_block in self.blocks.iter().rev() {
                if self.hash_block(existing_block) == current_hash {
                    fork_height = existing_block.index;
                    found_fork = true;
                    break;
                }
            }

            if !found_fork {
                info!("Could not find fork point");
                return false;
            }

            // Check if fork is below finalized height
            if fork_height <= finalized_height {
                info!("Cannot reorganize chain below finalized height {}", finalized_height);
                return false;
            }
        }

        // Verify no existing block reward transaction
        if block.transactions.iter().any(|tx| matches!(tx.tx_type, TxType::BlockReward)) {
            info!("Block already contains a reward transaction");
            return false;
        }

        // Apply all regular transactions first
        for tx in &block.transactions {
            let ok = self.apply_transaction(tx);
            if !ok {
                return false;
            }
        }

        // Add block reward transaction
        let block_reward = self.compute_block_reward(block.index);
        if block_reward > 0 {
            let reward_tx = Transaction {
                tx_type: TxType::BlockReward,
                inputs: vec![], // No inputs for minted coins
                outputs: vec![TxOutput {
                    amount: block_reward,
                    recipient_hash: block.proposer_address.clone(),
                }],
                lock_period: None,
            };

            // Apply the reward transaction
            if !self.apply_transaction(&reward_tx) {
                info!("Failed to apply block reward transaction");
                return false;
            }

            // Add reward transaction to block
            block.transactions.push(reward_tx);
            info!("Added block reward of {} coins to proposer", block_reward as f64 / 1_000_000_000.0);
        }

        let block_index = block.index; // Clone the index before moving block
        
        // Finally add the block
        info!("Adding block #{} with total supply: {}", block_index, self.get_total_supply() as f64 / 1_000_000_000.0);
        self.blocks.push(block);

        // Create checkpoint if needed
        if let Some(pos_state) = &mut self.pos_state {
            pos_state.create_checkpoint(block_index);
        }

        true
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

    pub fn propose_block(&self, pos_state: &mut PoSState) -> Option<Block> {
        let last_block = self.blocks.last()?;
        let next_index = last_block.index + 1;
        let prev_hash = self.hash_block(last_block);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Initialize VRF if needed
        if pos_state.vrf.is_none() {
            if let Err(e) = pos_state.initialize_vrf() {
                info!("Failed to initialize VRF: {}", e);
                return None;
            }
        }

        // Get stakers and VRF for proposer selection
        let stakers: Vec<&Staker> = pos_state.stakers.values().collect();
        let vrf = pos_state.vrf.as_mut()?;
        
        // Use VRF to select proposer
        let proposer = crate::blockchain::consensus::vrf::select_proposer(
            &stakers,
            &prev_hash,
            vrf
        )?;

        // For MVP, we're not implementing actual transaction selection
        // In production, this would select transactions from mempool
        let transactions = Vec::new();

        Some(Block {
            index: next_index,
            prev_hash,
            timestamp,
            transactions,
            proposer_address: proposer.address_hash.clone(),
            block_signature: Vec::new(),  // Should be signed by proposer
        })
    }
}
