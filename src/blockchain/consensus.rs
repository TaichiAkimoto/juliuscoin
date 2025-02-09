//! Proof of Stake (PoS) consensus implementation.
//! 
//! This module implements a Proof of Stake consensus mechanism with:
//! - VRF-based validator selection
//! - Slashing conditions for misbehavior
//! - Checkpointing for finality
//! - Stake-weighted block production
//! 
//! The implementation includes mechanisms to prevent various attack vectors
//! and ensure network security through economic incentives.

use crate::chain::{Block, Transaction};
use crate::Blockchain;
use crate::crypto::sign_message;
use log::info;
use vrf::{VRFProof, VRF, ECVRF};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Represents different types of slashable offenses in the PoS system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingReason {
    /// Proposing multiple blocks at the same height
    DoubleProposal,
    /// Voting for conflicting blocks at the same height
    DoubleVoting,
    /// Failed to participate in consensus when selected
    Offline,
}

/// Records a slashing event for a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecord {
    /// Address of the slashed staker
    pub staker_address: Vec<u8>,
    /// Reason for the slash
    pub reason: SlashingReason,
    /// Block height at which the slash occurred
    pub block_height: u64,
    /// Amount of stake slashed as penalty
    pub penalty_amount: u64,
}

/// Represents a validator in the PoS system.
#[derive(Clone, Serialize, Deserialize)]
pub struct Staker {
    /// Hash of the staker's post-quantum address
    pub address_hash: Vec<u8>,
    /// Amount of coins staked
    pub stake_amount: u64,
    /// Dilithium public key for block signing
    pub public_key: Vec<u8>,
    /// VRF secret key for proposer selection
    pub secret_key: Vec<u8>,
    /// Height of the last block proposed by this staker
    pub last_proposal_height: Option<u64>,
    /// Timestamp of last consensus participation
    pub last_active_time: u64,
    /// History of slashing events for this staker
    pub slashing_records: Vec<SlashingRecord>,
}

/// Maintains the state of the Proof of Stake system.
#[derive(Clone, Serialize, Deserialize)]
pub struct PoSState {
    /// Map of staker addresses to their information
    pub stakers: HashMap<Vec<u8>, Staker>,
    /// VRF instance for random proposer selection
    pub vrf: ECVRF,
    /// Global history of all slashing events
    pub slashing_records: Vec<SlashingRecord>,
    /// Height of the last checkpoint block
    pub last_checkpoint_height: u64,
    /// Number of blocks between checkpoints
    pub checkpoint_interval: u64,
}

impl PoSState {
    /// Creates a new PoS state with initial settings
    pub fn new() -> Self {
        Self {
            stakers: HashMap::new(),
            vrf: ECVRF::new(),
            slashing_records: Vec::new(),
            last_checkpoint_height: 0,
            checkpoint_interval: 100, // 100ブロックごとにチェックポイント
        }
    }

    /// Slashes a staker for misbehavior
    /// 
    /// # Arguments
    /// * `staker_address` - Address of the misbehaving staker
    /// * `reason` - Type of slashable offense
    /// * `block_height` - Height at which the offense occurred
    pub fn slash_staker(&mut self, staker_address: &[u8], reason: SlashingReason, block_height: u64) {
        if let Some(staker) = self.stakers.get_mut(staker_address) {
            let penalty_amount = match reason {
                SlashingReason::DoubleProposal => staker.stake_amount / 2, // 50%のスラッシング
                SlashingReason::DoubleVoting => staker.stake_amount,       // 100%のスラッシング
                SlashingReason::Offline => staker.stake_amount / 10,       // 10%のスラッシング
            };

            let record = SlashingRecord {
                staker_address: staker_address.to_vec(),
                reason: reason.clone(),
                block_height,
                penalty_amount,
            };

            staker.stake_amount -= penalty_amount;
            staker.slashing_records.push(record.clone());
            self.slashing_records.push(record);

            info!(
                "Staker slashed: {:?}, Reason: {:?}, Amount: {}",
                hex::encode(staker_address),
                reason,
                penalty_amount
            );
        }
    }

    /// Selects the next block proposer using VRF
    /// 
    /// # Arguments
    /// * `seed` - Random seed for VRF (usually previous block hash)
    /// 
    /// # Returns
    /// * `Option<&Staker>` - The selected proposer, if any
    pub fn select_proposer(&self, seed: &[u8]) -> Option<&Staker> {
        let total_stake: u64 = self.stakers.values().map(|s| s.stake_amount).sum();
        if total_stake == 0 {
            return None;
        }

        // 各ステーカーのVRF出力とステーク量から選択確率を計算
        let mut best_score = 0.0;
        let mut selected = None;

        for staker in self.stakers.values() {
            // VRF計算
            if let Ok(proof) = self.vrf.prove(&staker.secret_key, seed) {
                let hash = proof.hash();
                // VRF出力を0-1の範囲にマッピング
                let vrf_value = u64::from_be_bytes(hash[0..8].try_into().unwrap()) as f64 
                    / u64::MAX as f64;
                
                // ステーク量による重み付け
                let weighted_score = vrf_value * (staker.stake_amount as f64 / total_stake as f64);
                
                if weighted_score > best_score {
                    best_score = weighted_score;
                    selected = Some(staker);
                }
            }
        }

        selected
    }

    /// Creates a checkpoint for finality
    /// 
    /// # Arguments
    /// * `block_height` - Height at which to create the checkpoint
    /// 
    /// # Returns
    /// * `bool` - True if checkpoint was successfully created
    pub fn create_checkpoint(&mut self, block_height: u64) -> bool {
        if block_height - self.last_checkpoint_height >= self.checkpoint_interval {
            // チェックポイントの作成処理
            self.last_checkpoint_height = block_height;
            
            // 長期間オフラインのステーカーをスラッシング
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let offline_threshold = 24 * 60 * 60; // 24時間
            
            for (address, staker) in self.stakers.iter() {
                if current_time - staker.last_active_time > offline_threshold {
                    self.slash_staker(
                        address,
                        SlashingReason::Offline,
                        block_height,
                    );
                }
            }
            
            true
        } else {
            false
        }
    }
}

/// Produces a new block in the PoS system
/// 
/// # Arguments
/// * `chain` - The blockchain instance
/// * `transactions` - List of transactions to include in the block
/// * `proposer` - The selected block proposer
/// * `pos_state` - Current state of the PoS system
/// 
/// # Returns
/// * `Block` - The newly created block
pub fn produce_block(
    chain: &mut Blockchain,
    transactions: Vec<Transaction>,
    proposer: &Staker,
    pos_state: &mut PoSState,
) -> Block {
    let last_block = chain.blocks.last().unwrap();
    let next_index = last_block.index + 1;
    let prev_hash = chain.hash_block(last_block);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 二重提案のチェック
    if let Some(last_height) = proposer.last_proposal_height {
        if next_index - last_height < 100 { // 100ブロック以内の二重提案をチェック
            pos_state.slash_staker(
                &proposer.address_hash,
                SlashingReason::DoubleProposal,
                next_index,
            );
            panic!("Double proposal detected!");
        }
    }

    let block_candidate = Block {
        index: next_index,
        prev_hash,
        timestamp,
        transactions,
        proposer_address: proposer.address_hash.clone(),
        block_signature: vec![], // ここで署名を後付けする
    };

    // ブロック署名
    let block_data = bincode::serialize(&(
        block_candidate.index,
        block_candidate.prev_hash.clone(),
        block_candidate.timestamp,
        block_candidate.transactions.clone(),
        block_candidate.proposer_address.clone(),
    ))
    .unwrap();

    let sig = sign_message(&block_data, &proposer.secret_key);

    // チェックポイント処理
    pos_state.create_checkpoint(next_index);

    // 署名を格納
    Block {
        block_signature: sig,
        ..block_candidate
    }
}

/// Executes one step of the PoS consensus algorithm
/// 
/// # Arguments
/// * `chain` - The blockchain instance
/// * `mempool` - Pending transactions to potentially include
/// * `pos_state` - Current state of the PoS system
pub fn pos_step(
    chain: &mut Blockchain,
    mempool: Vec<Transaction>,
    pos_state: &mut PoSState,
) {
    // VRFのシード値として前ブロックのハッシュを使用
    let last_block = chain.blocks.last().unwrap();
    let seed = chain.hash_block(last_block);

    if let Some(proposer) = pos_state.select_proposer(&seed) {
        info!("選出されたProposer: {:?}", hex::encode(&proposer.address_hash));
        let new_block = produce_block(chain, mempool, proposer, pos_state);
        
        // プロポーザーの状態更新
        if let Some(staker) = pos_state.stakers.get_mut(&proposer.address_hash) {
            staker.last_proposal_height = Some(new_block.index);
            staker.last_active_time = new_block.timestamp;
        }
        
        chain.add_block(new_block);
    } else {
        info!("有効なステーカーが存在しないためブロックを生成できません");
    }
}
