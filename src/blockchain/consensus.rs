use crate::chain::{Block, Transaction};
use crate::Blockchain;
use crate::crypto::sign_message;
use log::info;
use vrf::{VRFProof, VRF, ECVRF};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// スラッシング理由
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingReason {
    DoubleProposal,
    DoubleVoting,
    Offline,
}

/// スラッシング記録
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub staker_address: Vec<u8>,
    pub reason: SlashingReason,
    pub block_height: u64,
    pub penalty_amount: u64,
}

/// ステーカー情報を持つ構造体
#[derive(Clone, Serialize, Deserialize)]
pub struct Staker {
    pub address_hash: Vec<u8>,
    pub stake_amount: u64,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub last_proposal_height: Option<u64>,
    pub last_active_time: u64,
    pub slashing_records: Vec<SlashingRecord>,
}

/// PoS コンセンサスの状態管理
pub struct PoSState {
    pub stakers: HashMap<Vec<u8>, Staker>,
    pub vrf: ECVRF,
    pub slashing_records: Vec<SlashingRecord>,
    pub last_checkpoint_height: u64,
    pub checkpoint_interval: u64,
}

impl PoSState {
    pub fn new() -> Self {
        Self {
            stakers: HashMap::new(),
            vrf: ECVRF::new(),
            slashing_records: Vec::new(),
            last_checkpoint_height: 0,
            checkpoint_interval: 100, // 100ブロックごとにチェックポイント
        }
    }

    /// スラッシングの実行
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

    /// VRFを使用してプロポーザーを選出
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

    /// チェックポイントの作成と検証
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

/// ブロック生成
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

/// 改良版PoSフロー：VRFベースの選出とスラッシング機能付き
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
