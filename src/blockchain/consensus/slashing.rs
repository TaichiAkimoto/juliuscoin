use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingReason {
    DoubleProposal,
    DoubleVoting,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub staker_address: Vec<u8>,
    pub reason: SlashingReason,
    pub block_height: u64,
    pub penalty_amount: u64,
}

impl SlashingRecord {
    pub fn new(staker_address: Vec<u8>, reason: SlashingReason, block_height: u64, penalty_amount: u64) -> Self {
        Self {
            staker_address,
            reason,
            block_height,
            penalty_amount,
        }
    }

    pub fn calculate_penalty(reason: &SlashingReason, total_stake: u64) -> u64 {
        match reason {
            SlashingReason::DoubleProposal => total_stake / 2, // 50% penalty
            SlashingReason::DoubleVoting => total_stake,       // 100% penalty
            SlashingReason::Offline => total_stake / 10,       // 10% penalty
        }
    }
} 