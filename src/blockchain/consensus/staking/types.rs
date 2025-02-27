use serde::{Serialize, Deserialize};
use crate::blockchain::consensus::slashing::{SlashingReason, SlashingRecord};

/// Represents a withdrawal request for unstaking
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct WithdrawalRequest {
    pub amount: u64,
    pub request_height: u64,
    pub unlock_height: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Staker {
    pub address_hash: Vec<u8>,
    pub stake_amount: u64,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub last_proposal_height: Option<u64>,
    pub last_active_time: u64,
    pub slashing_records: Vec<SlashingRecord>,
    pub pending_withdrawals: Vec<WithdrawalRequest>,
    pub accumulated_rewards: u64,
}

impl Staker {
    pub fn new(stake_amount: u64) -> Self {
        Self {
            address_hash: Vec::new(),
            stake_amount,
            public_key: Vec::new(),
            secret_key: Vec::new(),
            last_proposal_height: None,
            last_active_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            slashing_records: Vec::new(),
            pending_withdrawals: Vec::new(),
            accumulated_rewards: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StakingInfo {
    pub current_stake: u64,
    pub pending_withdrawals: Vec<WithdrawalRequest>,
    pub total_pending_withdrawals: u64,
    pub accumulated_rewards: u64,
    pub last_active_time: u64,
    pub slashing_records: Vec<SlashingRecord>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ValidatorVote {
    Finalize(u64), // Vote to finalize up to this height
    Justify(u64),  // Vote to justify an epoch
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EpochInfo {
    pub epoch_number: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub is_justified: bool,
    pub is_finalized: bool,
    pub total_stake_voted: u64,
    pub votes: std::collections::HashMap<Vec<u8>, ValidatorVote>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FinalizationState {
    pub finalized_height: u64,
    pub current_epoch: u64,
    pub epoch_length: u64,
    pub epochs: std::collections::HashMap<u64, EpochInfo>,
    pub votes: std::collections::HashMap<Vec<u8>, ValidatorVote>,
    pub last_vote_height: std::collections::HashMap<Vec<u8>, u64>,
    pub last_cleanup_height: u64,
    pub finality_delay: u64,  // Number of epochs required between justification and finalization
}
