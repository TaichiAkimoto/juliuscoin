use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingReason {
    DoubleProposal,
    DoubleVoting,
    OfflineWarning,    // No slashing, just a warning
    OfflineMinor,      // Minor slashing for moderate offline periods
    OfflineMajor,      // Major slashing for extended offline periods
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorParticipation {
    pub missed_proposals: u64,
    pub missed_votes: u64,
    pub consecutive_missed_checkpoints: u32,
    pub last_active_height: u64,
    pub last_warning_height: Option<u64>,
}

impl ValidatorParticipation {
    pub fn new() -> Self {
        Self {
            missed_proposals: 0,
            missed_votes: 0,
            consecutive_missed_checkpoints: 0,
            last_active_height: 0,
            last_warning_height: None,
        }
    }

    pub fn record_activity(&mut self, height: u64) {
        self.consecutive_missed_checkpoints = 0;
        self.last_active_height = height;
    }

    pub fn record_missed_checkpoint(&mut self) {
        self.consecutive_missed_checkpoints += 1;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub staker_address: Vec<u8>,
    pub reason: SlashingReason,
    pub block_height: u64,
    pub penalty_amount: u64,
    pub timestamp: u64,
}

impl SlashingRecord {
    pub fn new(staker_address: Vec<u8>, reason: SlashingReason, block_height: u64, penalty_amount: u64) -> Self {
        Self {
            staker_address,
            reason,
            block_height,
            penalty_amount,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn calculate_penalty(reason: &SlashingReason, total_stake: u64) -> u64 {
        match reason {
            SlashingReason::DoubleProposal => total_stake / 2,    // 50% penalty
            SlashingReason::DoubleVoting => total_stake,          // 100% penalty
            SlashingReason::OfflineWarning => 0,                  // No penalty, just warning
            SlashingReason::OfflineMinor => total_stake / 20,     // 5% penalty
            SlashingReason::OfflineMajor => total_stake / 4,      // 25% penalty
        }
    }
}

// Constants for offline detection thresholds
pub const OFFLINE_WARNING_THRESHOLD: u32 = 3;      // Consecutive missed checkpoints for warning
pub const OFFLINE_MINOR_THRESHOLD: u32 = 5;        // For minor slashing (5%)
pub const OFFLINE_MAJOR_THRESHOLD: u32 = 10;       // For major slashing (25%)
pub const WARNING_COOLDOWN_BLOCKS: u64 = 1000;     // Blocks before another warning can be issued 