use std::collections::HashMap;
use anyhow::Result;
use crate::blockchain::consensus::staking::types::{ValidatorVote, EpochInfo, FinalizationState};

pub trait FinalizationProcessor {
    /// Submit a finalization vote for a validator
    fn submit_finalization_vote(&mut self, validator_address: &[u8], vote_height: u64, current_height: u64) -> Result<(), String>;
    
    /// Try to justify and finalize epochs based on current votes
    fn try_justify_and_finalize(&mut self, current_height: u64);
    
    /// Clean up old votes that are no longer needed
    fn cleanup_old_votes(&mut self, current_height: u64);
    
    /// Get the current voting status for a height
    fn get_voting_status(&self, height: u64) -> (u64, u64); // Returns (total_votes, required_votes)
    
    /// Check if it's safe to build on a given height
    fn is_safe_to_build_on(&self, height: u64, current_height: u64) -> bool;
    
    /// Get the current finalized height
    fn get_finalized_height(&self) -> u64;
    
    /// Check if a specific height is finalized
    fn is_height_finalized(&self, height: u64) -> bool;
    
    /// Get the current epoch length
    fn get_epoch_length(&self) -> u64;
    
    /// Check if an epoch is justified
    fn is_epoch_justified(&self, epoch_num: u64) -> bool;
    
    /// Check if an epoch is finalized
    fn is_epoch_finalized(&self, epoch_num: u64) -> bool;
}

pub trait EpochManager {
    /// Create a new epoch
    fn create_epoch(&mut self, epoch_number: u64, start_height: u64, end_height: u64);
    
    /// Get information about a specific epoch
    fn get_epoch_info(&self, epoch_number: u64) -> Option<&EpochInfo>;
    
    /// Get the current epoch number
    fn get_current_epoch(&self) -> u64;
    
    /// Get the epoch number for a given height
    fn get_epoch_for_height(&self, height: u64) -> u64;
    
    /// Update epoch justification status
    fn justify_epoch(&mut self, epoch_number: u64);
    
    /// Update epoch finalization status
    fn finalize_epoch(&mut self, epoch_number: u64);
}
