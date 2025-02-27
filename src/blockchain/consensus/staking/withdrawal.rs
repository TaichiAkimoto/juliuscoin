use anyhow::Result;
use crate::blockchain::consensus::staking::types::WithdrawalRequest;

pub trait WithdrawalProcessor {
    /// Process all pending withdrawals that have reached their unlock height
    /// Returns a vector of (address, amount) pairs for successful withdrawals
    fn process_withdrawals(&mut self, current_height: u64) -> Vec<(Vec<u8>, u64)>;
    
    /// Request to unstake a certain amount
    /// Returns an error if the request is invalid
    fn request_unstake(&mut self, staker_hash: &[u8], amount: u64, current_height: u64) -> Result<(), String>;
    
    /// Get all pending withdrawals for a staker
    fn get_pending_withdrawals(&self, staker_hash: &[u8]) -> Vec<WithdrawalRequest>;
    
    /// Get the total amount of pending withdrawals for a staker
    fn get_total_pending_withdrawals(&self, staker_hash: &[u8]) -> u64;
    
    /// Check if a withdrawal request is valid
    fn validate_withdrawal_request(&self, staker_hash: &[u8], amount: u64) -> Result<(), String>;
}
