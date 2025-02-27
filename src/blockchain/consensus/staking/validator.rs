use anyhow::Result;
use crate::blockchain::consensus::staking::types::{Staker, StakingInfo};
use crate::blockchain::consensus::slashing::{SlashingReason, SlashingRecord};

pub trait ValidatorOperations {
    fn is_validator(&self, address_hash: &[u8]) -> bool;
    fn get_active_validators(&self) -> Vec<Vec<u8>>;
    fn get_stake_amount(&self, address_hash: &[u8]) -> u64;
    fn get_staking_info(&self, address_hash: &[u8]) -> Option<StakingInfo>;
    fn stake(&mut self, address: Vec<u8>, amount: u64, public_key: Vec<u8>) -> Result<(), String>;
    fn update_last_active_time(&mut self, address_hash: &[u8]) -> Result<(), String>;
    fn get_total_stake(&self) -> u64;
    fn get_validator_stake(&self, address: &[u8]) -> u64;
    fn was_staker_at_height(&self, address: &[u8], height: u64) -> bool;
    fn slash_staker(&mut self, staker_address: &[u8], reason: SlashingReason, block_height: u64);
    fn cleanup_slashed_validators(&mut self, current_height: u64);
    fn record_proposal(&mut self, block_height: u64, staker_addr: &[u8], block_hash: &[u8]);
    fn record_vote(&mut self, block_height: u64, staker_addr: &[u8], block_hash: &[u8]);
    fn record_key_transfer(&mut self, public_key: &[u8], transfer_height: u64);
    fn is_key_allowed_to_stake(&self, public_key: &[u8], current_height: u64) -> bool;
}
