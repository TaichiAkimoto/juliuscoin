use std::collections::HashMap;
use crate::blockchain::consensus::staking::types::Staker;

pub trait RewardsDistributor {
    /// Distributes rewards to active validators based on their stake and participation
    fn distribute_rewards(&mut self, current_height: u64);
    
    /// Gets the base reward rate (rewards per 1000 blocks, in basis points)
    fn get_base_reward_rate(&self) -> u64;
    
    /// Sets the base reward rate (rewards per 1000 blocks, in basis points)
    fn set_base_reward_rate(&mut self, rate: u64);
    
    /// Gets the accumulated rewards for a validator
    fn get_accumulated_rewards(&self, address_hash: &[u8]) -> u64;
    
    /// Calculates the reward for a validator based on their stake and the current parameters
    fn calculate_reward(&self, stake_amount: u64, blocks_participated: u64) -> u64;
}
