use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use vrf::openssl::{ECVRF, CipherSuite, Error as VRFError};
use crate::blockchain::consensus::slashing::{SlashingReason, SlashingRecord};
use log::info;

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

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ValidatorVote {
    Finalize(u64), // Vote to finalize up to this height
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FinalizationState {
    pub finalized_height: u64,
    pub votes: HashMap<Vec<u8>, ValidatorVote>,
    pub last_vote_height: HashMap<Vec<u8>, u64>,
    pub last_cleanup_height: u64,  // Track when we last cleaned up old votes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PoSState {
    pub stakers: HashMap<Vec<u8>, Staker>,
    #[serde(skip)]
    pub vrf: Option<ECVRF>,
    pub slashing_records: Vec<SlashingRecord>,
    pub last_checkpoint_height: u64,
    pub checkpoint_interval: u64,
    pub minimum_stake: u64,
    pub base_reward_rate: u64,  // Rewards per 1000 blocks, in basis points (1/100 of 1%)
    pub finalization: FinalizationState,
}

impl Clone for PoSState {
    fn clone(&self) -> Self {
        let vrf = if self.vrf.is_some() {
            ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).ok()
        } else {
            None
        };
        
        Self {
            stakers: self.stakers.clone(),
            vrf,
            slashing_records: self.slashing_records.clone(),
            last_checkpoint_height: self.last_checkpoint_height,
            checkpoint_interval: self.checkpoint_interval,
            minimum_stake: self.minimum_stake,
            base_reward_rate: self.base_reward_rate,
            finalization: self.finalization.clone(),
        }
    }
}

impl PoSState {
    pub fn new() -> Result<Self, VRFError> {
        let vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)?;
        Ok(Self {
            stakers: HashMap::new(),
            vrf: Some(vrf),
            slashing_records: Vec::new(),
            last_checkpoint_height: 0,
            checkpoint_interval: 100,
            minimum_stake: 1000,  // Minimum stake amount
            base_reward_rate: 500, // 5% per 1000 blocks
            finalization: FinalizationState {
                finalized_height: 0,
                votes: HashMap::new(),
                last_vote_height: HashMap::new(),
                last_cleanup_height: 0,
            },
        })
    }

    pub fn initialize_vrf(&mut self) -> Result<(), VRFError> {
        if self.vrf.is_none() {
            self.vrf = Some(ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)?);
        }
        Ok(())
    }

    pub fn slash_staker(&mut self, staker_address: &[u8], reason: SlashingReason, block_height: u64) {
        if let Some(staker) = self.stakers.get_mut(staker_address) {
            let penalty_amount = SlashingRecord::calculate_penalty(&reason, staker.stake_amount);
            
            let record = SlashingRecord::new(
                staker_address.to_vec(),
                reason.clone(),
                block_height,
                penalty_amount,
            );

            staker.stake_amount -= penalty_amount;
            staker.slashing_records.push(record.clone());
            self.slashing_records.push(record);
        }
    }

    pub fn create_checkpoint(&mut self, block_height: u64) -> bool {
        if block_height - self.last_checkpoint_height >= self.checkpoint_interval {
            self.last_checkpoint_height = block_height;
            
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let offline_threshold = 24 * 60 * 60; // 24 hours
            
            // Collect addresses that need slashing first
            let addresses_to_slash: Vec<_> = self.stakers
                .iter()
                .filter(|(_, staker)| current_time - staker.last_active_time > offline_threshold)
                .map(|(addr, _)| addr.clone())
                .collect();
            
            // Then perform slashing
            for address in addresses_to_slash {
                self.slash_staker(
                    &address,
                    SlashingReason::Offline,
                    block_height,
                );
            }
            
            true
        } else {
            false
        }
    }

    /// Stakes coins for a validator
    pub fn stake(&mut self, address_hash: Vec<u8>, amount: u64, public_key: Vec<u8>) -> Result<(), String> {
        if amount < self.minimum_stake {
            return Err(format!("Stake amount {} is below minimum required {}", amount, self.minimum_stake));
        }

        let staker = self.stakers.entry(address_hash.clone()).or_insert(Staker {
            address_hash,
            stake_amount: 0,
            public_key,
            secret_key: vec![],
            last_proposal_height: None,
            last_active_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            slashing_records: vec![],
            pending_withdrawals: vec![],
            accumulated_rewards: 0,
        });
        staker.stake_amount += amount;
        Ok(())
    }

    /// Initiates an unstaking request
    pub fn request_unstake(&mut self, address_hash: &[u8], amount: u64, current_height: u64) -> Result<(), String> {
        let staker = self.stakers.get_mut(address_hash)
            .ok_or_else(|| "Staker not found".to_string())?;
        
        if staker.stake_amount < amount {
            return Err("Insufficient stake amount".to_string());
        }

        // Ensure remaining stake is either 0 or above minimum
        if staker.stake_amount - amount < self.minimum_stake && staker.stake_amount - amount > 0 {
            return Err(format!(
                "Remaining stake would be below minimum. Must withdraw all or leave at least {}",
                self.minimum_stake
            ));
        }

        let unlock_height = current_height + 100; // 100 blocks lock period
        staker.pending_withdrawals.push(WithdrawalRequest {
            amount,
            request_height: current_height,
            unlock_height,
        });
        staker.stake_amount -= amount;

        // Remove staker if no stake left and no pending withdrawals
        if staker.stake_amount == 0 && staker.pending_withdrawals.is_empty() {
            self.stakers.remove(address_hash);
        }

        Ok(())
    }

    /// Processes mature withdrawal requests
    pub fn process_withdrawals(&mut self, current_height: u64) -> Vec<(Vec<u8>, u64)> {
        let mut processed_withdrawals = Vec::new();

        // Collect addresses that need processing
        let addresses: Vec<_> = self.stakers.keys().cloned().collect();

        for address in addresses {
            if let Some(staker) = self.stakers.get_mut(&address) {
                // Find mature withdrawals
                let (mature, pending): (Vec<_>, Vec<_>) = staker
                    .pending_withdrawals
                    .drain(..)
                    .partition(|w| w.unlock_height <= current_height);

                // Process mature withdrawals
                let total_withdrawal: u64 = mature.iter().map(|w| w.amount).sum();
                if total_withdrawal > 0 {
                    processed_withdrawals.push((address.clone(), total_withdrawal));
                }

                // Keep remaining pending withdrawals
                staker.pending_withdrawals = pending;

                // Remove staker if no stake left and no pending withdrawals
                if staker.stake_amount == 0 && staker.pending_withdrawals.is_empty() {
                    self.stakers.remove(&address);
                }
            }
        }

        processed_withdrawals
    }

    /// Calculates and distributes staking rewards
    pub fn distribute_rewards(&mut self, current_height: u64) {
        for staker in self.stakers.values_mut() {
            if let Some(last_height) = staker.last_proposal_height {
                let blocks_passed = current_height - last_height;
                if blocks_passed >= 1000 {
                    // Calculate rewards based on stake amount and time
                    let reward = (staker.stake_amount * self.base_reward_rate) / 10000; // Convert basis points to percentage
                    staker.accumulated_rewards += reward;
                    staker.last_proposal_height = Some(current_height);
                }
            }
        }
    }

    /// Gets detailed staking info for an address
    pub fn get_staking_info(&self, address_hash: &[u8]) -> Option<StakingInfo> {
        self.stakers.get(address_hash).map(|staker| {
            let total_pending_withdrawals: u64 = staker.pending_withdrawals
                .iter()
                .map(|w| w.amount)
                .sum();

            StakingInfo {
                current_stake: staker.stake_amount,
                pending_withdrawals: staker.pending_withdrawals.clone(),
                total_pending_withdrawals,
                accumulated_rewards: staker.accumulated_rewards,
                last_active_time: staker.last_active_time,
                slashing_records: staker.slashing_records.clone(),
            }
        })
    }

    /// Gets the total stake amount for a validator
    pub fn get_stake_amount(&self, address_hash: &[u8]) -> u64 {
        self.stakers
            .get(address_hash)
            .map(|s| s.stake_amount)
            .unwrap_or(0)
    }

    /// Checks if an address is a validator
    pub fn is_validator(&self, address_hash: &[u8]) -> bool {
        self.stakers.contains_key(address_hash)
    }

    /// Gets all active validators
    pub fn get_active_validators(&self) -> Vec<&Staker> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let offline_threshold = 24 * 60 * 60; // 24 hours

        self.stakers
            .values()
            .filter(|s| current_time - s.last_active_time <= offline_threshold)
            .collect()
    }

    /// Updates the last active time for a validator
    pub fn update_last_active_time(&mut self, address_hash: &[u8]) -> Result<(), String> {
        let staker = self.stakers.get_mut(address_hash)
            .ok_or_else(|| "Staker not found".to_string())?;
        
        staker.last_active_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Ok(())
    }

    /// Submit a finalization vote from a validator
    pub fn submit_finalization_vote(&mut self, validator_address: &[u8], vote_height: u64, current_height: u64) -> Result<(), String> {
        // Verify validator exists and is active
        let staker = self.stakers.get(validator_address)
            .ok_or_else(|| "Validator not found".to_string())?;

        // Validate vote height
        if vote_height > current_height {
            return Err("Cannot vote for future blocks".to_string());
        }

        if vote_height <= self.finalization.finalized_height {
            return Err("Block height already finalized".to_string());
        }

        // Check if validator can vote at this height
        if let Some(last_vote_height) = self.finalization.last_vote_height.get(validator_address) {
            if current_height <= *last_vote_height {
                return Err("Validator already voted at this height".to_string());
            }
        }

        // Record the vote
        self.finalization.votes.insert(
            validator_address.to_vec(),
            ValidatorVote::Finalize(vote_height)
        );
        self.finalization.last_vote_height.insert(
            validator_address.to_vec(),
            current_height
        );

        // Check if we have enough votes to finalize
        self.try_finalize(current_height);

        // Periodically cleanup old votes (every 100 blocks)
        if current_height >= self.finalization.last_cleanup_height + 100 {
            self.cleanup_old_votes(current_height);
        }

        Ok(())
    }

    /// Try to finalize blocks based on validator votes
    fn try_finalize(&mut self, current_height: u64) {
        let total_stake: u64 = self.stakers.values()
            .map(|s| s.stake_amount)
            .sum();

        // Calculate the minimum height that 2/3 of stake voted to finalize
        let mut height_votes: HashMap<u64, u64> = HashMap::new();
        
        for (validator, vote) in &self.finalization.votes {
            if let ValidatorVote::Finalize(height) = vote {
                if let Some(staker) = self.stakers.get(validator) {
                    *height_votes.entry(*height).or_default() += staker.stake_amount;
                }
            }
        }

        // Find the highest height with 2/3 stake voting for it
        let threshold = total_stake * 2 / 3;
        let mut new_finalized_height = self.finalization.finalized_height;

        for (height, stake) in height_votes {
            if stake >= threshold && height > new_finalized_height {
                new_finalized_height = height;
            }
        }

        // Update finalized height if we found a new one
        if new_finalized_height > self.finalization.finalized_height {
            info!("Finalizing blocks up to height {}", new_finalized_height);
            self.finalization.finalized_height = new_finalized_height;
        }
    }

    /// Cleanup old votes periodically to prevent memory bloat
    fn cleanup_old_votes(&mut self, current_height: u64) {
        self.finalization.votes.retain(|_, vote| {
            if let ValidatorVote::Finalize(height) = vote {
                *height > self.finalization.finalized_height
            } else {
                true
            }
        });

        // Cleanup old last vote heights
        self.finalization.last_vote_height.retain(|_, height| {
            *height > current_height - 1000 // Keep last 1000 blocks of voting history
        });

        self.finalization.last_cleanup_height = current_height;
    }

    /// Get the current voting status for a specific height
    pub fn get_voting_status(&self, height: u64) -> (u64, u64) {
        let total_stake: u64 = self.stakers.values()
            .map(|s| s.stake_amount)
            .sum();

        let voted_stake: u64 = self.finalization.votes
            .iter()
            .filter_map(|(validator, vote)| {
                if let ValidatorVote::Finalize(h) = vote {
                    if *h >= height {
                        self.stakers.get(validator).map(|s| s.stake_amount)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .sum();

        (voted_stake, total_stake)
    }

    /// Check if a block height is safe to build on
    pub fn is_safe_to_build_on(&self, height: u64, current_height: u64) -> bool {
        // Don't build on finalized blocks
        if height <= self.finalization.finalized_height {
            return false;
        }

        // Don't build too far ahead
        if height > current_height + 100 {
            return false;
        }

        true
    }

    /// Get the current finalized height
    pub fn get_finalized_height(&self) -> u64 {
        self.finalization.finalized_height
    }

    /// Check if a given height is finalized
    pub fn is_height_finalized(&self, height: u64) -> bool {
        height <= self.finalization.finalized_height
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