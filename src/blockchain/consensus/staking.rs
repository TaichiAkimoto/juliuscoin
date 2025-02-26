use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use vrf::openssl::{ECVRF, CipherSuite, Error as VRFError};
use crate::blockchain::consensus::slashing::{SlashingReason, SlashingRecord};
use crate::blockchain::consensus::vdf::{VDFProof, SimpleVDF, WesolowskiVDF};
use log::info;
use crate::blockchain::consensus::delegation::{DelegationState, StakingPool};
use anyhow::Result as AnyhowResult;

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
    pub votes: HashMap<Vec<u8>, ValidatorVote>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FinalizationState {
    pub finalized_height: u64,
    pub current_epoch: u64,
    pub epoch_length: u64,
    pub epochs: HashMap<u64, EpochInfo>,
    pub votes: HashMap<Vec<u8>, ValidatorVote>,
    pub last_vote_height: HashMap<Vec<u8>, u64>,
    pub last_cleanup_height: u64,
    pub finality_delay: u64,  // Number of epochs required between justification and finalization
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
    // Track proposals and votes per height for slashing
    pub proposals_per_height: HashMap<u64, HashMap<Vec<u8>, Vec<u8>>>, // height => (staker => block_hash)
    pub votes_per_height: HashMap<u64, HashMap<Vec<u8>, Vec<u8>>>, // height => (staker => block_hash)
    pub transferred_keys: HashMap<Vec<u8>, u64>, // public_key => transfer_height
    // New fields for VDF-based randomness
    pub use_vdf: bool,
    pub vdf_iterations: u64,
    pub delegation: DelegationState,  // New field for delegation system
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
            proposals_per_height: self.proposals_per_height.clone(),
            votes_per_height: self.votes_per_height.clone(),
            transferred_keys: self.transferred_keys.clone(),
            use_vdf: self.use_vdf,
            vdf_iterations: self.vdf_iterations,
            delegation: self.delegation.clone(),
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
                current_epoch: 0,
                epoch_length: 100, // 100 blocks per epoch
                epochs: HashMap::new(),
                votes: HashMap::new(),
                last_vote_height: HashMap::new(),
                last_cleanup_height: 0,
                finality_delay: 2,  // Require 2 epochs between justification and finalization
            },
            proposals_per_height: HashMap::new(),
            votes_per_height: HashMap::new(),
            transferred_keys: HashMap::new(),
            // Default: VDF is disabled; set iterations to 1000 if enabled
            use_vdf: false,
            vdf_iterations: 1000,
            delegation: DelegationState::new(10000), // Minimum pool stake of 10000
        })
    }

    /// Generate a VDF proof for the given input
    /// 
    /// # Arguments
    /// * `input` - The input challenge to the VDF
    /// 
    /// # Returns
    /// * `Result<VDFProof>` - The VDF proof if successful
    pub fn generate_vdf_proof(&self, input: &[u8]) -> AnyhowResult<VDFProof> {
        if !self.use_vdf {
            return Err(anyhow::anyhow!("VDF is not enabled"));
        }

        // Use the simple VDF implementation for now
        // In production, you might want to use the Wesolowski VDF
        let vdf = SimpleVDF::new(self.vdf_iterations);
        let proof = vdf.generate(input);
        
        Ok(proof)
    }

    /// Verify a VDF proof
    /// 
    /// # Arguments
    /// * `proof` - The VDF proof to verify
    /// 
    /// # Returns
    /// * `bool` - True if the proof is valid
    pub fn verify_vdf_proof(&self, proof: &VDFProof) -> bool {
        if !self.use_vdf {
            return false;
        }

        // Use the simple VDF implementation for verification
        let vdf = SimpleVDF::new(self.vdf_iterations);
        vdf.verify(proof)
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

            // Apply the penalty
            staker.stake_amount = staker.stake_amount.saturating_sub(penalty_amount);
            
            // Record the slashing event
            staker.slashing_records.push(record.clone());
            self.slashing_records.push(record);

            // For severe violations, remove from active validator set
            match reason {
                SlashingReason::DoubleProposal | SlashingReason::DoubleVoting => {
                    // Remove all stake for severe violations
                    staker.stake_amount = 0;
                }
                SlashingReason::Offline => {
                    // For offline violations, if stake drops below minimum, remove completely
                    if staker.stake_amount < self.minimum_stake {
                        staker.stake_amount = 0;
                    }
                }
            }

            // If no stake left, queue for removal
            if staker.stake_amount == 0 {
                // The staker will be removed in the next cleanup cycle
                staker.last_active_time = 0;
            }
        }
    }

    pub fn cleanup_slashed_validators(&mut self, current_height: u64) {
        // Collect addresses to remove
        let addresses_to_remove: Vec<_> = self.stakers
            .iter()
            .filter(|(_, staker)| {
                // Remove if stake is 0 and has slashing records
                staker.stake_amount == 0 && !staker.slashing_records.is_empty()
            })
            .map(|(addr, _)| addr.clone())
            .collect();

        // Process removals
        for address in addresses_to_remove {
            if let Some(staker) = self.stakers.remove(&address) {
                // Create withdrawal request for any remaining rewards
                if staker.accumulated_rewards > 0 {
                    let withdrawal = WithdrawalRequest {
                        amount: staker.accumulated_rewards,
                        request_height: current_height,
                        unlock_height: current_height + 100, // Standard unlock period
                    };
                    
                    // Re-insert staker with only the withdrawal request
                    self.stakers.insert(address.clone(), Staker {
                        address_hash: address,
                        stake_amount: 0,
                        public_key: staker.public_key,
                        secret_key: vec![],
                        last_proposal_height: None,
                        last_active_time: 0,
                        slashing_records: staker.slashing_records,
                        pending_withdrawals: vec![withdrawal],
                        accumulated_rewards: 0,
                    });
                }
            }
        }
    }

    pub fn process_slashing_records(&mut self, current_height: u64) {
        // Process any pending slashing records
        let records_to_process: Vec<_> = self.slashing_records
            .iter()
            .filter(|record| record.block_height + 100 <= current_height) // Wait 100 blocks before finalizing
            .cloned()
            .collect();

        for record in records_to_process {
            if let Some(staker) = self.stakers.get_mut(&record.staker_address) {
                // Remove the record from pending
                self.slashing_records.retain(|r| r.block_height != record.block_height);
                
                // If stake is 0 and no pending withdrawals, mark for cleanup
                if staker.stake_amount == 0 && staker.pending_withdrawals.is_empty() {
                    staker.last_active_time = 0;
                }
            }
        }

        // Run cleanup
        self.cleanup_slashed_validators(current_height);
    }

    pub fn create_checkpoint(&mut self, block_height: u64) -> bool {
        if block_height - self.last_checkpoint_height >= self.checkpoint_interval {
            self.last_checkpoint_height = block_height;
            
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            // Enhanced offline detection parameters
            let offline_threshold = 24 * 60 * 60; // 24 hours
            let missed_blocks_threshold = 100; // Number of consecutive blocks missed before slashing
            
            // Collect addresses that need slashing
            let addresses_to_slash: Vec<_> = self.stakers
                .iter()
                .filter(|(_, staker)| {
                    // Check both time-based and block-based inactivity
                    let time_inactive = current_time - staker.last_active_time > offline_threshold;
                    
                    // Check if staker has missed too many consecutive blocks
                    let missed_blocks = if let Some(last_height) = staker.last_proposal_height {
                        block_height - last_height
                    } else {
                        block_height // If never proposed, count from start
                    };
                    
                    let blocks_missed = missed_blocks > missed_blocks_threshold;
                    
                    // Only slash if both conditions are met to avoid false positives
                    time_inactive && blocks_missed
                })
                .map(|(addr, _)| addr.clone())
                .collect();
            
            // Then perform slashing with appropriate penalties
            for address in addresses_to_slash {
                self.slash_staker(
                    &address,
                    SlashingReason::Offline,
                    block_height,
                );
            }

            // Process any pending slashing records
            self.process_slashing_records(block_height);
            
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
        let mut total_stake = 0u64;
        let mut active_validators = Vec::new();

        // Calculate total stake including pool stakes
        for staker in self.stakers.values() {
            if staker.stake_amount >= self.minimum_stake {
                total_stake += staker.stake_amount;
                active_validators.push(staker.address_hash.clone());
            }
        }

        // Collect pool data first
        let active_pools: Vec<(Vec<u8>, u64)> = self.delegation.get_active_pools()
            .into_iter()
            .filter(|pool| pool.total_stake >= self.minimum_stake)
            .map(|pool| (pool.pool_address.clone(), pool.total_stake))
            .collect();

        // Add pool stakes to total
        for (pool_address, stake) in &active_pools {
            total_stake += stake;
            active_validators.push(pool_address.clone());
        }

        if total_stake == 0 || active_validators.is_empty() {
            return;
        }

        // Calculate base reward for this distribution
        let blocks_since_last = current_height.saturating_sub(self.last_checkpoint_height);
        let base_reward = (blocks_since_last as u128 * self.base_reward_rate as u128 / 1000) as u64;

        // Distribute rewards to individual stakers
        for staker in self.stakers.values_mut() {
            if staker.stake_amount >= self.minimum_stake {
                let reward = (base_reward as u128 * staker.stake_amount as u128 / total_stake as u128) as u64;
                staker.accumulated_rewards = staker.accumulated_rewards.saturating_add(reward);
            }
        }

        // Calculate and distribute rewards to pools
        for (pool_address, stake) in active_pools {
            let reward = (base_reward as u128 * stake as u128 / total_stake as u128) as u64;
            if let Err(e) = self.delegation.distribute_pool_rewards(&pool_address, reward) {
                info!("Failed to distribute rewards to pool: {}", e);
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
        // Check individual validators
        if let Some(staker) = self.stakers.get(address_hash) {
            return staker.stake_amount >= self.minimum_stake;
        }

        // Check staking pools
        if let Some(pool) = self.delegation.get_pool_info(address_hash) {
            return pool.total_stake >= self.minimum_stake;
        }

        false
    }

    /// Gets all active validators
    pub fn get_active_validators(&self) -> Vec<Vec<u8>> {
        let mut validators = Vec::new();

        // Add individual validators
        for staker in self.stakers.values() {
            if staker.stake_amount >= self.minimum_stake {
                validators.push(staker.address_hash.clone());
            }
        }

        // Add pool validators
        for pool in self.delegation.get_active_pools() {
            if pool.total_stake >= self.minimum_stake {
                validators.push(pool.pool_address.clone());
            }
        }

        validators
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

        // Calculate epoch number for the vote height
        let epoch = vote_height / self.finalization.epoch_length;
        
        // Get or create epoch info
        let epoch_info = self.finalization.epochs.entry(epoch).or_insert_with(|| EpochInfo {
            epoch_number: epoch,
            start_height: epoch * self.finalization.epoch_length,
            end_height: (epoch + 1) * self.finalization.epoch_length - 1,
            is_justified: false,
            is_finalized: false,
            total_stake_voted: 0,
            votes: HashMap::new(),
        });

        // Record the vote
        if !epoch_info.votes.contains_key(validator_address) {
            epoch_info.total_stake_voted += staker.stake_amount;
        }
        epoch_info.votes.insert(validator_address.to_vec(), ValidatorVote::Justify(vote_height));

        self.finalization.last_vote_height.insert(
            validator_address.to_vec(),
            current_height
        );

        // Try to justify and finalize epochs
        self.try_justify_and_finalize(current_height);

        // Periodically cleanup old votes
        if current_height >= self.finalization.last_cleanup_height + 100 {
            self.cleanup_old_votes(current_height);
        }

        Ok(())
    }

    /// Try to justify and finalize epochs based on validator votes
    fn try_justify_and_finalize(&mut self, current_height: u64) {
        let total_stake: u64 = self.stakers.values()
            .map(|s| s.stake_amount)
            .sum();
        let threshold = (total_stake * 2) / 3; // 2/3 majority required

        // Try to justify epochs
        let current_epoch = current_height / self.finalization.epoch_length;
        for epoch_num in 0..=current_epoch {
            if let Some(epoch_info) = self.finalization.epochs.get_mut(&epoch_num) {
                if !epoch_info.is_justified && epoch_info.total_stake_voted >= threshold {
                    epoch_info.is_justified = true;
                    info!("Epoch {} justified at height {}", epoch_num, current_height);
                }
            }
        }

        // Try to finalize epochs
        let mut last_finalized_epoch = self.finalization.finalized_height / self.finalization.epoch_length;
        
        // First collect epochs that can be finalized
        let mut epochs_to_finalize = Vec::new();
        
        // Iterate through epochs after the last finalized one
        'outer: for epoch_num in (last_finalized_epoch + 1)..=current_epoch {
            if let Some(epoch_info) = self.finalization.epochs.get(&epoch_num) {
                // Check if this epoch can be finalized
                if epoch_info.is_justified {
                    // Check if enough epochs have passed since justification
                    let epochs_since_justification = current_epoch.saturating_sub(epoch_num);
                    if epochs_since_justification >= self.finalization.finality_delay {
                        // Check if all epochs between last finalized and this one are justified
                        for intermediate_epoch in last_finalized_epoch + 1..epoch_num {
                            if let Some(intermediate_info) = self.finalization.epochs.get(&intermediate_epoch) {
                                if !intermediate_info.is_justified {
                                    continue 'outer;
                                }
                            } else {
                                continue 'outer;
                            }
                        }
                        
                        epochs_to_finalize.push((epoch_num, epoch_info.end_height));
                    }
                }
            }
        }

        // Now finalize the collected epochs
        for (epoch_num, end_height) in epochs_to_finalize {
            // Finalize this epoch and all epochs before it
            for e in last_finalized_epoch + 1..=epoch_num {
                if let Some(e_info) = self.finalization.epochs.get_mut(&e) {
                    e_info.is_finalized = true;
                }
            }
            self.finalization.finalized_height = end_height;
            last_finalized_epoch = epoch_num;
            info!("Finalized up to epoch {} (height {})", epoch_num, end_height);
        }
    }

    fn cleanup_old_votes(&mut self, current_height: u64) {
        let current_epoch = current_height / self.finalization.epoch_length;
        
        // Remove epochs that are more than finality_delay + 2 epochs old
        let min_epoch_to_keep = current_epoch.saturating_sub(self.finalization.finality_delay + 2);
        self.finalization.epochs.retain(|&epoch_num, _| {
            epoch_num >= min_epoch_to_keep || epoch_num > self.finalization.finalized_height / self.finalization.epoch_length
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
        // A block is safe to build on if:
        // 1. It's finalized, or
        // 2. It's in a justified epoch and enough time has passed
        
        if height <= self.finalization.finalized_height {
            return true;
        }

        let epoch = height / self.finalization.epoch_length;
        let current_epoch = current_height / self.finalization.epoch_length;

        if let Some(epoch_info) = self.finalization.epochs.get(&epoch) {
            if epoch_info.is_justified {
                // Allow building on justified epochs that are old enough
                return current_epoch >= epoch + self.finalization.finality_delay;
            }
        }

        false
    }

    /// Get the current finalized height
    pub fn get_finalized_height(&self) -> u64 {
        self.finalization.finalized_height
    }

    /// Check if a given height is finalized
    pub fn is_height_finalized(&self, height: u64) -> bool {
        height <= self.finalization.finalized_height
    }

    /// Record a block proposal and check for double proposals
    pub fn record_proposal(&mut self, block_height: u64, staker_addr: &[u8], block_hash: &[u8]) {
        let proposals = self.proposals_per_height.entry(block_height).or_default();
        
        if let Some(previous_hash) = proposals.get(staker_addr) {
            if previous_hash != block_hash {
                // Double proposal detected - slash the staker
                self.slash_staker(
                    staker_addr,
                    SlashingReason::DoubleProposal,
                    block_height,
                );
            }
        } else {
            proposals.insert(staker_addr.to_vec(), block_hash.to_vec());
        }

        // Cleanup old proposals (keep last 1000 blocks)
        if block_height > 1000 {
            self.proposals_per_height.remove(&(block_height - 1000));
        }
    }

    /// Record a vote and check for double voting
    pub fn record_vote(&mut self, block_height: u64, staker_addr: &[u8], block_hash: &[u8]) {
        let votes = self.votes_per_height.entry(block_height).or_default();
        
        if let Some(previous_hash) = votes.get(staker_addr) {
            if previous_hash != block_hash {
                // Double voting detected - slash the staker
                self.slash_staker(
                    staker_addr,
                    SlashingReason::DoubleVoting,
                    block_height,
                );
            }
        } else {
            votes.insert(staker_addr.to_vec(), block_hash.to_vec());
        }

        // Cleanup old votes (keep last 1000 blocks)
        if block_height > 1000 {
            self.votes_per_height.remove(&(block_height - 1000));
        }
    }

    /// Record a key transfer to prevent long-range attacks
    pub fn record_key_transfer(&mut self, public_key: &[u8], transfer_height: u64) {
        self.transferred_keys.insert(public_key.to_vec(), transfer_height);
    }

    /// Check if a key is allowed to stake (not transferred or slashed)
    pub fn is_key_allowed_to_stake(&self, public_key: &[u8], current_height: u64) -> bool {
        if let Some(transfer_height) = self.transferred_keys.get(public_key) {
            // Key was transferred - only allow staking if within safe range
            current_height <= *transfer_height + 10000 // Allow staking within 10000 blocks of transfer
        } else {
            true
        }
    }

    pub fn get_epoch_length(&self) -> u64 {
        self.finalization.epoch_length
    }

    pub fn was_staker_at_height(&self, address: &[u8], height: u64) -> bool {
        // Check if the address was a staker at the given height by looking at historical records
        if let Some(staker) = self.stakers.get(address) {
            // If they have a last_proposal_height before or at the target height, they were a staker
            if let Some(last_proposal) = staker.last_proposal_height {
                return last_proposal <= height;
            }
        }
        false
    }

    pub fn get_total_stake(&self) -> u64 {
        let individual_stake: u64 = self.stakers.values()
            .filter(|s| s.stake_amount >= self.minimum_stake)
            .map(|s| s.stake_amount)
            .sum();

        let pool_stake: u64 = self.delegation.get_active_pools()
            .iter()
            .filter(|p| p.total_stake >= self.minimum_stake)
            .map(|p| p.total_stake)
            .sum();

        individual_stake.saturating_add(pool_stake)
    }

    pub fn get_validator_stake(&self, address: &[u8]) -> u64 {
        // Check individual stake
        if let Some(staker) = self.stakers.get(address) {
            return staker.stake_amount;
        }

        // Check if it's a pool
        if let Some(pool) = self.delegation.get_pool_info(address) {
            return pool.total_stake;
        }

        0
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
