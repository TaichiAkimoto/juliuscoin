pub mod types;
pub mod validator;
pub mod rewards;
pub mod withdrawal;
pub mod finalization;

pub use types::{
    Staker, WithdrawalRequest, StakingInfo,
    ValidatorVote, EpochInfo, FinalizationState
};
pub use validator::ValidatorOperations;
pub use rewards::RewardsDistributor;
pub use withdrawal::WithdrawalProcessor;
pub use finalization::{FinalizationProcessor, EpochManager};

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use vrf::openssl::{ECVRF, CipherSuite};
use log::{info, warn};
use crate::blockchain::consensus::delegation::DelegationState;
use crate::blockchain::consensus::vdf::{VDFProof, SimpleVDF, WesolowskiVDF};
use crate::blockchain::consensus::slashing::{
    SlashingReason, SlashingRecord, ValidatorParticipation,
    OFFLINE_WARNING_THRESHOLD, OFFLINE_MINOR_THRESHOLD,
    OFFLINE_MAJOR_THRESHOLD, WARNING_COOLDOWN_BLOCKS,
};
use anyhow::Result as AnyhowResult;

/// Enhanced structure for tracking transferred keys to prevent long-range attacks
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct TransferredKeys {
    /// Maps public key to the block height when it was transferred
    transferred: HashMap<Vec<u8>, u64>,
    /// Maps public key to its transfer history for additional security
    transfer_history: HashMap<Vec<u8>, Vec<(u64, Vec<u8>)>>, // (height, new_owner)
}

impl TransferredKeys {
    pub fn new() -> Self {
        Self {
            transferred: HashMap::new(),
            transfer_history: HashMap::new(),
        }
    }

    /// Records a key transfer with the new owner for better tracking
    pub fn record_transfer(&mut self, key: Vec<u8>, new_owner: Vec<u8>, height: u64) {
        self.transferred.insert(key.clone(), height);
        self.transfer_history
            .entry(key)
            .or_default()
            .push((height, new_owner));
    }

    /// Checks if a key is valid for signing at a specific height
    pub fn is_valid_at_height(&self, key: &[u8], height: u64) -> bool {
        match self.transferred.get(key) {
            Some(transfer_height) => height < *transfer_height,
            None => true,
        }
    }

    /// Gets the complete transfer history of a key
    pub fn get_transfer_history(&self, key: &[u8]) -> Option<&Vec<(u64, Vec<u8>)>> {
        self.transfer_history.get(key)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PoSState {
    pub stakers: HashMap<Vec<u8>, Staker>,
    #[serde(skip)]
    pub vrf: Option<ECVRF>,
    pub slashing_records: Vec<crate::blockchain::consensus::slashing::SlashingRecord>,
    pub last_checkpoint_height: u64,
    pub checkpoint_interval: u64,
    pub minimum_stake: u64,
    pub base_reward_rate: u64,  // Rewards per 1000 blocks, in basis points (1/100 of 1%)
    pub finalization: FinalizationState,
    pub proposals_per_height: HashMap<u64, HashMap<Vec<u8>, Vec<u8>>>, // height => (staker => block_hash)
    pub votes_per_height: HashMap<u64, HashMap<Vec<u8>, Vec<u8>>>, // height => (staker => block_hash)
    pub transferred_keys: TransferredKeys,
    pub use_vdf: bool,
    pub vdf_iterations: u64,
    pub delegation: DelegationState,
    pub validator_participation: HashMap<Vec<u8>, ValidatorParticipation>,
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
            validator_participation: self.validator_participation.clone(),
        }
    }
}

impl PoSState {
    pub fn new() -> AnyhowResult<Self> {
        let vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)
            .map_err(|e| anyhow::anyhow!("Failed to initialize VRF: {}", e))?;
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
            transferred_keys: TransferredKeys::new(),
            use_vdf: false,
            vdf_iterations: 1000,
            delegation: DelegationState::new(10000), // Minimum pool stake of 10000
            validator_participation: HashMap::new(),
        })
    }

    pub fn create_checkpoint(&mut self, height: u64) {
        self.track_validator_participation(height);
        self.last_checkpoint_height = height;
    }

    pub fn should_create_checkpoint(&self, height: u64) -> bool {
        height > self.last_checkpoint_height + self.checkpoint_interval
    }

    pub fn initialize_vrf(&mut self) -> AnyhowResult<()> {
        if self.vrf.is_none() {
            self.vrf = Some(ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)
                .map_err(|e| anyhow::anyhow!("Failed to initialize VRF: {}", e))?);
        }
        Ok(())
    }

    pub fn generate_vdf_proof(&self, input: &[u8]) -> AnyhowResult<VDFProof> {
        if !self.use_vdf {
            return Err(anyhow::anyhow!("VDF is not enabled"));
        }

        let vdf = SimpleVDF::new(self.vdf_iterations);
        let proof = vdf.generate(input);
        
        Ok(proof)
    }

    pub fn verify_vdf_proof(&self, proof: &VDFProof) -> bool {
        if !self.use_vdf {
            return false;
        }

        let vdf = SimpleVDF::new(self.vdf_iterations);
        vdf.verify(proof)
    }

    // Track validator participation at each checkpoint
    fn track_validator_participation(&mut self, height: u64) {
        // Collect active validators first to avoid borrow conflicts
        let active_validators = self.get_active_validators();
        
        // Track participation for each validator
        for validator_addr in active_validators {
            // Check participation before modifying any state
            let has_participated = self.has_validator_participated(&validator_addr, height);
            
            // Now update participation record
            let participation = self.validator_participation
                .entry(validator_addr.clone())
                .or_insert_with(ValidatorParticipation::new);

            if has_participated {
                participation.record_activity(height);
            } else {
                participation.record_missed_checkpoint();
                
                let missed = participation.consecutive_missed_checkpoints;
                let should_warn = missed >= OFFLINE_WARNING_THRESHOLD;
                let should_slash_minor = missed >= OFFLINE_MINOR_THRESHOLD;
                let should_slash_major = missed >= OFFLINE_MAJOR_THRESHOLD;
                
                // Store warning state if needed
                let mut issue_warning = false;
                if should_warn {
                    if let Some(last_warning) = participation.last_warning_height {
                        if height >= last_warning + WARNING_COOLDOWN_BLOCKS {
                            issue_warning = true;
                            participation.last_warning_height = Some(height);
                        }
                    } else {
                        issue_warning = true;
                        participation.last_warning_height = Some(height);
                    }
                }
                
                // Handle slashing and warnings
                if should_slash_major {
                    // Clone validator_addr to avoid borrow issues
                    let addr_clone = validator_addr.clone();
                    self.slash_staker(&addr_clone, SlashingReason::OfflineMajor, height);
                } else if should_slash_minor {
                    // Clone validator_addr to avoid borrow issues
                    let addr_clone = validator_addr.clone();
                    self.slash_staker(&addr_clone, SlashingReason::OfflineMinor, height);
                } else if issue_warning {
                    // Issue warning outside of mutable borrow
                    self.issue_offline_warning(&validator_addr, height);
                }
            }
        }
    }

    // Check if validator has participated since last checkpoint
    fn has_validator_participated(&self, validator_addr: &[u8], current_height: u64) -> bool {
        let last_checkpoint = self.last_checkpoint_height;
        
        // Check for proposals
        if let Some(proposals) = self.proposals_per_height.get(&current_height) {
            if proposals.contains_key(validator_addr) {
                return true;
            }
        }
        
        // Check for votes
        if let Some(votes) = self.votes_per_height.get(&current_height) {
            if votes.contains_key(validator_addr) {
                return true;
            }
        }
        
        false
    }

    // Issue warning for offline validator
    fn issue_offline_warning(&self, validator_addr: &[u8], height: u64) {
        if let Some(staker) = self.stakers.get(validator_addr) {
            warn!(
                "Validator {} has been offline for {} consecutive checkpoints at height {}",
                hex::encode(validator_addr),
                OFFLINE_WARNING_THRESHOLD,
                height
            );
        }
    }

    /// Enhanced key transfer recording with new owner tracking
    fn record_key_transfer(&mut self, public_key: &[u8], new_owner: &[u8], transfer_height: u64) {
        self.transferred_keys.record_transfer(
            public_key.to_vec(),
            new_owner.to_vec(),
            transfer_height
        );
    }

    /// Enhanced validation for key usage at specific heights
    fn is_key_allowed_to_stake(&self, public_key: &[u8], current_height: u64) -> bool {
        self.transferred_keys.is_valid_at_height(public_key, current_height)
    }

    /// Process a stake transfer between validators
    pub fn process_stake_transfer(
        &mut self,
        from_key: &[u8],
        to_key: &[u8],
        amount: u64,
        current_height: u64
    ) -> Result<(), String> {
        // Verify the source key hasn't been transferred
        if !self.is_key_allowed_to_stake(from_key, current_height) {
            return Err("Source key is not valid for staking at this height".to_string());
        }

        // Process the stake transfer
        if let Some(from_staker) = self.stakers.get_mut(from_key) {
            if from_staker.stake_amount < amount {
                return Err("Insufficient stake amount".to_string());
            }

            // Update stake amounts
            from_staker.stake_amount -= amount;
            self.stakers
                .entry(to_key.to_vec())
                .or_insert_with(|| Staker::new(0))
                .stake_amount += amount;

            // Record the key transfer
            self.record_key_transfer(from_key, to_key, current_height);

            Ok(())
        } else {
            Err("Source staker not found".to_string())
        }
    }

    /// Validate block signatures with enhanced key transfer checks
    pub fn validate_block_signatures(&self, block_height: u64, signatures: &[(Vec<u8>, Vec<u8>)]) -> Result<(), String> {
        for (key, _signature) in signatures {
            if !self.transferred_keys.is_valid_at_height(key, block_height) {
                return Err(format!(
                    "Invalid signature: key was transferred before height {}",
                    block_height
                ));
            }
        }
        Ok(())
    }
}

impl ValidatorOperations for PoSState {
    fn is_validator(&self, address_hash: &[u8]) -> bool {
        if let Some(staker) = self.stakers.get(address_hash) {
            staker.stake_amount >= self.minimum_stake
        } else {
            false
        }
    }

    fn get_active_validators(&self) -> Vec<Vec<u8>> {
        self.stakers
            .iter()
            .filter(|(_, staker)| staker.stake_amount >= self.minimum_stake)
            .map(|(addr, _)| addr.clone())
            .collect()
    }

    fn get_stake_amount(&self, address_hash: &[u8]) -> u64 {
        self.stakers
            .get(address_hash)
            .map(|staker| staker.stake_amount)
            .unwrap_or(0)
    }

    fn get_staking_info(&self, address_hash: &[u8]) -> Option<StakingInfo> {
        self.stakers.get(address_hash).map(|staker| StakingInfo {
            current_stake: staker.stake_amount,
            pending_withdrawals: staker.pending_withdrawals.clone(),
            total_pending_withdrawals: staker.pending_withdrawals.iter().map(|w| w.amount).sum(),
            accumulated_rewards: staker.accumulated_rewards,
            last_active_time: staker.last_active_time,
            slashing_records: staker.slashing_records.clone(),
        })
    }

    fn stake(&mut self, address: Vec<u8>, amount: u64, public_key: Vec<u8>) -> Result<(), String> {
        if amount < self.minimum_stake {
            return Err(format!("Stake amount must be at least {}", self.minimum_stake));
        }

        if !self.is_key_allowed_to_stake(&public_key, 0) {
            return Err("Public key is not allowed to stake yet".to_string());
        }

        let staker = Staker {
            address_hash: address.clone(),
            stake_amount: amount,
            public_key,
            secret_key: Vec::new(), // This should be set by the caller
            last_proposal_height: None,
            last_active_time: 0,
            slashing_records: Vec::new(),
            pending_withdrawals: Vec::new(),
            accumulated_rewards: 0,
        };

        self.stakers.insert(address, staker);
        Ok(())
    }

    fn update_last_active_time(&mut self, address_hash: &[u8]) -> Result<(), String> {
        if let Some(staker) = self.stakers.get_mut(address_hash) {
            staker.last_active_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(())
        } else {
            Err("Staker not found".to_string())
        }
    }

    fn get_total_stake(&self) -> u64 {
        self.stakers.values().map(|s| s.stake_amount).sum()
    }

    fn get_validator_stake(&self, address: &[u8]) -> u64 {
        self.stakers
            .get(address)
            .map(|s| s.stake_amount)
            .unwrap_or(0)
    }

    fn was_staker_at_height(&self, address: &[u8], height: u64) -> bool {
        if let Some(staker) = self.stakers.get(address) {
            match staker.last_proposal_height {
                Some(last_height) => last_height <= height,
                None => false,
            }
        } else {
            false
        }
    }

    fn slash_staker(&mut self, staker_address: &[u8], reason: SlashingReason, block_height: u64) {
        // First get the stake amount and check if we need to slash
        let (should_cleanup, penalty_amount) = if let Some(staker) = self.stakers.get(staker_address) {
            let penalty_amount = SlashingRecord::calculate_penalty(&reason, staker.stake_amount);
            let new_stake = staker.stake_amount.saturating_sub(penalty_amount);
            (new_stake < self.minimum_stake, penalty_amount)
        } else {
            return;
        };

        // Now update the staker's state
        if let Some(staker) = self.stakers.get_mut(staker_address) {
            let record = SlashingRecord::new(
                staker_address.to_vec(),
                reason.clone(),
                block_height,
                penalty_amount,
            );

            staker.stake_amount = staker.stake_amount.saturating_sub(penalty_amount);
            staker.slashing_records.push(record.clone());
            self.slashing_records.push(record);

            // Reset participation tracking after slashing
            if let Some(participation) = self.validator_participation.get_mut(staker_address) {
                participation.consecutive_missed_checkpoints = 0;
            }

            if should_cleanup {
                staker.stake_amount = 0;
            }
        }

        // If we need to cleanup, do it after all other operations
        if should_cleanup {
            self.cleanup_slashed_validators(block_height);
        }

        info!(
            "Slashed validator {} for reason {:?}. Penalty amount: {}, Remaining stake: {}",
            hex::encode(staker_address),
            reason,
            penalty_amount,
            self.stakers.get(staker_address).map(|s| s.stake_amount).unwrap_or(0)
        );
    }

    fn cleanup_slashed_validators(&mut self, current_height: u64) {
        let addresses_to_remove: Vec<_> = self.stakers
            .iter()
            .filter(|(_, staker)| {
                staker.stake_amount == 0 && !staker.slashing_records.is_empty()
            })
            .map(|(addr, _)| addr.clone())
            .collect();

        for address in addresses_to_remove {
            if let Some(staker) = self.stakers.remove(&address) {
                if staker.accumulated_rewards > 0 {
                    let withdrawal = WithdrawalRequest {
                        amount: staker.accumulated_rewards,
                        request_height: current_height,
                        unlock_height: current_height + 100,
                    };
                    
                    self.stakers.insert(address.clone(), Staker {
                        address_hash: address,
                        stake_amount: 0,
                        public_key: staker.public_key,
                        secret_key: staker.secret_key,
                        last_proposal_height: None,
                        last_active_time: 0,
                        slashing_records: Vec::new(),
                        pending_withdrawals: vec![withdrawal],
                        accumulated_rewards: 0,
                    });
                }
            }
        }
    }

    fn record_proposal(&mut self, block_height: u64, staker_addr: &[u8], block_hash: &[u8]) {
        if let Some(staker) = self.stakers.get_mut(staker_addr) {
            staker.last_proposal_height = Some(block_height);
        }
        
        self.proposals_per_height
            .entry(block_height)
            .or_insert_with(HashMap::new)
            .insert(staker_addr.to_vec(), block_hash.to_vec());
    }

    fn record_vote(&mut self, block_height: u64, staker_addr: &[u8], block_hash: &[u8]) {
        self.votes_per_height
            .entry(block_height)
            .or_insert_with(HashMap::new)
            .insert(staker_addr.to_vec(), block_hash.to_vec());
    }

    fn record_key_transfer(&mut self, public_key: &[u8], transfer_height: u64) {
        self.transferred_keys.record_transfer(public_key.to_vec(), Vec::new(), transfer_height);
    }

    fn is_key_allowed_to_stake(&self, public_key: &[u8], current_height: u64) -> bool {
        self.transferred_keys.is_valid_at_height(public_key, current_height)
    }
}

impl RewardsDistributor for PoSState {
    fn distribute_rewards(&mut self, current_height: u64) {
        let total_stake = self.get_total_stake();
        if total_stake == 0 {
            return;
        }

        let base_reward_rate = self.base_reward_rate;

        for staker in self.stakers.values_mut() {
            if staker.stake_amount >= self.minimum_stake {
                let blocks_participated = current_height - staker.last_active_time;
                let base_reward = (staker.stake_amount * base_reward_rate) / 10_000;
                let reward = (base_reward * blocks_participated) / 1000;
                staker.accumulated_rewards += reward;
                staker.last_active_time = current_height;
            }
        }
    }

    fn get_base_reward_rate(&self) -> u64 {
        self.base_reward_rate
    }

    fn set_base_reward_rate(&mut self, rate: u64) {
        self.base_reward_rate = rate;
    }

    fn get_accumulated_rewards(&self, address_hash: &[u8]) -> u64 {
        self.stakers
            .get(address_hash)
            .map(|s| s.accumulated_rewards)
            .unwrap_or(0)
    }

    fn calculate_reward(&self, stake_amount: u64, blocks_participated: u64) -> u64 {
        let base_reward = (stake_amount * self.base_reward_rate) / 10_000; // Convert basis points to percentage
        (base_reward * blocks_participated) / 1000 // Scale by blocks participated
    }
}

impl WithdrawalProcessor for PoSState {
    fn process_withdrawals(&mut self, current_height: u64) -> Vec<(Vec<u8>, u64)> {
        let mut processed_withdrawals = Vec::new();

        for (address, staker) in self.stakers.iter_mut() {
            let (to_process, to_keep): (Vec<_>, Vec<_>) = staker
                .pending_withdrawals
                .iter()
                .cloned()
                .partition(|w| w.unlock_height <= current_height);

            let total_amount: u64 = to_process.iter().map(|w| w.amount).sum();
            if total_amount > 0 {
                processed_withdrawals.push((address.clone(), total_amount));
            }

            staker.pending_withdrawals = to_keep;
        }

        processed_withdrawals
    }

    fn request_unstake(&mut self, staker_hash: &[u8], amount: u64, current_height: u64) -> Result<(), String> {
        if let Some(staker) = self.stakers.get_mut(staker_hash) {
            if amount > staker.stake_amount {
                return Err("Insufficient stake amount".to_string());
            }

            let withdrawal = WithdrawalRequest {
                amount,
                request_height: current_height,
                unlock_height: current_height + 100, // 100 block lockup period
            };

            staker.stake_amount -= amount;
            staker.pending_withdrawals.push(withdrawal);
            Ok(())
        } else {
            Err("Staker not found".to_string())
        }
    }

    fn get_pending_withdrawals(&self, staker_hash: &[u8]) -> Vec<WithdrawalRequest> {
        self.stakers
            .get(staker_hash)
            .map(|s| s.pending_withdrawals.clone())
            .unwrap_or_default()
    }

    fn get_total_pending_withdrawals(&self, staker_hash: &[u8]) -> u64 {
        self.stakers
            .get(staker_hash)
            .map(|s| s.pending_withdrawals.iter().map(|w| w.amount).sum())
            .unwrap_or(0)
    }

    fn validate_withdrawal_request(&self, staker_hash: &[u8], amount: u64) -> Result<(), String> {
        if let Some(staker) = self.stakers.get(staker_hash) {
            if amount > staker.stake_amount {
                Err("Insufficient stake amount".to_string())
            } else {
                Ok(())
            }
        } else {
            Err("Staker not found".to_string())
        }
    }
}

impl FinalizationProcessor for PoSState {
    fn submit_finalization_vote(&mut self, validator_address: &[u8], vote_height: u64, current_height: u64) -> Result<(), String> {
        if !self.is_validator(validator_address) {
            return Err("Not a validator".to_string());
        }

        let epoch = vote_height / self.finalization.epoch_length;
        let vote = ValidatorVote::Finalize(vote_height);
        let validator_stake = self.get_validator_stake(validator_address);
        
        self.finalization.votes.insert(validator_address.to_vec(), vote.clone());
        self.finalization.last_vote_height.insert(validator_address.to_vec(), current_height);
        
        if let Some(epoch_info) = self.finalization.epochs.get_mut(&epoch) {
            epoch_info.votes.insert(validator_address.to_vec(), vote);
            epoch_info.total_stake_voted += validator_stake;
        }

        Ok(())
    }

    fn try_justify_and_finalize(&mut self, current_height: u64) {
        let current_epoch = current_height / self.finalization.epoch_length;
        let total_stake = self.get_total_stake();
        
        // Try to justify epochs
        for epoch_num in 0..=current_epoch {
            if let Some(epoch_info) = self.finalization.epochs.get_mut(&epoch_num) {
                if epoch_info.total_stake_voted * 3 >= total_stake * 2 { // 2/3 majority
                    epoch_info.is_justified = true;
                }
            }
        }

        // Try to finalize epochs
        for epoch_num in 0..=current_epoch.saturating_sub(self.finalization.finality_delay) {
            if self.is_epoch_justified(epoch_num) && self.is_epoch_justified(epoch_num + 1) {
                if let Some(epoch_info) = self.finalization.epochs.get_mut(&epoch_num) {
                    epoch_info.is_finalized = true;
                    self.finalization.finalized_height = epoch_info.end_height;
                }
            }
        }
    }

    fn cleanup_old_votes(&mut self, current_height: u64) {
        let current_epoch = current_height / self.finalization.epoch_length;
        let cleanup_threshold = current_epoch.saturating_sub(3); // Keep last 3 epochs

        self.finalization.epochs.retain(|&epoch, _| epoch >= cleanup_threshold);
        self.finalization.last_cleanup_height = current_height;
    }

    fn get_voting_status(&self, height: u64) -> (u64, u64) {
        let epoch = height / self.finalization.epoch_length;
        let total_stake = self.get_total_stake();
        let voted_stake = self.finalization.epochs
            .get(&epoch)
            .map(|e| e.total_stake_voted)
            .unwrap_or(0);
        
        (voted_stake, (total_stake * 2) / 3) // Return (votes_received, votes_needed)
    }

    fn is_safe_to_build_on(&self, height: u64, current_height: u64) -> bool {
        if height > current_height {
            return false;
        }

        let epoch = height / self.finalization.epoch_length;
        self.is_epoch_justified(epoch)
    }

    fn get_finalized_height(&self) -> u64 {
        self.finalization.finalized_height
    }

    fn is_height_finalized(&self, height: u64) -> bool {
        height <= self.finalization.finalized_height
    }

    fn get_epoch_length(&self) -> u64 {
        self.finalization.epoch_length
    }

    fn is_epoch_justified(&self, epoch_num: u64) -> bool {
        self.finalization.epochs
            .get(&epoch_num)
            .map(|e| e.is_justified)
            .unwrap_or(false)
    }

    fn is_epoch_finalized(&self, epoch_num: u64) -> bool {
        self.finalization.epochs
            .get(&epoch_num)
            .map(|e| e.is_finalized)
            .unwrap_or(false)
    }
}

impl EpochManager for PoSState {
    fn create_epoch(&mut self, epoch_number: u64, start_height: u64, end_height: u64) {
        let epoch_info = EpochInfo {
            epoch_number,
            start_height,
            end_height,
            is_justified: false,
            is_finalized: false,
            total_stake_voted: 0,
            votes: HashMap::new(),
        };
        self.finalization.epochs.insert(epoch_number, epoch_info);
    }

    fn get_epoch_info(&self, epoch_number: u64) -> Option<&EpochInfo> {
        self.finalization.epochs.get(&epoch_number)
    }

    fn get_current_epoch(&self) -> u64 {
        self.finalization.current_epoch
    }

    fn get_epoch_for_height(&self, height: u64) -> u64 {
        height / self.finalization.epoch_length
    }

    fn justify_epoch(&mut self, epoch_number: u64) {
        if let Some(epoch_info) = self.finalization.epochs.get_mut(&epoch_number) {
            epoch_info.is_justified = true;
        }
    }

    fn finalize_epoch(&mut self, epoch_number: u64) {
        if let Some(epoch_info) = self.finalization.epochs.get_mut(&epoch_number) {
            epoch_info.is_finalized = true;
            self.finalization.finalized_height = epoch_info.end_height;
        }
    }
}
