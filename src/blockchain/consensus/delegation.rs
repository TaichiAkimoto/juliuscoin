use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use log::info;

/// Represents a staking pool that allows multiple users to stake together
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StakingPool {
    pub pool_address: Vec<u8>,              // Pool's unique address
    pub operator_address: Vec<u8>,          // Pool operator's address
    pub total_stake: u64,                   // Total stake in the pool
    pub delegations: HashMap<Vec<u8>, u64>, // Delegator address -> stake amount
    pub commission_rate: u32,               // Commission rate in basis points (1/10000)
    pub accumulated_rewards: u64,           // Unclaimed rewards
    pub min_delegation: u64,                // Minimum delegation amount
    pub is_active: bool,                    // Whether the pool is accepting new delegations
}

/// Represents a delegation request to join or leave a pool
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DelegationRequest {
    pub delegator_address: Vec<u8>,
    pub pool_address: Vec<u8>,
    pub amount: u64,
    pub request_type: DelegationRequestType,
    pub request_height: u64,
    pub unlock_height: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum DelegationRequestType {
    Join,
    Leave,
}

/// Manages the delegation and staking pool system
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DelegationState {
    pub pools: HashMap<Vec<u8>, StakingPool>,
    pub pending_requests: Vec<DelegationRequest>,
    pub min_pool_stake: u64,           // Minimum stake required to create a pool
    pub max_commission_rate: u32,      // Maximum allowed commission rate in basis points
    pub unbonding_period: u64,         // Number of blocks for unbonding period
}

impl DelegationState {
    pub fn new(min_pool_stake: u64) -> Self {
        Self {
            pools: HashMap::new(),
            pending_requests: Vec::new(),
            min_pool_stake,
            max_commission_rate: 3000,  // 30% maximum commission
            unbonding_period: 10080,    // ~7 days at 1 block per minute
        }
    }

    /// Create a new staking pool
    pub fn create_pool(
        &mut self,
        pool_address: Vec<u8>,
        operator_address: Vec<u8>,
        initial_stake: u64,
        commission_rate: u32,
        min_delegation: u64,
    ) -> Result<(), String> {
        // Validate parameters
        if initial_stake < self.min_pool_stake {
            return Err(format!("Initial stake must be at least {}", self.min_pool_stake));
        }
        if commission_rate > self.max_commission_rate {
            return Err(format!("Commission rate cannot exceed {}", self.max_commission_rate));
        }
        if self.pools.contains_key(&pool_address) {
            return Err("Pool already exists".to_string());
        }

        let mut delegations = HashMap::new();
        delegations.insert(operator_address.clone(), initial_stake);

        let pool = StakingPool {
            pool_address: pool_address.clone(),
            operator_address,
            total_stake: initial_stake,
            delegations,
            commission_rate,
            accumulated_rewards: 0,
            min_delegation,
            is_active: true,
        };

        self.pools.insert(pool_address, pool);
        Ok(())
    }

    /// Request to delegate tokens to a pool
    pub fn request_delegation(
        &mut self,
        delegator_address: Vec<u8>,
        pool_address: Vec<u8>,
        amount: u64,
        current_height: u64,
    ) -> Result<(), String> {
        let pool = self.pools.get(&pool_address)
            .ok_or("Pool not found")?;

        if !pool.is_active {
            return Err("Pool is not accepting new delegations".to_string());
        }

        if amount < pool.min_delegation {
            return Err(format!("Minimum delegation amount is {}", pool.min_delegation));
        }

        let request = DelegationRequest {
            delegator_address,
            pool_address,
            amount,
            request_type: DelegationRequestType::Join,
            request_height: current_height,
            unlock_height: current_height + 1, // Immediate for joining
        };

        self.pending_requests.push(request);
        Ok(())
    }

    /// Request to undelegate tokens from a pool
    pub fn request_undelegation(
        &mut self,
        delegator_address: Vec<u8>,
        pool_address: Vec<u8>,
        amount: u64,
        current_height: u64,
    ) -> Result<(), String> {
        let pool = self.pools.get(&pool_address)
            .ok_or("Pool not found")?;

        let current_stake = pool.delegations.get(&delegator_address)
            .ok_or("No delegation found for this address")?;

        if amount > *current_stake {
            return Err("Insufficient delegated stake".to_string());
        }

        let request = DelegationRequest {
            delegator_address,
            pool_address,
            amount,
            request_type: DelegationRequestType::Leave,
            request_height: current_height,
            unlock_height: current_height + self.unbonding_period,
        };

        self.pending_requests.push(request);
        Ok(())
    }

    /// Process pending delegation requests
    pub fn process_requests(&mut self, current_height: u64) -> Vec<(Vec<u8>, u64)> {
        let mut completed_requests = Vec::new();
        let mut remaining_requests = Vec::new();

        // First, collect requests that are ready to process
        let requests_to_process: Vec<_> = self.pending_requests
            .iter()
            .filter(|request| current_height >= request.unlock_height)
            .cloned()
            .collect();

        // Process the collected requests
        for request in requests_to_process {
            match self.process_single_request(request.clone()) {
                Ok((address, amount)) => completed_requests.push((address, amount)),
                Err(e) => {
                    info!("Failed to process delegation request: {}", e);
                    remaining_requests.push(request);
                }
            }
        }

        // Keep the requests that are not ready yet
        self.pending_requests = self.pending_requests
            .iter()
            .filter(|request| current_height < request.unlock_height)
            .cloned()
            .collect();

        completed_requests
    }

    fn process_single_request(&mut self, request: DelegationRequest) -> Result<(Vec<u8>, u64), String> {
        let pool = self.pools.get_mut(&request.pool_address)
            .ok_or("Pool not found")?;

        match request.request_type {
            DelegationRequestType::Join => {
                pool.total_stake += request.amount;
                let current_stake = pool.delegations.entry(request.delegator_address.clone())
                    .or_insert(0);
                *current_stake += request.amount;
                Ok((request.delegator_address, 0)) // 0 indicates no payout needed
            },
            DelegationRequestType::Leave => {
                pool.total_stake = pool.total_stake.saturating_sub(request.amount);
                if let Some(stake) = pool.delegations.get_mut(&request.delegator_address) {
                    *stake = stake.saturating_sub(request.amount);
                    if *stake == 0 {
                        pool.delegations.remove(&request.delegator_address);
                    }
                }
                Ok((request.delegator_address, request.amount))
            }
        }
    }

    /// Distribute rewards to a pool
    pub fn distribute_pool_rewards(&mut self, pool_address: &[u8], reward_amount: u64) -> Result<(), String> {
        let pool = self.pools.get_mut(pool_address)
            .ok_or("Pool not found")?;

        if reward_amount == 0 {
            return Ok(());
        }

        // Calculate operator commission
        let commission = (reward_amount as u128 * pool.commission_rate as u128 / 10000) as u64;
        let remaining_reward = reward_amount.saturating_sub(commission);

        // Add commission to operator's share
        if let Some(operator_stake) = pool.delegations.get_mut(&pool.operator_address) {
            *operator_stake = operator_stake.saturating_add(commission);
        }

        // Distribute remaining rewards proportionally
        pool.accumulated_rewards = pool.accumulated_rewards.saturating_add(remaining_reward);
        
        Ok(())
    }

    /// Claim accumulated rewards for a delegator
    pub fn claim_rewards(&mut self, pool_address: &[u8], delegator_address: &[u8]) -> Result<u64, String> {
        let pool = self.pools.get_mut(pool_address)
            .ok_or("Pool not found")?;

        let delegator_stake = pool.delegations.get(delegator_address)
            .ok_or("No delegation found for this address")?;

        if pool.accumulated_rewards == 0 || pool.total_stake == 0 {
            return Ok(0);
        }

        // Calculate delegator's share of rewards
        let reward_share = (pool.accumulated_rewards as u128 * *delegator_stake as u128 / pool.total_stake as u128) as u64;
        pool.accumulated_rewards = pool.accumulated_rewards.saturating_sub(reward_share);

        Ok(reward_share)
    }

    /// Update pool parameters (only by operator)
    pub fn update_pool_params(
        &mut self,
        pool_address: &[u8],
        operator_address: &[u8],
        new_commission_rate: Option<u32>,
        new_min_delegation: Option<u64>,
        is_active: Option<bool>,
    ) -> Result<(), String> {
        let pool = self.pools.get_mut(pool_address)
            .ok_or("Pool not found")?;

        if pool.operator_address != operator_address {
            return Err("Only the pool operator can update parameters".to_string());
        }

        if let Some(rate) = new_commission_rate {
            if rate > self.max_commission_rate {
                return Err(format!("Commission rate cannot exceed {}", self.max_commission_rate));
            }
            pool.commission_rate = rate;
        }

        if let Some(min_delegation) = new_min_delegation {
            pool.min_delegation = min_delegation;
        }

        if let Some(active) = is_active {
            pool.is_active = active;
        }

        Ok(())
    }

    /// Get pool information
    pub fn get_pool_info(&self, pool_address: &[u8]) -> Option<&StakingPool> {
        self.pools.get(pool_address)
    }

    /// Get delegator information in a pool
    pub fn get_delegator_info(&self, pool_address: &[u8], delegator_address: &[u8]) -> Option<u64> {
        self.pools.get(pool_address)
            .and_then(|pool| pool.delegations.get(delegator_address))
            .copied()
    }

    /// Get all active pools
    pub fn get_active_pools(&self) -> Vec<&StakingPool> {
        self.pools.values()
            .filter(|pool| pool.is_active)
            .collect()
    }
} 