use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use vrf::openssl::{ECVRF, CipherSuite, Error as VRFError};
use crate::blockchain::consensus::slashing::{SlashingReason, SlashingRecord};

#[derive(Clone, Serialize, Deserialize)]
pub struct Staker {
    pub address_hash: Vec<u8>,
    pub stake_amount: u64,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub last_proposal_height: Option<u64>,
    pub last_active_time: u64,
    pub slashing_records: Vec<SlashingRecord>,
}

pub struct PoSState {
    pub stakers: HashMap<Vec<u8>, Staker>,
    pub vrf: ECVRF,
    pub slashing_records: Vec<SlashingRecord>,
    pub last_checkpoint_height: u64,
    pub checkpoint_interval: u64,
}

impl PoSState {
    pub fn new() -> Result<Self, VRFError> {
        Ok(Self {
            stakers: HashMap::new(),
            vrf: ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)?,
            slashing_records: Vec::new(),
            last_checkpoint_height: 0,
            checkpoint_interval: 100,
        })
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
} 