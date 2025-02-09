use vrf::{VRFProof, VRF};
use crate::blockchain::consensus::staking::Staker;

pub fn select_proposer(stakers: &[&Staker], seed: &[u8], vrf: &impl VRF) -> Option<&Staker> {
    let total_stake: u64 = stakers.iter().map(|s| s.stake_amount).sum();
    if total_stake == 0 {
        return None;
    }

    let mut best_score = 0.0;
    let mut selected = None;

    for staker in stakers {
        if let Ok(proof) = vrf.prove(&staker.secret_key, seed) {
            let hash = proof.hash();
            // Map VRF output to 0-1 range
            let vrf_value = u64::from_be_bytes(hash[0..8].try_into().unwrap()) as f64 
                / u64::MAX as f64;
            
            // Weight by stake amount
            let weighted_score = vrf_value * (staker.stake_amount as f64 / total_stake as f64);
            
            if weighted_score > best_score {
                best_score = weighted_score;
                selected = Some(*staker);
            }
        }
    }

    selected
} 