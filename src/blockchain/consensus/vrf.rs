use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;
use crate::blockchain::consensus::staking::Staker;

pub fn select_proposer<'a>(
    stakers: &'a [&'a Staker], 
    seed: &[u8], 
    vrf: &mut ECVRF
) -> Option<&'a Staker> {
    let total_stake: u64 = stakers.iter().map(|s| s.stake_amount).sum();
    if total_stake == 0 {
        return None;
    }

    let mut best_score = 0.0;
    let mut selected = None;

    for staker in stakers {
        // Convert the secret key to the appropriate format
        if let Ok(proof) = vrf.prove(&staker.secret_key, seed) {
            // Use the proof directly as bytes for the hash
            let hash = &proof[..8]; // Take first 8 bytes of the proof
            
            // Map VRF output to 0-1 range
            let vrf_value = u64::from_be_bytes(hash.try_into().unwrap()) as f64 
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