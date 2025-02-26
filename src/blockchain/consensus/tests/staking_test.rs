#[cfg(test)]
mod tests {
    use crate::blockchain::consensus::staking::{PoSState, ValidatorVote};
    use crate::blockchain::consensus::slashing::SlashingReason;
    use std::collections::HashMap;

    #[test]
    fn test_finality_across_epochs() {
        let mut pos_state = PoSState::new().unwrap();
        assert_eq!(pos_state.get_finalized_height(), 0);

        let validator_keys: Vec<Vec<u8>> = (0..3).map(|i| vec![i; 32]).collect();
        for key in &validator_keys {
            pos_state.stake(key.clone(), 10000, key.clone()).unwrap();
        }

        let epoch_length = pos_state.get_epoch_length();
        let finality_delay = pos_state.finalization.finality_delay;

        // Simulate blocks and votes for a few epochs
        for height in 1..=(epoch_length * (finality_delay + 3)) {
            let current_epoch = height / epoch_length;

            // Each validator votes for the current height
            for key in &validator_keys {
                pos_state.submit_finalization_vote(key, height, height).unwrap();
            }

            pos_state.try_justify_and_finalize(height);

            // Check finalized height progression
            if height >= epoch_length * (finality_delay + 1) {
                let expected_finalized_height = epoch_length * (current_epoch - finality_delay);
                assert_eq!(pos_state.get_finalized_height(), expected_finalized_height, "Finalized height incorrect at height {}", height);
            }
        }

        assert!(pos_state.get_finalized_height() > 0);
        assert_eq!(pos_state.get_finalized_height(), epoch_length * (3 - finality_delay)); // Assuming 3 epochs processed
    }
}
