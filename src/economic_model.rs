/// Economic model for Julius Coin
#[derive(Debug)]
pub struct EconomicModel {
    pub total_supply: u64,
    pub block_reward: u64,
    pub inflation_rate: f64,
}

impl EconomicModel {
    /// Create a new economic model
    pub fn new(total_supply: u64, block_reward: u64, inflation_rate: f64) -> Self {
        EconomicModel { total_supply, block_reward, inflation_rate }
    }

    /// Calculate the new supply after a block is mined
    pub fn calculate_new_supply(&self, blocks_mined: u64) -> u64 {
        let new_supply = self.block_reward * blocks_mined;
        new_supply
    }

    /// Adjust the block reward based on inflation rate
    pub fn adjust_block_reward(&mut self) {
        self.block_reward = (self.block_reward as f64 * (1.0 - self.inflation_rate)) as u64;
    }
}
