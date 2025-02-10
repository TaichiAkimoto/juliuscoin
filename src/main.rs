use juliuscoin::{
    blockchain::chain::{Blockchain, Transaction},
    blockchain::consensus::PoSState,
    cryptography::wallet::Wallet,
    network::P2PNetwork,
    governance::Governance,
    governance::JIPStatus
};
use log::info;
use anyhow::Result;
use std::error::Error;

/// メイン関数
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ログ初期化
    env_logger::init();
    info!("=== Julius Coin MVPノードを起動します ===");

    // Initialize components
    let mut chain = Blockchain::new();
    let _wallet = Wallet::new();
    let _network = P2PNetwork::new(8333); // Using standard Bitcoin port as default
    let mut governance = Governance::new(1000, 1000); // Minimum stake and voting period
    let mut pos_state = PoSState::new().expect("Failed to initialize PoS state");
    let mempool: Vec<Transaction> = Vec::new();

    // Main blockchain loop
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Process pending transactions
        if let Some(tx) = mempool.first() {
            if chain.apply_transaction(tx) {
                info!("Transaction processed successfully");
            }
        }

        // Process governance proposals
        // First collect the voting JIPs
        let voting_jips: Vec<_> = governance.jips.values()
            .filter(|j| j.status == JIPStatus::Voting)
            .map(|j| j.id)
            .collect();
        
        // Then process them
        for jip_id in voting_jips {
            if let Ok(status) = governance.tally_votes(jip_id, 1000) { // Using 1000 as total stake for MVP
                info!("JIP {} status updated to {:?}", jip_id, status);
            }
        }

        // Update validator set
        let stakers: Vec<_> = pos_state.stakers.values().collect();
        for staker in stakers {
            if staker.stake_amount > 1000 {
                info!("Validator {} active with stake {}", 
                    hex::encode(&staker.address_hash), 
                    staker.stake_amount
                );
            }
        }

        // Consensus step
        if let Some(block) = chain.propose_block() {
            let block_hash = chain.hash_block(&block);
            info!("New block proposed with hash: {}", hex::encode(&block_hash));
        }
    }
}
