use juliuscoin::{
    blockchain::chain::Blockchain,
    blockchain::utxo::Transaction,
    blockchain::consensus::{PoSState, Staker},
    cryptography::wallet::Wallet,
    network::P2PNetwork,
    governance::Governance,
    governance::{JIPStatus, JIPType, VoteType}
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
    let mut wallet = Wallet::new()?;
    let mut network = P2PNetwork::new();
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
        if let Some(proposal) = governance.proposals.iter().find(|p| p.status == JIPStatus::Voting) {
            governance.update_proposal_status(proposal.id);
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
        if let Some(block) = chain.propose_block(&pos_state) {
            if chain.add_block(block) {
                info!("New block added to chain");
            }
        }
    }
}
