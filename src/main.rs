mod crypto;
mod chain;
mod consensus;
mod wallet;
mod network;
mod metrics;
mod governance;
mod cli;

use crate::chain::{Transaction, TxInput, TxOutput};
use crate::consensus::{PoSState, Staker};
use crate::wallet::Wallet;
use crate::chain::Blockchain;
use crate::cli::CliHandler;
use log::info;
use network::P2PNetwork;
use anyhow::Result;
use juliuscoin::{
    Transaction, TxInput, TxOutput,
    Blockchain,
    PoSState, Staker,
    Wallet,
    P2PNetwork,
    Governance, JIPType, JIPStatus, VoteType
};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::error::Error;

/// メイン関数
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ログ初期化
    env_logger::init();
    info!("=== Julius Coin MVPノードを起動します ===");

    // Initialize components
    let mut chain = Blockchain::new();
    let mut wallet = Wallet::new();
    let mut network = P2PNetwork::new().await?;
    let mut governance = Governance::new();
    let mut pos_state = PoSState::new().expect("Failed to initialize PoS state");
    let mempool = Vec::new();

    // Start network services
    network.start().await?;

    // Main blockchain loop
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Process pending transactions
        if let Some(tx) = mempool.first() {
            if chain.validate_transaction(tx) {
                chain.add_transaction(tx.clone());
            }
        }

        // Process governance proposals
        if let Some(proposal) = governance.get_active_proposals().first() {
            if proposal.status == JIPStatus::Voting {
                governance.process_votes(proposal);
            }
        }

        // Update validator set
        for staker in pos_state.get_validators() {
            if staker.stake_amount > 1000 {
                pos_state.add_validator(staker.clone());
            }
        }

        // Consensus step
        if let Some(block) = chain.create_block() {
            chain.add_block(block)?;
            network.broadcast_block(&block).await?;
        }
    }
}
