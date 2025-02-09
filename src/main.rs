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
    governance::{Governance, JIPType, JIPStatus, VoteType},
};
use std::sync::Arc;
use tokio::sync::Mutex;

/// メイン関数
#[tokio::main]
async fn main() -> Result<()> {
    // ログ初期化
    env_logger::init();
    info!("=== Julius Coin MVPノードを起動します ===");

    // (1) ブロックチェーン初期化
    let chain = Arc::new(Mutex::new(Blockchain::new()));

    // (2) ウォレットがない場合は新規作成
    let wallet_path = "wallet.bin";
    let my_wallet = if std::path::Path::new(wallet_path).exists() {
        info!("既存ウォレットを読み込み: {}", wallet_path);
        Wallet::load_from_file(wallet_path)?
    } else {
        info!("新規ウォレットを生成");
        let w = Wallet::new();
        w.save_to_file(wallet_path)?;
        w
    };

    info!("自分のアドレスHash = {}", hex::encode(&my_wallet.address_hash));

    // (3) PoS状態の初期化とステーカー登録
    let pos_state = Arc::new(Mutex::new(PoSState::new()));
    let my_staker = Staker {
        address_hash: my_wallet.address_hash.clone(),
        stake_amount: 1000,
        public_key: my_wallet.public_key.clone(),
        secret_key: my_wallet.secret_key.clone(),
        last_proposal_height: None,
        last_active_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        slashing_records: Vec::new(),
    };
    pos_state.lock().await.stakers.insert(my_wallet.address_hash.clone(), my_staker);

    // (4) ガバナンスシステムの初期化
    let governance = Arc::new(Mutex::new(Governance::new(
        1000000,     // 最小提案ステーク量: 1M coins
        2016,        // 投票期間: 2週間 (2016ブロック)
    )));

    // (5) P2Pネットワークを起動
    let network = Arc::new(P2PNetwork::new(8333));
    info!("P2Pネットワークを起動します...");

    // (6) CLIハンドラの初期化
    let cli_handler = Arc::new(Mutex::new(CliHandler::new(
        governance.lock().await.clone(),
        my_wallet.get_address(),
        chain.lock().await.blocks.len() as u64,
    )));

    // CLIコマンドの処理ループを開始
    let cli_handler_clone = cli_handler.clone();
    tokio::spawn(async move {
        use tokio::io::{self, AsyncBufReadExt};
        let mut reader = io::BufReader::new(io::stdin());
        let mut line = String::new();

        loop {
            print!("> ");
            if let Ok(n) = reader.read_line(&mut line).await {
                if n == 0 {
                    break;
                }
                let args: Vec<String> = line.trim()
                    .split_whitespace()
                    .map(String::from)
                    .collect();

                if !args.is_empty() {
                    match cli_handler_clone.lock().await.handle_command(args) {
                        Ok(_) => {},
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
                line.clear();
            }
        }
    });

    // P2Pネットワークを起動
    if let Err(e) = network.start().await {
        eprintln!("Failed to start P2P network: {}", e);
    }

    // メインループ
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // ブロック生成処理
        let mut chain = chain.lock().await;
        let mut pos_state = pos_state.lock().await;
        
        let mempool = vec![]; // 実際のトランザクションプールから取得
        consensus::pos_step(&mut chain, mempool, &mut pos_state);
        
        // ガバナンス処理
        let mut governance = governance.lock().await;
        for (id, jip) in governance.jips.iter_mut() {
            if let Some(end) = jip.voting_period_end {
                if chain.blocks.len() as u64 >= end {
                    let _ = governance.tally_votes(*id, pos_state.stakers.values().map(|s| s.stake_amount).sum());
                }
            }
        }
    }

    Ok(())
}
