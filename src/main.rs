mod crypto;
mod chain;
mod consensus;
mod wallet;
mod network;
mod metrics;

use crate::chain::{Transaction, TxInput, TxOutput};
use crate::consensus::{Staker, pos_step};
use crate::wallet::Wallet;
use crate::chain::Blockchain;
use log::info;
use network::P2PNetwork;
use anyhow::Result;

/// メイン関数
#[tokio::main]
async fn main() -> Result<()> {
    // ログ初期化
    env_logger::init();
    info!("=== Julius Coin MVPノードを起動します ===");

    // (1) ブロックチェーン初期化
    let mut chain = Blockchain::new();

    // (2) ウォレットがない場合は新規作成
    //     実際にはCLI引数や設定ファイルから複数ウォレットを扱う想定です
    let wallet_path = "wallet.bin";
    let my_wallet = if std::path::Path::new(wallet_path).exists() {
        info!("既存ウォレットを読み込み: {}", wallet_path);
        Wallet::load_from_file(wallet_path)
    } else {
        info!("新規ウォレットを生成");
        let w = Wallet::new();
        w.save_to_file(wallet_path);
        w
    };

    info!("自分のアドレスHash = {}", hex::encode(&my_wallet.address_hash));

    // (3) ステーカー一覧を準備: ここでは自分だけをステーカーとする
    let my_staker = Staker {
        address_hash: my_wallet.address_hash.clone(),
        stake_amount: 1000,  // 適当なステーク量(自分が選ばれやすくなる)
        public_key: my_wallet.public_key.clone(),
        secret_key: my_wallet.secret_key.clone(),
    };
    let stakers = vec![my_staker];

    // (4) 適当なトランザクションを1つ作ってみる: 自分から自分への送金（MVP用のテスト）
    // 実際にはUTXOを取得 → TxInputを構成 → 署名 → TxOutput
    // ここではGenesis直後でUTXOが無いので、擬似的にインプットをでっちあげる
    let pseudo_input_id = "genesis-utxo-0".to_string();

    // TxInputを生成: 署名を作る
    let tx_dummy = Transaction {
        inputs: vec![{
            let mut inp = TxInput {
                utxo_id: pseudo_input_id.clone(),
                sig: vec![],
                pub_key: my_wallet.public_key.clone(),
            };
            // トランザクション全体をシリアライズして署名
            let tx_bytes = bincode::serialize(&(
                pseudo_input_id.clone()
            )).unwrap();
            let signature = crypto::sign_message(&tx_bytes, &my_wallet.secret_key);
            inp.sig = signature;
            inp
        }],
        outputs: vec![TxOutput {
            amount: 500,
            recipient_hash: my_wallet.address_hash.clone(),
        }],
    };

    // (5) PoSステップでブロック生成
    info!("トランザクションを含むブロック生成を試みます...");
    let mempool = vec![tx_dummy];
    pos_step(&mut chain, mempool, &stakers);

    // 結果表示
    info!("チェーンのブロック数: {}", chain.blocks.len());
    for (i, b) in chain.blocks.iter().enumerate() {
        info!("Block #{} => Tx数: {}", b.index, b.transactions.len());
        if i == 0 {
            info!("(Genesis Block)");
        }
    }

    // (6) 簡易CLIループなど入れても良いが、MVPなので終了
    info!("=== Julius Coin MVP完了 ===");

    // P2Pネットワークを起動
    let network = P2PNetwork::new(8333);
    println!("P2Pネットワークを起動します...");
    network.start().await?;

    // 暗号メトリクスを表示
    let metrics = crypto::CRYPTO_METRICS.lock().unwrap();
    metrics.print_stats();

    Ok(())
}
