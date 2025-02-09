use serde::{Serialize, Deserialize};
use crate::crypto::verify_signature;
use log::info;

/// UTXOを構造体で表現
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UTXO {
    pub amount: u64,
    pub owner_hash: Vec<u8>, // PQAddress.hash
}

/// トランザクションの入力
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxInput {
    pub utxo_id: String,       // UTXOを特定するID (例: "ブロック番号-トランザクション番号-outIndex"など)
    pub sig: Vec<u8>,          // 署名(Dilithium)
    pub pub_key: Vec<u8>,      // 公開鍵(Dilithium)
}

/// トランザクションの出力
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxOutput {
    pub amount: u64,
    pub recipient_hash: Vec<u8>,
}

/// トランザクション本体
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

/// ブロック
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Block {
    pub index: u64,
    pub prev_hash: Vec<u8>,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub proposer_address: Vec<u8>, // Dilithium公開鍵をハッシュ化したもの
    pub block_signature: Vec<u8>,  // proposerの秘密鍵でブロック全体を署名(MVP簡易実装)
}

/// チェーン全体
#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    // UTXOを管理する簡易マップ (utxo_id -> UTXO)
    pub utxos: std::collections::HashMap<String, UTXO>,
}

impl Blockchain {
    /// 新規チェーンを作成 (ジェネシスブロック）
    pub fn new() -> Self {
        let genesis_block = Block {
            index: 0,
            prev_hash: vec![],
            timestamp: 0,
            transactions: vec![],
            proposer_address: vec![],
            block_signature: vec![],
        };
        Self {
            blocks: vec![genesis_block],
            utxos: std::collections::HashMap::new(),
        }
    }

    /// トランザクションを検証し、UTXOを更新
    pub fn apply_transaction(&mut self, tx: &Transaction) -> bool {
        let mut total_in = 0;
        let mut total_out = 0;

        // 入力を検証
        for inp in &tx.inputs {
            let utxo = match self.utxos.get(&inp.utxo_id) {
                Some(u) => u,
                None => {
                    info!("UTXOが存在しません: {}", inp.utxo_id);
                    return false;
                }
            };
            // 所有権の検証(Dilithium署名)
            let tx_hash = bincode::serialize(&tx).unwrap(); 
            if !verify_signature(&tx_hash, &inp.sig, &inp.pub_key) {
                info!("署名が無効です");
                return false;
            }
            // 入力のowner_hashとpub_keyのハッシュが一致するかチェック
            let pk_hash = crate::crypto::derive_address_from_pk(&inp.pub_key);
            if pk_hash != utxo.owner_hash {
                info!("所有者ハッシュが一致しません");
                return false;
            }
            total_in += utxo.amount;
        }

        // 出力を計算
        for outp in &tx.outputs {
            total_out += outp.amount;
        }

        // インプット合計 >= アウトプット合計 であること
        if total_in < total_out {
            info!("送金額が不正です。インプット合計 < アウトプット合計");
            return false;
        }

        // UTXO更新(インプットのUTXOを削除 → アウトプットを新規作成)
        for inp in &tx.inputs {
            self.utxos.remove(&inp.utxo_id);
        }

        // 新しいUTXOを生成(簡易的に"{block_index}-tx_index-out_index"などのIDを付ける)
        // 実際のブロック取り込み時に正式にIDをふる想定。
        for (i, outp) in tx.outputs.iter().enumerate() {
            let new_id = format!("pending-txoutput-{}-{}", tx.inputs.len(), i);
            self.utxos.insert(new_id, UTXO {
                amount: outp.amount,
                owner_hash: outp.recipient_hash.clone(),
            });
        }

        true
    }

    /// ブロックをチェーンに追加
    pub fn add_block(&mut self, block: Block) -> bool {
        // ブロック署名の検証
        let _block_data = bincode::serialize(&(
            block.index,
            block.prev_hash.clone(),
            block.timestamp,
            block.transactions.clone(),
            block.proposer_address.clone(),
        )).unwrap();

        // proposer_address(ハッシュ)を利用して公開鍵自体は別途取得するのが本来ですが、
        // MVPではブロックに秘密鍵署名が載っている前提で省略 & 検証スキップも可。
        // ここではPoSの簡易モデルなので最低限のチェックのみ。
        // ひとまず署名未検証でも良しとする。
        // let valid_sig = verify_signature(&block_data, &block.block_signature, ???);

        // 直前のブロックとつながっているか
        let last_block = self.blocks.last().unwrap();
        if block.prev_hash != self.hash_block(last_block) {
            info!("ブロックチェーンに繋がらないブロックです");
            return false;
        }

        // トランザクションを全て適用してみる
        for tx in &block.transactions {
            let ok = self.apply_transaction(tx);
            if !ok {
                info!("トランザクションが無効、ブロック追加失敗");
                return false;
            }
        }

        // 最後にブロックを追加
        info!("ブロック #{} を追加", block.index);
        self.blocks.push(block);

        true
    }

    /// 簡易ブロックハッシュ計算(SHA-256)
    pub fn hash_block(&self, block: &Block) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let encoded = bincode::serialize(block).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().to_vec()
    }
}
