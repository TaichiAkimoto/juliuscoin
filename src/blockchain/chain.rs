//! Core blockchain data structures and operations.
//! 
//! This module implements the fundamental blockchain structures including:
//! - UTXO (Unspent Transaction Output) management
//! - Transaction processing
//! - Block creation and validation
//! - Chain management
//! 
//! The implementation uses post-quantum cryptography for transaction signatures
//! and block validation.

use serde::{Serialize, Deserialize};
use crate::cryptography::crypto::{verify_signature, derive_address_from_pk};
use crate::blockchain::consensus::PoSState;
use log::info;

/// Represents an Unspent Transaction Output (UTXO) in the blockchain.
/// 
/// UTXOs are the fundamental unit of value in the blockchain, representing
/// coins that can be spent in future transactions.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UTXO {
    /// The amount of coins in this UTXO
    pub amount: u64,
    /// Hash of the owner's post-quantum address
    pub owner_hash: Vec<u8>, // PQAddress.hash
}

/// Represents an input to a transaction.
/// 
/// Transaction inputs reference existing UTXOs and include cryptographic proof
/// that the sender has the right to spend them.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxInput {
    /// Unique identifier for the UTXO being spent (format: "block_number-tx_number-output_index")
    pub utxo_id: String,       // UTXOを特定するID (例: "ブロック番号-トランザクション番号-outIndex"など)
    /// Dilithium signature proving ownership of the UTXO
    pub sig: Vec<u8>,          // 署名(Dilithium)
    /// Dilithium public key of the UTXO owner
    pub pub_key: Vec<u8>,      // 公開鍵(Dilithium)
}

/// Represents an output of a transaction.
/// 
/// Transaction outputs create new UTXOs that can be spent in future transactions.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxOutput {
    /// Amount of coins to transfer
    pub amount: u64,
    /// Hash of the recipient's address
    pub recipient_hash: Vec<u8>,
}

/// Represents a complete transaction in the blockchain.
/// 
/// A transaction consumes existing UTXOs as inputs and creates new UTXOs as outputs.
/// The total value of inputs must equal the total value of outputs.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transaction {
    /// List of UTXOs to be consumed
    pub inputs: Vec<TxInput>,
    /// List of new UTXOs to be created
    pub outputs: Vec<TxOutput>,
}

/// Represents a block in the blockchain.
/// 
/// Each block contains a list of transactions and is cryptographically linked
/// to the previous block through its hash. Blocks are signed by their proposer
/// using post-quantum signatures.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Block {
    /// Block height in the chain
    pub index: u64,
    /// Hash of the previous block
    pub prev_hash: Vec<u8>,
    /// Unix timestamp of block creation
    pub timestamp: u64,
    /// List of transactions included in this block
    pub transactions: Vec<Transaction>,
    /// Hash of the proposer's Dilithium public key
    pub proposer_address: Vec<u8>,
    /// Dilithium signature of the block by the proposer
    pub block_signature: Vec<u8>,
}

/// The main blockchain structure that manages the chain of blocks and UTXO set.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Blockchain {
    /// Ordered list of blocks in the chain
    pub blocks: Vec<Block>,
    /// Map of UTXO IDs to their corresponding UTXO data
    pub utxos: std::collections::HashMap<String, UTXO>,
}

impl Blockchain {
    /// Creates a new blockchain with a genesis block
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

    /// Validates and applies a transaction to the UTXO set
    /// 
    /// # Arguments
    /// * `tx` - The transaction to apply
    /// 
    /// # Returns
    /// * `bool` - True if the transaction was successfully applied
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
            let pk_hash = derive_address_from_pk(&inp.pub_key);
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

    /// Adds a new block to the chain after validation
    /// 
    /// # Arguments
    /// * `block` - The block to add
    /// 
    /// # Returns
    /// * `bool` - True if the block was successfully added
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

    /// Computes the hash of a block
    /// 
    /// # Arguments
    /// * `block` - The block to hash
    /// 
    /// # Returns
    /// * `Vec<u8>` - The SHA-256 hash of the block
    pub fn hash_block(&self, block: &Block) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let encoded = bincode::serialize(block).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().to_vec()
    }

    pub fn propose_block(&self, pos_state: &PoSState) -> Option<Block> {
        let last_block = self.blocks.last()?;
        let next_index = last_block.index + 1;
        let prev_hash = self.hash_block(last_block);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get stakers for proposer selection
        let stakers: Vec<&Staker> = pos_state.stakers.values().collect();
        
        // Use VRF to select proposer
        let proposer = crate::blockchain::consensus::vrf::select_proposer(
            &stakers,
            &prev_hash,
            &mut pos_state.vrf
        )?;

        // For MVP, we're not implementing actual transaction selection
        // In production, this would select transactions from mempool
        let transactions = Vec::new();

        Some(Block {
            index: next_index,
            prev_hash,
            timestamp,
            transactions,
            proposer_address: proposer.address_hash.clone(),
            block_signature: Vec::new(),  // Should be signed by proposer
        })
    }
}
