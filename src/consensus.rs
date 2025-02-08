use crate::chain::{Block, Transaction};
use crate::Blockchain;
use crate::crypto::sign_message;
use log::info;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

/// 仮のステーク情報を持つ構造体
#[derive(Clone)]
pub struct Staker {
    pub address_hash: Vec<u8>,
    pub stake_amount: u64,
    #[allow(dead_code)]
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// PoS選出: ステーク量に応じてランダムにブロック提案者を決定する（超単純化）
pub fn select_proposer(stakers: &[Staker]) -> Option<&Staker> {
    let total_stake: u64 = stakers.iter().map(|s| s.stake_amount).sum();
    if total_stake == 0 {
        return None;
    }
    let mut rng = rand::thread_rng();
    let pick = rng.gen_range(0..total_stake);
    let mut cumulative = 0;
    for staker in stakers {
        cumulative += staker.stake_amount;
        if pick < cumulative {
            return Some(staker);
        }
    }
    None
}

/// ブロック生成
pub fn produce_block(
    chain: &mut Blockchain,
    transactions: Vec<Transaction>,
    proposer: &Staker,
) -> Block {
    let last_block = chain.blocks.last().unwrap();
    let next_index = last_block.index + 1;
    let prev_hash = chain.hash_block(last_block);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let block_candidate = Block {
        index: next_index,
        prev_hash,
        timestamp,
        transactions,
        proposer_address: proposer.address_hash.clone(),
        block_signature: vec![], // ここで署名を後付けする
    };

    // ブロック署名(簡易例):
    let block_data = bincode::serialize(&(
        block_candidate.index,
        block_candidate.prev_hash.clone(),
        block_candidate.timestamp,
        block_candidate.transactions.clone(),
        block_candidate.proposer_address.clone(),
    )).unwrap();

    let sig = sign_message(&block_data, &proposer.secret_key);

    // 署名を格納
    let signed_block = Block {
        block_signature: sig,
        ..block_candidate
    };
    signed_block
}

/// 簡易PoSフロー：トランザクションを集め、選ばれたproposerでブロック生成
pub fn pos_step(chain: &mut Blockchain, mempool: Vec<Transaction>, stakers: &[Staker]) {
    if let Some(proposer) = select_proposer(stakers) {
        info!("選出されたProposer: {:?}", hex::encode(&proposer.address_hash));
        let new_block = produce_block(chain, mempool, proposer);
        chain.add_block(new_block);
    } else {
        info!("ステークが存在せずブロックを生成できません");
    }
}
