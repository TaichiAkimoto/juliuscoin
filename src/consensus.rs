use rand::Rng;
use crate::chain::{Block, Transaction};
use crate::Blockchain;
use log::info;

/// Staker構造体
#[derive(Clone)]
pub struct Staker {
    pub address_hash: Vec<u8>,
    pub stake_amount: u64,
    #[allow(dead_code)]
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// PoS選出: ステーク量に応じてランダムにブロック提案者を選出
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
        block_signature: vec![],
    };

    let block_data = bincode::serialize(&(
        block_candidate.index,
        block_candidate.prev_hash.clone(),
        block_candidate.timestamp,
        block_candidate.transactions.clone(),
        block_candidate.proposer_address.clone(),
    )).unwrap();

    let sig = sign_message(&block_data, &proposer.secret_key);

    let signed_block = Block {
        block_signature: sig,
        ..block_candidate
    };
    signed_block
}

/// PoSステップ: トランザクションを集めてブロックを生成
pub fn pos_step(chain: &mut Blockchain, mempool: Vec<Transaction>, stakers: &[Staker]) {
    if let Some(proposer) = select_proposer(stakers) {
        info!("選出されたProposer: {:?}", hex::encode(&proposer.address_hash));
        let new_block = produce_block(chain, mempool, proposer);
        chain.add_block(new_block);
    } else {
        info!("ステークが存在しないためブロックを生成できません");
    }
}
