use serde::{Serialize, Deserialize};
use crate::chain::{Block, Transaction};

#[derive(Serialize, Deserialize)]
pub enum Message {
    Block(Block),
    Transaction(Transaction),
    GetBlocks { start: u64, end: u64 },
    Blocks(Vec<Block>),
} 