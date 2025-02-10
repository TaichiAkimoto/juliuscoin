use serde::{Serialize, Deserialize};
use crate::blockchain::chain::{Block, Transaction};

/// Network message types for P2P communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // Block and transaction propagation
    Block(Block),
    Transaction(Transaction),
    
    // Chain synchronization
    GetBlocks { start: u64, end: u64 },
    Blocks(Vec<Block>),
    GetBlocksAfter(u64), // Request blocks after given height
    GetBlockHeader(u64), // Request specific block header
    BlockHeader(Block),  // Response with block header
    
    // Peer discovery and management
    Ping(u64),          // Timestamp
    Pong(u64),          // Echo timestamp
    GetPeers,           // Request peer list
    Peers(Vec<String>), // Response with peer addresses
    
    // Network status
    Status {
        version: u32,
        height: u64,
        total_difficulty: u64,
    },
}

/// Encrypted P2P message with Kyber-based encryption
#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender_address: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>, // Only used during initial key exchange
}

/// Signed message wrapper for authentication
#[derive(Serialize, Deserialize)]
pub struct SignedMessage {
    pub sender_address: Vec<u8>,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
} 