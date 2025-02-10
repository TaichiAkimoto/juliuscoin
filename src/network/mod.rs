pub mod message;
pub mod peer;
pub mod protocol;

pub use message::Message;
pub use peer::Peer;
pub use protocol::P2PNetwork;

// Constants for network configuration
pub const CONNECTION_TIMEOUT: u64 = 10; // seconds
pub const HEARTBEAT_INTERVAL: u64 = 30; // seconds
pub const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024; // 50MB
pub const MAX_PEERS: usize = 50;
pub const PEER_SCORE_THRESHOLD: i32 = -100; // Ban threshold
pub const BLOCK_PROPAGATION_TIMEOUT: u64 = 5; // seconds
pub const SYNC_BATCH_SIZE: usize = 100; // blocks 