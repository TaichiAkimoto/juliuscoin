use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use crate::cryptography::crypto::PQAddress;
use std::fmt;

/// Peer scoring categories and weights
const SUCCESSFUL_BLOCK_PROPAGATION: i32 = 1;
const SUCCESSFUL_TX_PROPAGATION: i32 = 1;
const VALID_MESSAGE: i32 = 1;
const INVALID_MESSAGE: i32 = -10;
const INVALID_BLOCK: i32 = -20;
const INVALID_TX: i32 = -10;
const SLOW_RESPONSE: i32 = -1;
const FAILED_PING: i32 = -5;

/// Peer connection state and metadata
#[derive(Clone)]
pub struct Peer {
    pub address: PQAddress,
    pub socket_addr: SocketAddr,
    pub stream: Arc<Mutex<TcpStream>>,
    pub shared_secret: Vec<u8>,      // Kyber shared secret
    pub last_seen: Arc<Mutex<Instant>>,
    pub score: Arc<Mutex<i32>>,      // Peer reputation score
    pub status: Arc<Mutex<PeerStatus>>,
    pub banned_until: Arc<Mutex<Option<Instant>>>,
}

/// Peer status information
#[derive(Clone, Debug)]
pub struct PeerStatus {
    pub version: u32,
    pub height: u64,
    pub total_difficulty: u64,
}

impl Peer {
    /// Create a new peer instance
    pub fn new(
        address: PQAddress,
        socket_addr: SocketAddr,
        stream: TcpStream,
        shared_secret: Vec<u8>,
    ) -> Self {
        Self {
            address,
            socket_addr,
            stream: Arc::new(Mutex::new(stream)),
            shared_secret,
            last_seen: Arc::new(Mutex::new(Instant::now())),
            score: Arc::new(Mutex::new(0)),
            status: Arc::new(Mutex::new(PeerStatus {
                version: 0,
                height: 0,
                total_difficulty: 0,
            })),
            banned_until: Arc::new(Mutex::new(None)),
        }
    }

    /// Update peer's score based on behavior
    pub async fn update_score(&self, category: PeerScoreCategory) {
        let score_change = match category {
            PeerScoreCategory::SuccessfulBlockPropagation => SUCCESSFUL_BLOCK_PROPAGATION,
            PeerScoreCategory::SuccessfulTxPropagation => SUCCESSFUL_TX_PROPAGATION,
            PeerScoreCategory::ValidMessage => VALID_MESSAGE,
            PeerScoreCategory::InvalidMessage => INVALID_MESSAGE,
            PeerScoreCategory::InvalidBlock => INVALID_BLOCK,
            PeerScoreCategory::InvalidTx => INVALID_TX,
            PeerScoreCategory::SlowResponse => SLOW_RESPONSE,
            PeerScoreCategory::FailedPing => FAILED_PING,
        };

        let mut score = self.score.lock().await;
        *score += score_change;
    }

    /// Check if peer is banned
    pub async fn is_banned(&self) -> bool {
        let banned_until = self.banned_until.lock().await;
        match *banned_until {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    /// Ban peer for specified duration
    pub async fn ban(&self, duration: Duration) {
        let mut banned_until = self.banned_until.lock().await;
        *banned_until = Some(Instant::now() + duration);
    }

    /// Update peer status
    pub async fn update_status(&self, version: u32, height: u64, total_difficulty: u64) {
        let mut status = self.status.lock().await;
        status.version = version;
        status.height = height;
        status.total_difficulty = total_difficulty;
        *self.last_seen.lock().await = Instant::now();
    }
}

/// Categories for peer scoring
#[derive(Debug, Clone, Copy)]
pub enum PeerScoreCategory {
    SuccessfulBlockPropagation,
    SuccessfulTxPropagation,
    ValidMessage,
    InvalidMessage,
    InvalidBlock,
    InvalidTx,
    SlowResponse,
    FailedPing,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only include fields that are easily printable
        f.debug_struct("Peer")
            .field("address", &self.address)
            .field("socket_addr", &self.socket_addr)
            .field("shared_secret", &"<hidden>")
            .field("last_seen", &"<hidden>")
            .field("score", &"<hidden>")
            .field("status", &"<hidden>")
            .field("banned_until", &"<hidden>")
            .finish()
    }
}

// Add Send + Sync marker traits
unsafe impl Send for Peer {}
unsafe impl Sync for Peer {} 