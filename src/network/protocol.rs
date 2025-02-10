use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::{Result, anyhow};
use log::{info, warn, error};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use futures::future::join_all;

use crate::blockchain::chain::{Block, Transaction, BlockChain, Chain, BlockValidationError, BlockValidationResult};
use crate::cryptography::crypto::{
    PQAddress, derive_address_from_pk,
};
use crate::network::message::{Message, EncryptedMessage, SignedMessage};
use crate::network::peer::{Peer, PeerScoreCategory};
use crate::network::{
    CONNECTION_TIMEOUT, HEARTBEAT_INTERVAL, MAX_MESSAGE_SIZE,
    MAX_PEERS, PEER_SCORE_THRESHOLD, BLOCK_PROPAGATION_TIMEOUT,
    SYNC_BATCH_SIZE,
};

// Constants
const NONCE_SIZE: usize = 12;
const SYNC_REQUEST_TIMEOUT: u64 = 30; // seconds
const MAX_BLOCKS_PER_REQUEST: usize = 500;
const MIN_SYNC_PEERS: usize = 3;

// Temporary placeholder for Kyber functions until they're implemented
fn generate_kyber_keypair() -> (Vec<u8>, Vec<u8>) {
    // TODO: Implement proper Kyber key generation
    (vec![0u8; 32], vec![0u8; 32])
}

fn kyber_encapsulate(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // TODO: Implement proper Kyber encapsulation
    (vec![0u8; 32], vec![0u8; 32])
}

/// Sync state for tracking block synchronization progress
#[derive(Debug)]
struct SyncState {
    /// Current sync target height
    target_height: u64,
    /// Height we're currently syncing from
    current_height: u64,
    /// Set of block heights requested but not yet received
    pending_requests: HashSet<u64>,
    /// Timestamp of last sync request
    last_request: Instant,
    /// Number of consecutive timeouts
    timeout_count: u32,
    /// Best peer for syncing (most work)
    best_peer: Option<Arc<Peer>>,
    /// Known fork points that need resolution
    fork_points: Vec<(u64, Vec<u8>)>, // (height, hash)
}

impl SyncState {
    fn new(current_height: u64) -> Self {
        Self {
            target_height: current_height,
            current_height,
            pending_requests: HashSet::new(),
            last_request: Instant::now(),
            timeout_count: 0,
            best_peer: None,
            fork_points: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.pending_requests.clear();
        self.timeout_count = 0;
        self.last_request = Instant::now();
    }
}

#[derive(Clone)]
pub struct P2PNetwork {
    port: u16,
    peers: Arc<Mutex<HashMap<Vec<u8>, Arc<Peer>>>>,
    keypair: (Vec<u8>, Vec<u8>), // Kyber (pk, sk)
    chain: Arc<Mutex<Chain>>,
}

impl P2PNetwork {
    pub fn new(port: u16, chain: Chain) -> Arc<Self> {
        Arc::new(Self {
            port,
            peers: Arc::new(Mutex::new(HashMap::new())),
            keypair: generate_kyber_keypair(),
            chain: Arc::new(Mutex::new(chain)),
        })
    }

    /// Start the P2P network service
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("P2P network listening on {}", addr);

        let (tx, mut rx) = mpsc::channel::<(TcpStream, SocketAddr)>(32);
        let peers = self.peers.clone();

        // Start heartbeat task
        self.spawn_heartbeat_task();

        // Handle incoming connections
        let network = self.clone();
        tokio::spawn(async move {
            while let Some((stream, addr)) = rx.recv().await {
                let peer_addr = addr.to_string();
                if let Err(e) = network.handle_peer(stream, addr).await {
                    error!("Error handling peer {}: {}", peer_addr, e);
                }
            }
        });

        loop {
            let (stream, addr) = listener.accept().await?;
            if self.peers.lock().await.len() >= MAX_PEERS {
                warn!("Max peers reached, rejecting connection from {}", addr);
                continue;
            }
            info!("New peer connection from: {}", addr);
            tx.send((stream, addr)).await?;
        }
    }

    /// Connect to a new peer
    pub async fn connect_to_peer(&self, addr: SocketAddr) -> Result<()> {
        // Check if we're already connected
        let peers = self.peers.lock().await;
        if peers.values().any(|p| p.socket_addr == addr) {
            return Ok(());
        }
        if peers.len() >= MAX_PEERS {
            return Err(anyhow!("Max peers reached"));
        }
        drop(peers);

        // Try to connect with timeout
        let stream = match timeout(Duration::from_secs(CONNECTION_TIMEOUT), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(anyhow!("Failed to connect to peer {}: {}", addr, e)),
            Err(_) => return Err(anyhow!("Connection timeout to peer {}", addr)),
        };

        self.establish_connection(stream, addr).await
    }

    /// Handle new peer connection
    async fn handle_peer(&self, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        self.establish_connection(stream, addr).await
    }

    /// Establish secure connection with peer
    async fn establish_connection(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        stream.set_nodelay(true)?;

        // 1. Send our Kyber public key
        stream.write_all(&self.keypair.0).await?;

        // 2. Receive peer's public key
        let mut peer_pk = vec![0u8; self.keypair.0.len()];
        stream.read_exact(&mut peer_pk).await?;

        // 3. Generate shared secret
        let (ciphertext, shared_secret) = kyber_encapsulate(&peer_pk);

        // 4. Send encapsulated key
        stream.write_all(&ciphertext).await?;

        // 5. Create and store peer
        let peer = Arc::new(Peer::new(
            PQAddress {
                hash: derive_address_from_pk(&peer_pk),
            },
            addr,
            stream,
            shared_secret,
        ));

        let mut peers = self.peers.lock().await;
        peers.insert(peer.address.hash.clone(), peer.clone());
        drop(peers);

        // 6. Start message handler for this peer
        self.spawn_message_handler(peer.clone()).await;

        // 7. Start chain synchronization
        self.start_chain_sync(peer).await?;

        info!("Established secure connection with peer: {}", addr);
        Ok(())
    }

    /// Start chain synchronization with a new peer
    async fn start_chain_sync(&self, peer: Arc<Peer>) -> Result<()> {
        // Get our current chain height
        let our_height = {
            let chain = self.chain.lock().await;
            chain.get_height()
        };

        // Request peer's chain status
        self.send_encrypted(&peer, &Message::Status {
            version: 1, // Current protocol version
            height: our_height,
            total_difficulty: 0, // TODO: Implement difficulty calculation
        }).await?;

        Ok(())
    }

    /// Sync blocks from a specific peer
    async fn sync_blocks_from_peer(&self, peer: Arc<Peer>, start_height: u64, end_height: u64) -> Result<Vec<Block>> {
        let mut blocks = Vec::new();
        let mut current_height = start_height;

        while current_height <= end_height {
            let batch_end = (current_height + MAX_BLOCKS_PER_REQUEST as u64 - 1).min(end_height);
            
            // Request batch of blocks
            self.send_encrypted(&peer, &Message::GetBlocks {
                start: current_height,
                end: batch_end,
            }).await?;

            // Wait for response with timeout
            let response = timeout(
                Duration::from_secs(SYNC_REQUEST_TIMEOUT),
                self.wait_for_blocks(&peer)
            ).await??;

            // Validate and process received blocks
            for block in response {
                // TODO: Add proper block validation
                blocks.push(block);
            }

            current_height = batch_end + 1;
        }

        Ok(blocks)
    }

    /// Wait for blocks response from peer
    async fn wait_for_blocks(&self, peer: &Arc<Peer>) -> Result<Vec<Block>> {
        // TODO: Implement proper message waiting mechanism
        // This is a placeholder that should be replaced with actual implementation
        Ok(Vec::new())
    }

    /// Find best peer for synchronization
    async fn find_sync_peers(&self) -> Vec<Arc<Peer>> {
        let peers = self.peers.lock().await;
        let mut sync_peers: Vec<Arc<Peer>> = peers.values()
            .filter(|p| {
                let status = p.status.try_lock()
                    .map(|s| s.height > 0)
                    .unwrap_or(false);
                status
            })
            .cloned()
            .collect();

        // Sort by height and total difficulty
        sync_peers.sort_by(|a, b| {
            let a_status = a.status.try_lock().unwrap();
            let b_status = b.status.try_lock().unwrap();
            b_status.height.cmp(&a_status.height)
                .then(b_status.total_difficulty.cmp(&a_status.total_difficulty))
        });

        sync_peers
    }

    /// Generate random nonce for AES-GCM
    fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        nonce
    }

    /// Send encrypted message to peer
    async fn send_encrypted(&self, peer: &Arc<Peer>, message: &Message) -> Result<()> {
        let message_bytes = bincode::serialize(message)?;

        // Encrypt with AES-GCM using shared secret
        let cipher = Aes256Gcm::new_from_slice(&peer.shared_secret)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
        
        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted_data = cipher.encrypt(nonce, message_bytes.as_ref())
            .map_err(|e| anyhow!("Failed to encrypt message: {}", e))?;

        let encrypted_message = EncryptedMessage {
            sender_address: peer.address.hash.clone(),
            encrypted_data,
            kyber_ciphertext: vec![], // Empty since key exchange is done
        };

        let message_bytes = bincode::serialize(&encrypted_message)?;
        let mut stream = peer.stream.lock().await;
        stream.write_all(&message_bytes).await?;

        Ok(())
    }

    /// Spawn heartbeat task
    fn spawn_heartbeat_task(&self) {
        let peers = self.peers.clone();
        let network = Arc::new(self.clone());
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(HEARTBEAT_INTERVAL)).await;
                let mut timed_out_peers = vec![];
                {
                    let peers_lock = peers.lock().await;
                    for (peer_key, peer) in peers_lock.iter() {
                        let last_seen = *peer.last_seen.lock().await;
                        if last_seen.elapsed() > Duration::from_secs(HEARTBEAT_INTERVAL * 2) {
                            warn!("Peer {} hasn't responded to heartbeat", peer.socket_addr);
                            timed_out_peers.push((peer_key.clone(), peer.socket_addr));
                        } else {
                            if let Err(e) = network.send_heartbeat(peer).await {
                                warn!("Failed to send heartbeat to peer {}: {}", peer.socket_addr, e);
                            }
                        }
                    }
                }
                // Attempt reconnection for timed out peers
                for (peer_key, addr) in timed_out_peers {
                    info!("Attempting to reconnect to peer {}", addr);
                    match network.connect_to_peer(addr).await {
                        Ok(_) => {
                            info!("Successfully reconnected to peer {}", addr);
                        },
                        Err(e) => {
                            warn!("Reconnection failed for {}: {}. Evicting peer.", addr, e);
                            let mut peers_lock = peers.lock().await;
                            peers_lock.remove(&peer_key);
                        }
                    }
                }
            }
        });
    }

    /// Send heartbeat to peer
    async fn send_heartbeat(&self, peer: &Arc<Peer>) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let message = Message::Ping(timestamp);
        self.send_encrypted(peer, &message).await?;
        Ok(())
    }

    /// Handle incoming messages from peer
    async fn handle_message(network: Arc<Self>, peer: Arc<Peer>, message: Message) -> Result<()> {
        match message {
            Message::Block(block) => {
                // Process single block
                network.process_received_blocks(vec![block], peer).await?;
            }
            Message::GetBlocks { start, end } => {
                // Send requested blocks
                let chain = network.chain.lock().await;
                let mut blocks = Vec::new();
                
                for height in start..=end {
                    if let Ok(block_range) = chain.get_blocks_range(height, height) {
                        blocks.extend(block_range);
                        if blocks.len() >= SYNC_BATCH_SIZE {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                drop(chain);

                network.send_encrypted(&peer, &Message::Blocks(blocks)).await?;
            }
            Message::Blocks(blocks) => {
                // Process received blocks
                network.process_received_blocks(blocks, peer.clone()).await?;
                
                // Update sync state if we're syncing
                let chain = network.chain.lock().await;
                let current_height = chain.get_height();
                drop(chain);
                
                let peer_status = peer.status.lock().await;
                let target_height = peer_status.height;
                drop(peer_status);
                
                if current_height < target_height {
                    // Continue syncing
                    network.request_blocks(peer, Arc::new(Mutex::new(SyncState::new(current_height)))).await?;
                }
            }
            Message::GetBlocksAfter(height) => {
                // Send blocks after specified height
                let chain = network.chain.lock().await;
                let current_height = chain.get_height();
                let mut blocks = Vec::new();

                if let Ok(block_range) = chain.get_blocks_range(height + 1, current_height) {
                    blocks = block_range;
                }
                drop(chain);

                network.send_encrypted(&peer, &Message::Blocks(blocks)).await?;
            }
            Message::Status { version, height, total_difficulty } => {
                peer.update_status(version, height, total_difficulty).await;

                // Check if we need to sync
                let our_height = {
                    let chain = network.chain.lock().await;
                    chain.get_height()
                };

                if height > our_height {
                    // Start syncing blocks
                    if let Ok(blocks) = network.sync_blocks_from_peer(
                        peer.clone(),
                        our_height + 1,
                        height
                    ).await {
                        let mut chain = network.chain.lock().await;
                        for block in blocks {
                            if let Err(e) = chain.add_block(block) {
                                error!("Failed to add synced block: {}", e);
                                peer.update_score(PeerScoreCategory::InvalidBlock).await;
                                break;
                            }
                        }
                    }
                }
            }
            Message::Transaction(tx) => {
                peer.update_score(PeerScoreCategory::SuccessfulTxPropagation).await;
                // TODO: Validate and process transaction
            }
            Message::GetBlockHeader(height) => {
                // TODO: Send block header for specified height
            }
            Message::BlockHeader(block) => {
                // TODO: Process received block header
            }
            Message::Ping(timestamp) => {
                let response = Message::Pong(timestamp);
                network.send_encrypted(&peer, &response).await?;
            }
            Message::Pong(_) => {
                // Update last seen is already handled
            }
            Message::GetPeers => {
                let peers = network.peers.lock().await;
                let peer_list = peers.values()
                    .map(|p| p.socket_addr.to_string())
                    .collect();
                let response = Message::Peers(peer_list);
                network.send_encrypted(&peer, &response).await?;
            }
            Message::Peers(addrs) => {
                for addr_str in addrs {
                    if let Ok(addr) = addr_str.parse() {
                        if let Err(e) = network.connect_to_peer(addr).await {
                            warn!("Failed to connect to discovered peer {}: {}", addr_str, e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Spawn message handler task for peer
    async fn spawn_message_handler(&self, peer: Arc<Peer>) {
        let peers = self.peers.clone();
        let network = Arc::new(self.clone());
        
        tokio::spawn(async move {
            loop {
                let mut stream = peer.stream.lock().await;
                
                // Read message length
                let len = match stream.read_u32_le().await {
                    Ok(len) => len as usize,
                    Err(e) => {
                        error!("Failed to read message length from peer: {}", e);
                        break;
                    }
                };

                if len > MAX_MESSAGE_SIZE {
                    error!("Message too large from peer");
                    peer.update_score(PeerScoreCategory::InvalidMessage).await;
                    break;
                }

                // Read encrypted message
                let mut message_bytes = vec![0u8; len];
                if let Err(e) = stream.read_exact(&mut message_bytes).await {
                    error!("Failed to read message from peer: {}", e);
                    break;
                }
                drop(stream);

                // Decrypt and handle message
                let encrypted_message: EncryptedMessage = match bincode::deserialize(&message_bytes) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Failed to deserialize message: {}", e);
                        peer.update_score(PeerScoreCategory::InvalidMessage).await;
                        continue;
                    }
                };

                // Decrypt with AES-GCM
                let cipher = match Aes256Gcm::new_from_slice(&peer.shared_secret) {
                    Ok(cipher) => cipher,
                    Err(e) => {
                        error!("Failed to create cipher: {}", e);
                        continue;
                    }
                };

                let nonce_bytes = Self::generate_nonce();
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                let decrypted_data = match cipher.decrypt(nonce, encrypted_message.encrypted_data.as_ref()) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Failed to decrypt message: {}", e);
                        peer.update_score(PeerScoreCategory::InvalidMessage).await;
                        continue;
                    }
                };

                // Deserialize and handle message
                let message: Message = match bincode::deserialize(&decrypted_data) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Failed to deserialize decrypted message: {}", e);
                        peer.update_score(PeerScoreCategory::InvalidMessage).await;
                        continue;
                    }
                };

                // Update last seen time
                *peer.last_seen.lock().await = Instant::now();

                // Handle message
                if let Err(e) = Self::handle_message(network.clone(), peer.clone(), message).await {
                    error!("Failed to handle message from peer: {}", e);
                    peer.update_score(PeerScoreCategory::InvalidMessage).await;
                } else {
                    peer.update_score(PeerScoreCategory::ValidMessage).await;
                }

                // Check peer score and ban if needed
                let score = *peer.score.lock().await;
                if score < PEER_SCORE_THRESHOLD {
                    warn!("Banning peer {} due to low score: {}", peer.socket_addr, score);
                    peer.ban(Duration::from_secs(3600)).await; // 1 hour ban
                    break;
                }
            }

            // Connection lost or peer banned, remove peer
            let mut peers = peers.lock().await;
            peers.remove(&peer.address.hash);
            info!("Peer disconnected: {}", peer.socket_addr);
        });
    }

    /// Broadcast block to all peers
    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        let message = Message::Block(block);
        let peers = self.peers.lock().await;
        
        for peer in peers.values() {
            if let Err(e) = self.send_encrypted(peer, &message).await {
                error!("Failed to broadcast block to {}: {}", peer.socket_addr, e);
                peer.update_score(PeerScoreCategory::SlowResponse).await;
            } else {
                peer.update_score(PeerScoreCategory::SuccessfulBlockPropagation).await;
            }
        }
        Ok(())
    }

    /// Broadcast transaction to all peers
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<()> {
        let message = Message::Transaction(tx);
        let peers = self.peers.lock().await;
        
        for peer in peers.values() {
            if let Err(e) = self.send_encrypted(peer, &message).await {
                error!("Failed to broadcast transaction to {}: {}", peer.socket_addr, e);
                peer.update_score(PeerScoreCategory::SlowResponse).await;
            } else {
                peer.update_score(PeerScoreCategory::SuccessfulTxPropagation).await;
            }
        }
        Ok(())
    }

    /// Start block synchronization process
    pub async fn start_sync(&self) -> Result<()> {
        let chain = self.chain.lock().await;
        let current_height = chain.get_height() as u64;
        drop(chain);

        let sync_state = Arc::new(Mutex::new(SyncState::new(current_height)));
        
        // Find best peer for syncing
        let best_peer = self.find_sync_peers().await.into_iter().next();
        if let Some(peer) = best_peer.clone() {
            let mut state = sync_state.lock().await;
            state.best_peer = Some(peer.clone());
            
            let peer_status = peer.status.lock().await;
            state.target_height = peer_status.height;
            drop(peer_status);
            
            // Start sync process
            self.request_blocks(peer, sync_state.clone()).await?;
        }

        Ok(())
    }

    /// Request blocks from peer with timeout and retry logic
    async fn request_blocks(&self, peer: Arc<Peer>, sync_state: Arc<Mutex<SyncState>>) -> Result<()> {
        let mut state = sync_state.lock().await;
        
        // Check if we need to sync
        if state.current_height >= state.target_height {
            return Ok(());
        }

        // Calculate batch size based on network conditions
        let batch_size = if state.timeout_count > 0 {
            SYNC_BATCH_SIZE / (2_u32.pow(state.timeout_count)) as usize
        } else {
            SYNC_BATCH_SIZE
        };

        let start = state.current_height + 1;
        let end = (start + batch_size as u64 - 1).min(state.target_height);

        // Record pending request
        for height in start..=end {
            state.pending_requests.insert(height);
        }
        state.last_request = Instant::now();
        drop(state);

        // Send request
        self.send_encrypted(&peer, &Message::GetBlocks { start, end }).await?;

        // Spawn timeout handler
        let network = Arc::new(self.clone());
        let sync_state_clone = sync_state.clone();
        let peer_clone = peer.clone();
        
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(SYNC_REQUEST_TIMEOUT)).await;
            
            let mut state = sync_state_clone.lock().await;
            if !state.pending_requests.is_empty() {
                state.timeout_count += 1;
                if state.timeout_count > 3 {
                    // Try different peer after too many timeouts
                    state.best_peer = None;
                    state.reset();
                } else {
                    // Retry with same peer
                    state.reset();
                    drop(state);
                    let _ = network.request_blocks(peer_clone, sync_state_clone).await;
                }
            }
        });

        Ok(())
    }

    /// Process received blocks and handle forks
    async fn process_received_blocks(&self, blocks: Vec<Block>, peer: Arc<Peer>) -> Result<()> {
        let mut chain = self.chain.lock().await;
        
        for block in blocks {
            // Skip if we already have this block
            if block.index <= chain.get_height() {
                continue;
            }

            // Validate the block
            match chain.validate_block(&block) {
                Ok(result) => {
                    // Check for potential fork
                    if let Some(fork_point) = result.fork_point {
                        // Handle fork
                        if result.total_fees > chain.get_chain_work() {
                            // Better chain found, reorg
                            self.handle_chain_reorganization(&mut chain, fork_point, block.clone()).await?;
                        }
                    } else {
                        // Normal block addition
                        if let Err(e) = chain.add_block(block) {
                            warn!("Failed to add block: {:?}", e);
                            peer.update_score(PeerScoreCategory::InvalidBlock).await;
                            continue;
                        }
                    }
                },
                Err(BlockValidationError::BelowFinalizedHeight(_)) => {
                    // Ignore blocks below finalization
                    continue;
                },
                Err(e) => {
                    warn!("Invalid block from peer: {:?}", e);
                    peer.update_score(PeerScoreCategory::InvalidBlock).await;
                    continue;
                }
            }
        }

        Ok(())
    }

    /// Handle chain reorganization
    async fn handle_chain_reorganization(
        &self,
        chain: &mut Chain,
        fork_point: u64,
        new_block: Block,
    ) -> Result<()> {
        // Get the current chain tip
        let current_tip = chain.get_height();
        
        // Create backup of current chain state
        let backup_blocks = chain.get_blocks_range(fork_point, current_tip)?;
        
        // Revert chain to fork point
        chain.revert_to_height(fork_point)?;
        
        // Try to add new block
        if let Err(e) = chain.add_block(new_block) {
            // Restore backup if new chain is invalid
            for block in backup_blocks {
                chain.add_block(block)?;
            }
            return Err(anyhow!("Failed to add fork block: {:?}", e));
        }
        
        info!("Chain reorganization: fork_point={}, old_tip={}, new_tip={}", 
            fork_point, current_tip, chain.get_height());
        
        Ok(())
    }
} 