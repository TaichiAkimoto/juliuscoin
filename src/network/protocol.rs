use std::collections::HashMap;
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

use crate::blockchain::chain::{Block, Transaction, BlockChain, Chain};
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
            chain.height()
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
                let mut peers = peers.lock().await;
                
                // Remove disconnected peers
                peers.retain(|_, peer| {
                    let last_seen = peer.last_seen.try_lock()
                        .map(|guard| *guard)
                        .unwrap_or_else(|_| Instant::now());
                    Instant::now().duration_since(last_seen).as_secs() < HEARTBEAT_INTERVAL * 2
                });

                // Send heartbeat to remaining peers
                for peer in peers.values() {
                    if let Err(e) = network.send_heartbeat(peer).await {
                        error!("Failed to send heartbeat to {}: {}", peer.socket_addr, e);
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
                // Validate and process received block
                let mut chain = network.chain.lock().await;
                if chain.validate_block(&block).is_ok() {
                    if chain.add_block(block).is_ok() {
                        peer.update_score(PeerScoreCategory::SuccessfulBlockPropagation).await;
                    } else {
                        peer.update_score(PeerScoreCategory::InvalidBlock).await;
                    }
                } else {
                    peer.update_score(PeerScoreCategory::InvalidBlock).await;
                }
            }
            Message::GetBlocks { start, end } => {
                // Send requested blocks
                let chain = network.chain.lock().await;
                let mut blocks = Vec::new();
                
                for height in start..=end {
                    if let Some(block) = chain.get_block_by_height(height) {
                        blocks.push(block);
                        if blocks.len() >= MAX_BLOCKS_PER_REQUEST {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                network.send_encrypted(&peer, &Message::Blocks(blocks)).await?;
            }
            Message::Blocks(blocks) => {
                // Process received blocks
                let mut chain = network.chain.lock().await;
                for block in blocks {
                    if chain.validate_block(&block).is_ok() {
                        if chain.add_block(block).is_ok() {
                            peer.update_score(PeerScoreCategory::SuccessfulBlockPropagation).await;
                        } else {
                            peer.update_score(PeerScoreCategory::InvalidBlock).await;
                        }
                    } else {
                        peer.update_score(PeerScoreCategory::InvalidBlock).await;
                    }
                }
            }
            Message::GetBlocksAfter(height) => {
                // Send blocks after specified height
                let chain = network.chain.lock().await;
                let current_height = chain.height();
                let mut blocks = Vec::new();

                for h in (height + 1)..=current_height {
                    if let Some(block) = chain.get_block_by_height(h) {
                        blocks.push(block);
                        if blocks.len() >= MAX_BLOCKS_PER_REQUEST {
                            break;
                        }
                    }
                }

                network.send_encrypted(&peer, &Message::Blocks(blocks)).await?;
            }
            Message::Status { version, height, total_difficulty } => {
                peer.update_status(version, height, total_difficulty).await;

                // Check if we need to sync
                let our_height = {
                    let chain = network.chain.lock().await;
                    chain.height()
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
} 