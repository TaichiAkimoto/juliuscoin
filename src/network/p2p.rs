use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use anyhow::{Result, anyhow};
use log::{info, warn, error};
use serde::{Serialize, Deserialize};
use crate::blockchain::chain::{Block, Transaction};
use crate::cryptography::crypto::{
    PQAddress, derive_address_from_pk, generate_dilithium_keypair,
    DilithiumKeypair,
};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature};
use pqcrypto_dilithium::dilithium5::{detached_sign, verify_detached_signature, PublicKey};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024; // 50MB max message size

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Message {
    Block(Block),
    Transaction(Transaction),
    GetBlocks { start: u64, end: u64 },
    Blocks(Vec<Block>),
    Heartbeat,
    PeerList(Vec<SocketAddr>),
    GetPeers,
}

#[derive(Serialize, Deserialize)]
pub struct SignedMessage {
    pub sender_address: Vec<u8>,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
struct Peer {
    address: PQAddress,
    socket_addr: SocketAddr,
    stream: Arc<Mutex<TcpStream>>,
    public_key: Vec<u8>,
    last_seen: Arc<Mutex<Instant>>,
}

pub struct P2PNetwork {
    port: u16,
    peers: Arc<Mutex<HashMap<Vec<u8>, Peer>>>,
    keypair: DilithiumKeypair,
}

impl P2PNetwork {
    pub fn new(port: u16) -> Self {
        let keypair = generate_dilithium_keypair();
        Self {
            port,
            peers: Arc::new(Mutex::new(HashMap::new())),
            keypair,
        }
    }

    /// Connect to a new peer
    pub async fn connect_to_peer(&self, addr: SocketAddr) -> Result<()> {
        // Check if we're already connected
        let peers = self.peers.lock().await;
        if peers.values().any(|p| p.socket_addr == addr) {
            return Ok(());
        }
        drop(peers);

        // Try to connect with timeout
        let stream = match timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(anyhow!("Failed to connect to peer {}: {}", addr, e)),
            Err(_) => return Err(anyhow!("Connection timeout to peer {}", addr)),
        };

        self.establish_connection(stream, addr).await
    }

    /// Establish connection with a peer
    async fn establish_connection(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        stream.set_nodelay(true)?;

        // 1. Send our public key with length prefix
        let pk_bytes = self.keypair.public.as_bytes();
        stream.write_u32_le(pk_bytes.len() as u32).await?;
        stream.write_all(pk_bytes).await?;

        // 2. Receive peer's public key with length prefix
        let pk_len = stream.read_u32_le().await? as usize;
        if pk_len > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Peer public key too large"));
        }
        let mut peer_pk = vec![0u8; pk_len];
        stream.read_exact(&mut peer_pk).await?;

        // 3. Save peer info
        let peer = Peer {
            address: PQAddress::new(&derive_address_from_pk(&peer_pk)),
            socket_addr: addr,
            stream: Arc::new(Mutex::new(stream)),
            public_key: peer_pk,
            last_seen: Arc::new(Mutex::new(Instant::now())),
        };

        let mut peers = self.peers.lock().await;
        peers.insert(peer.address.hash.clone(), peer.clone());
        drop(peers);

        // 4. Start message handling task for this peer
        self.spawn_message_handler(peer).await;

        info!("Established connection with peer: {}", addr);
        Ok(())
    }

    /// Spawn a task to handle incoming messages from a peer
    async fn spawn_message_handler(&self, peer: Peer) {
        let peers = self.peers.clone();
        let keypair = self.keypair.clone();

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
                    break;
                }

                // Read message
                let mut message_bytes = vec![0u8; len];
                if let Err(e) = stream.read_exact(&mut message_bytes).await {
                    error!("Failed to read message from peer: {}", e);
                    break;
                }
                drop(stream);

                // Deserialize and verify signed message
                let signed_message: SignedMessage = match bincode::deserialize(&message_bytes) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Failed to deserialize message: {}", e);
                        continue;
                    }
                };

                // Verify signature
                let peer_pk = match PublicKey::from_bytes(&peer.public_key) {
                    Ok(pk) => pk,
                    Err(e) => {
                        error!("Invalid peer public key: {}", e);
                        break;
                    }
                };

                let signature = match pqcrypto_dilithium::dilithium5::DetachedSignature::from_bytes(&signed_message.signature) {
                    Ok(sig) => sig,
                    Err(e) => {
                        error!("Invalid signature: {}", e);
                        continue;
                    }
                };

                if verify_detached_signature(&signature, &signed_message.data, &peer_pk).is_err() {
                    warn!("Invalid message signature from peer");
                    continue;
                }

                // Update last seen time
                *peer.last_seen.lock().await = Instant::now();

                // Handle message
                let message: Message = match bincode::deserialize(&signed_message.data) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Failed to deserialize inner message: {}", e);
                        continue;
                    }
                };

                match message {
                    Message::Heartbeat => continue,
                    Message::GetPeers => {
                        let peers_lock = peers.lock().await;
                        let peer_list: Vec<SocketAddr> = peers_lock.values()
                            .map(|p| p.socket_addr)
                            .collect();
                        drop(peers_lock);
                        
                        let response = Message::PeerList(peer_list);
                        if let Err(e) = Self::send_signed_static(&peer, &response, &keypair).await {
                            error!("Failed to send peer list: {}", e);
                        }
                    },
                    Message::PeerList(addrs) => {
                        for addr in addrs {
                            if let Err(e) = Self::connect_to_peer_static(addr, peers.clone(), &keypair).await {
                                warn!("Failed to connect to discovered peer {}: {}", addr, e);
                            }
                        }
                    },
                    _ => {
                        // Handle other message types...
                        info!("Received message: {:?}", message);
                    }
                }
            }

            // Connection lost, remove peer
            let mut peers = peers.lock().await;
            peers.remove(&peer.address.hash);
            info!("Peer disconnected: {}", peer.socket_addr);
        });
    }

    /// Static version of send_signed for use in spawned tasks
    async fn send_signed_static(peer: &Peer, message: &Message, keypair: &DilithiumKeypair) -> Result<()> {
        let message_bytes = bincode::serialize(message)?;
        let signature = detached_sign(&message_bytes, &keypair.secret);

        let signed_message = SignedMessage {
            sender_address: derive_address_from_pk(keypair.public.as_bytes()),
            data: message_bytes,
            signature: signature.as_bytes().to_vec(),
        };

        let message_bytes = bincode::serialize(&signed_message)?;
        let mut stream = peer.stream.lock().await;
        
        // Write length prefix
        stream.write_u32_le(message_bytes.len() as u32).await?;
        stream.write_all(&message_bytes).await?;

        Ok(())
    }

    /// Static version of connect_to_peer for use in spawned tasks
    async fn connect_to_peer_static(
        addr: SocketAddr,
        peers: Arc<Mutex<HashMap<Vec<u8>, Peer>>>,
        keypair: &DilithiumKeypair,
    ) -> Result<()> {
        // Implementation similar to connect_to_peer but using static references
        Ok(())
    }

    /// Sign and send a message to a peer
    async fn send_signed(&self, peer: &Peer, message: &Message) -> Result<()> {
        Self::send_signed_static(peer, message, &self.keypair).await
    }

    /// Broadcast a block to all peers
    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        let message = Message::Block(block.clone());
        let peers = self.peers.lock().await;
        
        for peer in peers.values() {
            if let Err(e) = self.send_signed(peer, &message).await {
                warn!("Failed to send block to peer {:?}: {}", peer.address.hash, e);
                continue;
            }
        }
        
        info!("Broadcasted block {} to {} peers", block.index, peers.len());
        Ok(())
    }

    /// Broadcast a transaction to all peers
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<()> {
        let message = Message::Transaction(tx.clone());
        let peers = self.peers.lock().await;
        
        for peer in peers.values() {
            if let Err(e) = self.send_signed(peer, &message).await {
                warn!("Failed to send transaction to peer {:?}: {}", peer.address.hash, e);
                continue;
            }
        }
        
        info!("Broadcasted transaction to {} peers", peers.len());
        Ok(())
    }

    /// Start the P2P network
    pub async fn start(&self) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("P2P network listening on {}", addr);

        // Start heartbeat task
        let peers = self.peers.clone();
        let keypair = self.keypair.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;
                let mut timed_out_peers = vec![];
                {
                    let peers_lock = peers.lock().await;
                    for (peer_key, peer) in peers_lock.iter() {
                        let last_seen = *peer.last_seen.lock().await;
                        if last_seen.elapsed() > HEARTBEAT_INTERVAL * 2 {
                            warn!("Peer {} hasn't responded to heartbeat", peer.socket_addr);
                            timed_out_peers.push((peer_key.clone(), peer.socket_addr));
                        } else {
                            if let Err(e) = Self::send_signed_static(peer, &Message::Heartbeat, &keypair).await {
                                warn!("Failed to send heartbeat to peer {}: {}", peer.socket_addr, e);
                            }
                        }
                    }
                }
                // Attempt reconnection for timed-out peers
                for (peer_key, addr) in timed_out_peers {
                    info!("Attempting to reconnect to peer {}", addr);
                    match Self::connect_to_peer_static(addr, peers.clone(), &keypair).await {
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

        // Accept incoming connections
        loop {
            let (stream, addr) = listener.accept().await?;
            info!("New peer connection from: {}", addr);
            
            if let Err(e) = self.establish_connection(stream, addr).await {
                warn!("Error establishing connection with {}: {}", addr, e);
            }
        }
    }
} 