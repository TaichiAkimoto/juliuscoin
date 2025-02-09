use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use anyhow::Result;
use crate::chain::{Block};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use log::info;
use crate::crypto::{
    generate_kyber_keypair, kyber_encapsulate, kyber_decapsulate,
    PQAddress,
};
use message::Message;
use serde::{Serialize, Deserialize};

mod message;
pub use message::Message;

/// 暗号化されたP2Pメッセージ
#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender_address: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>,
}

/// P2Pピア情報
#[derive(Clone)]
struct Peer {
    address: PQAddress,
    shared_secret: Vec<u8>,
    stream: Arc<TcpStream>,
}

/// P2Pネットワーク
pub struct P2PNetwork {
    port: u16,
    peers: Arc<Mutex<HashMap<Vec<u8>, Peer>>>,
    keypair: (Vec<u8>, Vec<u8>), // Kyber (pk, sk)
}

impl P2PNetwork {
    pub fn new(port: u16) -> Self {
        let (pk, sk) = generate_kyber_keypair();
        Self {
            port,
            peers: Arc::new(Mutex::new(HashMap::new())),
            keypair: (pk, sk),
        }
    }

    /// ピアとの接続確立とキー交換
    async fn establish_connection(&self, stream: TcpStream, addr: &str) -> Result<()> {
        let stream = Arc::new(stream);
        
        // 1. 自分のKyber公開鍵を送信
        let mut writer = tokio::io::BufWriter::new(stream.clone());
        tokio::io::AsyncWriteExt::write_all(&mut writer, &self.keypair.0).await?;
        writer.flush().await?;

        // 2. 相手のKyber公開鍵を受信
        let mut reader = tokio::io::BufReader::new(stream.clone());
        let mut peer_pk = vec![0u8; self.keypair.0.len()];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut peer_pk).await?;

        // 3. 共有鍵の確立
        let (ciphertext, shared_secret) = kyber_encapsulate(&peer_pk);

        // 4. カプセル化した鍵を送信
        writer.write_all(&ciphertext).await?;
        writer.flush().await?;

        // 5. ピア情報を保存
        let peer = Peer {
            address: PQAddress {
                public_key: peer_pk.clone(),
                hash: crate::crypto::derive_address_from_pk(&peer_pk),
            },
            shared_secret,
            stream,
        };

        let mut peers = self.peers.lock().await;
        peers.insert(peer.address.hash.clone(), peer);

        info!("Established secure connection with peer: {}", addr);
        Ok(())
    }

    /// メッセージの暗号化と送信
    async fn send_encrypted(&self, peer: &Peer, message: &Message) -> Result<()> {
        // メッセージをシリアライズ
        let message_bytes = bincode::serialize(message)?;

        // AES-GCMで暗号化 (shared_secretを鍵として使用)
        use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Nonce}};
        let cipher = Aes256Gcm::new_from_slice(&peer.shared_secret)?;
        let nonce = Nonce::from_slice(&[0u8; 12]); // 実際の実装では適切なnonceを生成する
        let encrypted_data = cipher.encrypt(nonce, message_bytes.as_ref())?;

        // 暗号化メッセージを構築
        let encrypted_message = EncryptedMessage {
            sender_address: peer.address.hash.clone(),
            encrypted_data,
            kyber_ciphertext: vec![], // 既に共有鍵確立済みなので空
        };

        // 送信
        let mut writer = tokio::io::BufWriter::new(peer.stream.clone());
        let message_bytes = bincode::serialize(&encrypted_message)?;
        writer.write_all(&message_bytes).await?;
        writer.flush().await?;

        Ok(())
    }

    /// メッセージの受信と復号
    async fn receive_encrypted(&self, stream: &TcpStream) -> Result<Message> {
        let mut reader = tokio::io::BufReader::new(stream);
        let mut message_bytes = Vec::new();
        reader.read_to_end(&mut message_bytes).await?;

        let encrypted_message: EncryptedMessage = bincode::deserialize(&message_bytes)?;
        
        // ピアの共有鍵を取得
        let peers = self.peers.lock().await;
        let peer = peers.get(&encrypted_message.sender_address)
            .ok_or_else(|| anyhow::anyhow!("Unknown peer"))?;

        // AES-GCMで復号
        use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Nonce}};
        let cipher = Aes256Gcm::new_from_slice(&peer.shared_secret)?;
        let nonce = Nonce::from_slice(&[0u8; 12]); // 送信側と同じnonce
        let decrypted_data = cipher.decrypt(nonce, encrypted_message.encrypted_data.as_ref())?;

        // メッセージをデシリアライズ
        let message: Message = bincode::deserialize(&decrypted_data)?;
        Ok(message)
    }

    /// P2Pネットワークの起動
    pub async fn start(&self) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("P2P network listening on {}", addr);

        let (tx, mut rx) = mpsc::channel(32);
        let peers = self.peers.clone();

        // 受信ハンドラ
        tokio::spawn(async move {
            while let Some((stream, addr)) = rx.recv().await {
                let peer_addr = addr.to_string();
                if let Err(e) = Self::handle_peer(stream, peers.clone()).await {
                    info!("Error handling peer {}: {}", peer_addr, e);
                }
            }
        });

        // 接続待ち受け
        loop {
            let (stream, addr) = listener.accept().await?;
            info!("New peer connection from: {}", addr);
            tx.send((stream, addr)).await?;
        }
    }

    /// ピア接続のハンドリング
    async fn handle_peer(
        stream: TcpStream,
        peers: Arc<Mutex<HashMap<Vec<u8>, Peer>>>,
    ) -> Result<()> {
        // ここでピアとのメッセージ処理を実装
        Ok(())
    }

    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        // ブロックをすべてのピアにブロードキャスト
        for peer in self.peers.lock().await.values() {
            // ブロックをシリアライズして送信
        }
        Ok(())
    }
} 