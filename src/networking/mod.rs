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

// Added import for Dilithium PQ signature functions
use crate::cryptography::crypto::{generate_dilithium_keypair, DilithiumKeypair, detached_sign, verify_signature};

// Added handshake message for PQ handshake
#[derive(Serialize, Deserialize)]
struct HandshakeMessage {
    pub kyber_public_key: Vec<u8>,
    pub dilithium_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

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
    dilithium_public_key: Vec<u8>,
}

/// P2Pネットワーク
pub struct P2PNetwork {
    port: u16,
    peers: Arc<Mutex<HashMap<Vec<u8>, Peer>>>,
    keypair: (Vec<u8>, Vec<u8>), // Kyber (pk, sk)
    dilithium_keypair: DilithiumKeypair,
}

impl P2PNetwork {
    pub fn new(port: u16) -> Self {
        let (pk, sk) = generate_kyber_keypair();
        let dilithium_keypair = generate_dilithium_keypair();
        Self {
            port,
            peers: Arc::new(Mutex::new(HashMap::new())),
            keypair: (pk, sk),
            dilithium_keypair,
        }
    }

    /// ピアとの接続確立とキー交換
    async fn establish_connection(&self, stream: TcpStream, addr: &str) -> Result<()> {
        let stream = Arc::new(stream);
        let mut writer = tokio::io::BufWriter::new(stream.clone());

        // 1. Send handshake message with Kyber and Dilithium public keys, signed by our Dilithium secret key
        let mut sign_data = self.keypair.0.clone();
        sign_data.extend(self.dilithium_keypair.public_key.clone());
        let signature = detached_sign(&sign_data, &self.dilithium_keypair.secret_key)?;
        let handshake = HandshakeMessage {
             kyber_public_key: self.keypair.0.clone(),
             dilithium_public_key: self.dilithium_keypair.public_key.clone(),
             signature,
        };
        let handshake_bytes = bincode::serialize(&handshake)?;
        tokio::io::AsyncWriteExt::write_all(&mut writer, &handshake_bytes).await?;
        writer.flush().await?;

        // 2. Read peer's handshake message
        let mut reader = tokio::io::BufReader::new(stream.clone());
        let mut buf = vec![0u8; 512];
        let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await?;
        buf.truncate(n);
        let peer_handshake: HandshakeMessage = bincode::deserialize(&buf)?;

        // Verify the peer's handshake signature
        let mut peer_sign_data = peer_handshake.kyber_public_key.clone();
        peer_sign_data.extend(peer_handshake.dilithium_public_key.clone());
        if !verify_signature(&peer_sign_data, &peer_handshake.signature, &peer_handshake.dilithium_public_key) {
             return Err(anyhow::anyhow!("Peer handshake signature verification failed"));
        }

        // 3. Establish shared secret using peer's Kyber public key from the handshake
        let (ciphertext, shared_secret) = kyber_encapsulate(&peer_handshake.kyber_public_key);

        // 4. Send the encapsulated ciphertext
        writer.write_all(&ciphertext).await?;
        writer.flush().await?;

        // 5. Save the peer information using data from the handshake
        let peer = Peer {
             address: PQAddress {
                  public_key: peer_handshake.kyber_public_key.clone(),
                  hash: crate::crypto::derive_address_from_pk(&peer_handshake.kyber_public_key),
             },
             shared_secret,
             stream,
             dilithium_public_key: peer_handshake.dilithium_public_key,
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

        // Derive our own sender address from our Kyber public key
        let my_address = crate::crypto::derive_address_from_pk(&self.keypair.0);

        // Construct the encrypted message with our sender address
        let encrypted_message = EncryptedMessage {
            sender_address: my_address.clone(),
            encrypted_data,
            kyber_ciphertext: vec![], // Already shared secret established
        };

        // Serialize the encrypted message
        let encrypted_message_bytes = bincode::serialize(&encrypted_message)?;

        // Sign the encrypted message bytes using our Dilithium secret key
        let signature = detached_sign(&encrypted_message_bytes, &self.dilithium_keypair.secret_key)?;

        // Wrap the encrypted message in a SignedMessage for tamper-evidence
        let signed_message = message::SignedMessage {
            sender_address: my_address,
            data: encrypted_message_bytes,
            signature,
        };

        // Serialize and send the signed message
        let signed_message_bytes = bincode::serialize(&signed_message)?;
        let mut writer = tokio::io::BufWriter::new(peer.stream.clone());
        writer.write_all(&signed_message_bytes).await?;
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