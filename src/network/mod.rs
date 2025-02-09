use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use anyhow::Result;
use crate::chain::{Block};

mod message;
pub use message::Message;

pub struct P2PNetwork {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerConnection>>>,
    port: u16,
}

struct PeerConnection {
    stream: TcpStream,
}

impl P2PNetwork {
    pub fn new(port: u16) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            port,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        println!("P2Pネットワークを開始しました。ポート: {}", self.port);

        loop {
            let (socket, addr) = listener.accept().await?;
            println!("新しいピア接続: {}", addr);
            
            let peer = PeerConnection { stream: socket };
            self.peers.write().await.insert(addr, peer);
            
            // 新しいピアの接続を処理
            self.handle_peer(addr).await?;
        }
    }

    async fn handle_peer(&self, addr: SocketAddr) -> Result<()> {
        // ここでピアとの通信処理を実装
        // - ブロックの受信
        // - トランザクションの受信
        // - 検証
        // - ブロードキャスト
        Ok(())
    }

    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        // ブロックをすべてのピアにブロードキャスト
        for peer in self.peers.read().await.values() {
            // ブロックをシリアライズして送信
        }
        Ok(())
    }
} 