use std::net::SocketAddr;

pub struct P2PNetwork {
    pub peers: Vec<SocketAddr>,
}

impl P2PNetwork {
    pub fn new() -> Self {
        P2PNetwork {
            peers: Vec::new(),
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr) {
        if !self.peers.contains(&addr) {
            self.peers.push(addr);
        }
    }
} 