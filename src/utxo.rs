use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UtxoId {
    pub block_index: u64,
    pub tx_index: u32,
    pub output_index: u32,
}

impl UtxoId {
    pub fn new(block_index: u64, tx_index: u32, output_index: u32) -> Self {
        Self {
            block_index,
            tx_index,
            output_index,
        }
    }

    pub fn genesis(output_index: u32) -> Self {
        Self {
            block_index: 0,
            tx_index: 0,
            output_index,
        }
    }

    pub fn pending(tx_index: u32, output_index: u32) -> Self {
        Self {
            block_index: u64::MAX, // pending transactions use max value to distinguish
            tx_index,
            output_index,
        }
    }

    // UTXOのIDをハッシュ化して16進数文字列として返す
    pub fn to_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.block_index.to_be_bytes());
        hasher.update(self.tx_index.to_be_bytes());
        hasher.update(self.output_index.to_be_bytes());
        
        let result = hasher.finalize();
        hex::encode(result)
    }
}

impl fmt::Display for UtxoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.block_index == u64::MAX {
            write!(f, "pending-txoutput-{}-{}", self.tx_index, self.output_index)
        } else if self.block_index == 0 {
            write!(f, "genesis-utxo-{}", self.output_index)
        } else {
            write!(f, "utxo-{}-{}-{}", self.block_index, self.tx_index, self.output_index)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_id_display() {
        let genesis = UtxoId::genesis(0);
        assert_eq!(genesis.to_string(), "genesis-utxo-0");

        let pending = UtxoId::pending(1, 2);
        assert_eq!(pending.to_string(), "pending-txoutput-1-2");

        let normal = UtxoId::new(1, 2, 3);
        assert_eq!(normal.to_string(), "utxo-1-2-3");
    }

    #[test]
    fn test_utxo_id_hash() {
        let utxo = UtxoId::new(1, 2, 3);
        let hash = utxo.to_hash();
        assert_eq!(hash.len(), 64); // SHA-256は32バイト（64文字の16進数）
    }
} 