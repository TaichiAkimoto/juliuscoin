use serde::{Serialize, Deserialize};
use crate::crypto::{generate_dilithium_keypair, derive_address_from_pk, PQAddress};
use std::fs;

/// ウォレット構造体
#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub address_hash: Vec<u8>,
}

impl Wallet {
    /// 新規ウォレット作成
    pub fn new() -> Self {
        let (pk, sk) = generate_dilithium_keypair();
        let hash = derive_address_from_pk(&pk);
        Wallet {
            public_key: pk,
            secret_key: sk,
            address_hash: hash,
        }
    }

    /// ウォレットをファイルに保存
    pub fn save_to_file(&self, path: &str) {
        let data = bincode::serialize(&self).unwrap();
        fs::write(path, data).expect("Failed to write wallet file");
    }

    /// ファイルからウォレットをロード
    pub fn load_from_file(path: &str) -> Self {
        let data = fs::read(path).expect("Failed to read wallet file");
        bincode::deserialize(&data).expect("Failed to deserialize wallet")
    }

    #[allow(dead_code)]
    pub fn get_address(&self) -> PQAddress {
        PQAddress {
            public_key: self.public_key.clone(),
            hash: self.address_hash.clone(),
        }
    }
}
