use std::fs;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use crate::cryptography::wallet::{Wallet, WalletError};

#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub address_hash: Vec<u8>,
    pub mnemonic: Option<String>,
}

pub struct WalletStorage {
    path: PathBuf,
}

impl WalletStorage {
    pub fn new(path: &str) -> Self {
        Self {
            path: PathBuf::from(path),
        }
    }

    pub fn save(&self, wallet: &Wallet) -> Result<(), WalletError> {
        let data = WalletData {
            public_key: wallet.public_key.clone(),
            secret_key: wallet.secret_key.clone(),
            address_hash: wallet.address_hash.clone(),
            mnemonic: wallet.get_mnemonic().map(String::from),
        };
        
        let serialized = bincode::serialize(&data)?;
        fs::write(&self.path, serialized)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Wallet, WalletError> {
        let data = WalletStorage::read_wallet_data(path)?;
        let path_buf = PathBuf::from(path);
        
        Ok(Wallet {
            public_key: data.public_key,
            secret_key: data.secret_key,
            address_hash: data.address_hash,
            mnemonic: data.mnemonic.map(|m| m.as_str().to_string()),
            path: path_buf.clone(),
            storage: WalletStorage::new(path),
        })
    }

    fn read_wallet_data(path: &str) -> Result<WalletData, WalletError> {
        let data = fs::read(path)?;
        let wallet_data: WalletData = bincode::deserialize(&data)?;
        Ok(wallet_data)
    }
} 