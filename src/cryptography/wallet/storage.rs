use std::fs;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use crate::cryptography::wallet::{Wallet, WalletError, PasswordPolicy};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub address_hash: Vec<u8>,
    pub mnemonic: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedWalletData {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    encrypted_data: Vec<u8>,
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

    pub fn save_encrypted(&self, salt: &[u8], nonce: &[u8], encrypted_data: &[u8]) -> Result<(), WalletError> {
        let encrypted_wallet = EncryptedWalletData {
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            encrypted_data: encrypted_data.to_vec(),
        };
        
        let serialized = bincode::serialize(&encrypted_wallet)?;
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
            mnemonic: data.mnemonic,
            path: path_buf.clone(),
            storage: WalletStorage::new(path),
            password_policy: PasswordPolicy::default(),
        })
    }

    pub fn load_encrypted(path: &str, password: &str) -> Result<Wallet, WalletError> {
        let file_data = fs::read(path)?;
        let encrypted_wallet: EncryptedWalletData = bincode::deserialize(&file_data)?;
        
        // Derive encryption key from password using PBKDF2
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            &encrypted_wallet.salt,
            100_000,
            &mut key,
        );

        // Create cipher instance
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        // Create nonce
        let nonce = Nonce::from_slice(&encrypted_wallet.nonce);

        // Decrypt the data
        let decrypted = cipher
            .decrypt(nonce, encrypted_wallet.encrypted_data.as_ref())
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        // Deserialize the decrypted data
        let wallet_data: WalletData = bincode::deserialize(&decrypted)?;
        let path_buf = PathBuf::from(path);

        Ok(Wallet {
            public_key: wallet_data.public_key,
            secret_key: wallet_data.secret_key,
            address_hash: wallet_data.address_hash,
            mnemonic: wallet_data.mnemonic,
            path: path_buf.clone(),
            storage: WalletStorage::new(path),
            password_policy: PasswordPolicy::default(),
        })
    }

    pub fn read_wallet_data(path: &str) -> Result<WalletData, WalletError> {
        let data = fs::read(path)?;
        let wallet_data: WalletData = bincode::deserialize(&data)?;
        Ok(wallet_data)
    }
} 