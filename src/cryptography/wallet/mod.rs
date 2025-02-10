mod mnemonic;
mod storage;

use std::path::PathBuf;
use thiserror::Error;
use crate::cryptography::crypto::{generate_dilithium_keypair, PQAddress, derive_address_from_pk};
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use regex::Regex;

pub use mnemonic::{Mnemonic, EntropySize};
pub use storage::{WalletData, WalletStorage};

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Key error: {0}")]
    KeyError(String),
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Password error: {0}")]
    Password(String),
}

impl From<WalletError> for String {
    fn from(err: WalletError) -> Self {
        err.to_string()
    }
}

pub struct PasswordPolicy {
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_numbers: bool,
    require_special: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
        }
    }
}

impl PasswordPolicy {
    pub fn validate(&self, password: &str) -> Result<(), WalletError> {
        if password.len() < self.min_length {
            return Err(WalletError::Password(format!(
                "Password must be at least {} characters long",
                self.min_length
            )));
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(WalletError::Password(
                "Password must contain at least one uppercase letter".into()
            ));
        }

        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(WalletError::Password(
                "Password must contain at least one lowercase letter".into()
            ));
        }

        if self.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            return Err(WalletError::Password(
                "Password must contain at least one number".into()
            ));
        }

        if self.require_special {
            let special = Regex::new(r#"[!@#$%^&*(),.?:{}|<>]"#).unwrap();
            if !special.is_match(password) {
                return Err(WalletError::Password(
                    "Password must contain at least one special character".into()
                ));
            }
        }

        Ok(())
    }
}

pub struct Wallet {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub address_hash: Vec<u8>,
    mnemonic: Option<String>,
    #[allow(dead_code)]
    path: PathBuf,
    storage: WalletStorage,
    password_policy: PasswordPolicy,
}

impl Wallet {
    pub fn new() -> Result<Self, WalletError> {
        let keypair = generate_dilithium_keypair();
        let public_key = keypair.public.as_bytes().to_vec();
        let secret_key = keypair.secret.as_bytes().to_vec();
        let address_hash = derive_address_from_pk(&public_key);
        let path = PathBuf::from("wallet.dat");

        Ok(Self {
            public_key,
            secret_key,
            address_hash,
            mnemonic: None,
            path: path.clone(),
            storage: WalletStorage::new(path.to_str().unwrap()),
            password_policy: PasswordPolicy::default(),
        })
    }

    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, WalletError> {
        let seed = mnemonic.to_seed();
        let keypair = generate_dilithium_keypair();
        let public_key = keypair.public.as_bytes().to_vec();
        let secret_key = keypair.secret.as_bytes().to_vec();
        let address_hash = derive_address_from_pk(&public_key);
        let path = PathBuf::from("wallet.dat");

        Ok(Self {
            public_key,
            secret_key,
            address_hash,
            mnemonic: Some(mnemonic.as_str().to_string()),
            path: path.clone(),
            storage: WalletStorage::new(path.to_str().unwrap()),
            password_policy: PasswordPolicy::default(),
        })
    }

    pub fn set_password_policy(&mut self, policy: PasswordPolicy) {
        self.password_policy = policy;
    }

    pub fn save(&self) -> Result<(), WalletError> {
        self.storage.save(self)
    }

    pub fn save_encrypted(&self, password: &str) -> Result<(), WalletError> {
        // Validate password against policy
        self.password_policy.validate(password)?;

        // Generate a salt for PBKDF2
        let salt: [u8; 32] = rand::random();
        
        // Derive encryption key from password using PBKDF2
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            &salt,
            100_000, // High iteration count for security
            &mut key,
        );

        // Create cipher instance
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        // Generate a random nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Serialize wallet data
        let data = WalletData {
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
            address_hash: self.address_hash.clone(),
            mnemonic: self.mnemonic.clone(),
        };
        let serialized = bincode::serialize(&data)?;

        // Encrypt the serialized data
        let encrypted = cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        // Save salt, nonce, and encrypted data
        self.storage.save_encrypted(&salt, &nonce_bytes, &encrypted)
    }

    pub fn load(path: &str) -> Result<Self, WalletError> {
        WalletStorage::load(path)
    }

    pub fn load_encrypted(path: &str, password: &str) -> Result<Self, WalletError> {
        WalletStorage::load_encrypted(path, password)
    }

    pub fn get_mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    pub fn get_address(&self) -> PQAddress {
        PQAddress::new(&self.address_hash)
    }

    pub fn backup(&self, backup_path: &str) -> Result<(), WalletError> {
        use std::fs;
        
        // Create backup data structure
        let backup_data = WalletData {
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
            address_hash: self.address_hash.clone(),
            mnemonic: self.mnemonic.clone(),
        };

        // Serialize backup data
        let serialized = bincode::serialize(&backup_data)?;

        // Write to backup file
        fs::write(backup_path, serialized)?;

        Ok(())
    }

    pub fn restore_from_backup(backup_path: &str) -> Result<Self, WalletError> {
        let data = WalletStorage::read_wallet_data(backup_path)?;
        let path = PathBuf::from("wallet.dat");

        Ok(Self {
            public_key: data.public_key,
            secret_key: data.secret_key,
            address_hash: data.address_hash,
            mnemonic: data.mnemonic,
            path: path.clone(),
            storage: WalletStorage::new(path.to_str().unwrap()),
            password_policy: PasswordPolicy::default(),
        })
    }
} 