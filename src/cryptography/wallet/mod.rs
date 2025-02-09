mod mnemonic;
mod storage;

use std::path::PathBuf;
use thiserror::Error;
use crate::cryptography::crypto::{generate_dilithium_keypair, PQAddress, derive_address_from_pk};
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use bincode::{deserialize, serialize};
use ed25519_dalek::v3::{Keypair, PublicKey, SecretKey};
use std::fs;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

pub use mnemonic::Mnemonic;
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
}

pub struct Wallet {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub address_hash: Vec<u8>,
    mnemonic: Option<String>,
    path: PathBuf,
    storage: WalletStorage,
}

impl Wallet {
    pub fn new() -> Self {
        let keypair = generate_dilithium_keypair();
        let public_key = keypair.public.as_bytes().to_vec();
        let secret_key = keypair.secret.as_bytes().to_vec();
        let address_hash = derive_address_from_pk(&public_key);
        let path = PathBuf::from("wallet.dat");

        Self {
            public_key,
            secret_key,
            address_hash,
            mnemonic: None,
            path: path.clone(),
            storage: WalletStorage::new(path.to_str().unwrap()),
        }
    }

    pub fn from_mnemonic(phrase: &str) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::from_phrase(phrase)?;
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
        })
    }

    pub fn save(&self) -> Result<(), WalletError> {
        self.storage.save(self)
    }

    pub fn load(path: &str) -> Result<Self, WalletError> {
        WalletStorage::load(path)
    }

    pub fn get_mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    pub fn get_address(&self) -> PQAddress {
        PQAddress::new(&self.address_hash)
    }
} 