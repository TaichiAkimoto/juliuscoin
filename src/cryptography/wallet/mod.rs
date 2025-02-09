mod mnemonic;
mod storage;

use std::path::PathBuf;
use thiserror::Error;
use crate::crypto::{generate_dilithium_keypair, PQAddress, derive_address_from_pk};

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
    mnemonic: Option<Mnemonic>,
    storage: WalletStorage,
}

impl Wallet {
    pub fn new() -> Self {
        let mnemonic = Mnemonic::generate();
        let seed = mnemonic.to_seed();
        let (pk, sk) = generate_dilithium_keypair();
        let address_hash = derive_address_from_pk(&pk);

        Self {
            public_key: pk,
            secret_key: sk,
            address_hash,
            mnemonic: Some(mnemonic),
            storage: WalletStorage::new("wallet.bin"),
        }
    }

    pub fn from_mnemonic(phrase: &str) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::from_phrase(phrase)?;
        let seed = mnemonic.to_seed();
        let (pk, sk) = generate_dilithium_keypair();
        let address_hash = derive_address_from_pk(&pk);

        Ok(Self {
            public_key: pk,
            secret_key: sk,
            address_hash,
            mnemonic: Some(mnemonic),
            storage: WalletStorage::new("wallet.bin"),
        })
    }

    pub fn save(&self) -> Result<(), WalletError> {
        self.storage.save(self)
    }

    pub fn load(path: &str) -> Result<Self, WalletError> {
        WalletStorage::load(path)
    }

    pub fn get_mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_ref().map(|m| m.as_str())
    }

    pub fn get_address(&self) -> PQAddress {
        PQAddress {
            public_key: self.public_key.clone(),
            hash: self.address_hash.clone(),
        }
    }
} 