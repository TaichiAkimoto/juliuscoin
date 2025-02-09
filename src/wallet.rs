use bincode::{deserialize, serialize};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Key error: {0}")]
    KeyError(String),
}

/// ウォレット構造体
pub struct Wallet {
    keypair: Keypair,
    wallet_path: PathBuf,
}

impl Wallet {
    /// 新規ウォレット作成
    pub fn new(wallet_path: PathBuf) -> Result<Self, WalletError> {
        if wallet_path.exists() {
            // 既存のウォレットを読み込む
            let data = fs::read(&wallet_path)?;
            let keypair: Keypair = deserialize(&data)?;
            Ok(Self {
                keypair,
                wallet_path,
            })
        } else {
            // 新しいウォレットを作成
            let mut rng = rand::thread_rng();
            let keypair = Keypair::generate(&mut rng);
            let wallet = Self {
                keypair,
                wallet_path,
            };
            wallet.save()?;
            Ok(wallet)
        }
    }

    /// ウォレットをファイルに保存
    pub fn save(&self) -> Result<(), WalletError> {
        let data = serialize(&self.keypair)?;
        fs::write(&self.wallet_path, data)?;
        Ok(())
    }

    /// ファイルからウォレットをロード
    pub fn load_from_file(path: &str) -> Self {
        let data = fs::read(path).expect("Failed to read wallet file");
        bincode::deserialize(&data).expect("Failed to deserialize wallet")
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public
    }

    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.keypair.sign(message)
    }
}
