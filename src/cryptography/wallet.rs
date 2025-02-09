use bincode::{deserialize, serialize};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use sha2::{Sha256, Digest};
use crate::crypto::{
    generate_dilithium_keypair,
    PQAddress,
    derive_address_from_pk,
};
use serde::{Serialize, Deserialize};

const WORD_LIST: &str = include_str!("bip39_wordlist.txt");

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

/// ウォレットデータ
#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub address_hash: Vec<u8>,
    pub mnemonic: Option<String>,
}

/// ウォレット構造体
pub struct Wallet {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub address_hash: Vec<u8>,
    mnemonic: Option<String>,
    path: PathBuf,
}

impl Wallet {
    /// 新規ウォレット作成（ニーモニック生成付き）
    pub fn new() -> Self {
        // 乱数からニーモニックを生成
        let mut rng = rand::thread_rng();
        let entropy: [u8; 32] = rand::random();
        let mnemonic = Self::generate_mnemonic(&entropy);

        // ニーモニックからシード生成
        let seed = Self::seed_from_mnemonic(&mnemonic);

        // シードから量子耐性鍵ペアを生成
        let (pk, sk) = generate_dilithium_keypair();
        let address_hash = derive_address_from_pk(&pk);

        Self {
            public_key: pk,
            secret_key: sk,
            address_hash,
            mnemonic: Some(mnemonic),
            path: PathBuf::from("wallet.bin"),
        }
    }

    /// ニーモニックからウォレットを復元
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, WalletError> {
        // ニーモニックの検証
        if !Self::validate_mnemonic(mnemonic) {
            return Err(WalletError::InvalidMnemonic("Invalid mnemonic phrase".into()));
        }

        // シード生成
        let seed = Self::seed_from_mnemonic(mnemonic);

        // シードから鍵ペア生成
        let (pk, sk) = generate_dilithium_keypair();
        let address_hash = derive_address_from_pk(&pk);

        Ok(Self {
            public_key: pk,
            secret_key: sk,
            address_hash,
            mnemonic: Some(mnemonic.to_string()),
            path: PathBuf::from("wallet.bin"),
        })
    }

    /// ニーモニックの生成
    fn generate_mnemonic(entropy: &[u8]) -> String {
        let words: Vec<&str> = WORD_LIST.lines().collect();
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        let checksum = hasher.finalize();
        
        let mut indices = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0;
        
        // エントロピーとチェックサムから11ビットずつ取り出してワードインデックスを生成
        for &byte in entropy.iter().chain(&checksum[..1]) {
            buffer = (buffer << 8) | byte as u32;
            bits += 8;
            
            while bits >= 11 {
                bits -= 11;
                let index = (buffer >> bits) & 0x7FF;
                indices.push(index as usize);
                buffer &= (1 << bits) - 1;
            }
        }
        
        // インデックスをワードに変換
        indices.iter()
            .map(|&i| words[i])
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// ニーモニックの検証
    fn validate_mnemonic(mnemonic: &str) -> bool {
        let words: Vec<&str> = WORD_LIST.lines().collect();
        let mnemonic_words: Vec<&str> = mnemonic.split_whitespace().collect();
        
        // 単語数チェック (12, 15, 18, 21, 24のいずれか)
        if ![12, 15, 18, 21, 24].contains(&mnemonic_words.len()) {
            return false;
        }
        
        // 各単語が辞書に存在するかチェック
        for word in &mnemonic_words {
            if !words.contains(word) {
                return false;
            }
        }
        
        true
    }

    /// ニーモニックからシード生成
    fn seed_from_mnemonic(mnemonic: &str) -> Vec<u8> {
        use pbkdf2::pbkdf2_hmac;
        use hmac::Hmac;
        use sha2::Sha512;
        
        let salt = "mnemonic";
        let mut seed = vec![0u8; 64];
        
        pbkdf2_hmac::<Hmac<Sha512>>(
            mnemonic.as_bytes(),
            salt.as_bytes(),
            2048,
            &mut seed,
        );
        
        seed
    }

    /// ウォレットの保存
    pub fn save_to_file(&self, path: &str) -> Result<(), WalletError> {
        let data = WalletData {
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
            address_hash: self.address_hash.clone(),
            mnemonic: self.mnemonic.clone(),
        };
        
        let serialized = serialize(&data)?;
        fs::write(path, serialized)?;
        Ok(())
    }

    /// ウォレットの読み込み
    pub fn load_from_file(path: &str) -> Result<Self, WalletError> {
        let data = fs::read(path)?;
        let wallet_data: WalletData = deserialize(&data)?;
        
        Ok(Self {
            public_key: wallet_data.public_key,
            secret_key: wallet_data.secret_key,
            address_hash: wallet_data.address_hash,
            mnemonic: wallet_data.mnemonic,
            path: PathBuf::from(path),
        })
    }

    /// ニーモニックの取得
    pub fn get_mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// アドレス情報の取得
    pub fn get_address(&self) -> PQAddress {
        PQAddress {
            public_key: self.public_key.clone(),
            hash: self.address_hash.clone(),
        }
    }
}
