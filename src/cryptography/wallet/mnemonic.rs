use sha2::{Sha256, Digest};
use crate::cryptography::wallet::WalletError;
use rand::RngCore;

const WORD_LIST: &str = include_str!("../../bip39_wordlist.txt");

pub struct Mnemonic {
    phrase: String,
    passphrase: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum EntropySize {
    Bits128 = 16, // 12 words
    Bits256 = 32, // 24 words
}

impl Mnemonic {
    pub fn generate() -> Self {
        Self::generate_with_size(EntropySize::Bits256)
    }

    pub fn generate_with_size(size: EntropySize) -> Self {
        let entropy_bytes = size as usize;
        let mut entropy = vec![0u8; entropy_bytes];
        rand::thread_rng().fill_bytes(&mut entropy);
        let phrase = Self::generate_phrase(&entropy);
        Self { phrase, passphrase: None }
    }

    pub fn from_phrase(phrase: &str) -> Result<Self, WalletError> {
        if Self::validate_phrase_with_checksum(phrase) {
            Ok(Self { phrase: phrase.to_string(), passphrase: None })
        } else {
            Err(WalletError::InvalidMnemonic("Invalid mnemonic phrase or checksum".into()))
        }
    }

    pub fn from_phrase_with_passphrase(phrase: &str, passphrase: &str) -> Result<Self, WalletError> {
        if Self::validate_phrase_with_checksum(phrase) {
            Ok(Self { 
                phrase: phrase.to_string(), 
                passphrase: Some(passphrase.to_string()) 
            })
        } else {
            Err(WalletError::InvalidMnemonic("Invalid mnemonic phrase or checksum".into()))
        }
    }

    pub fn set_passphrase(&mut self, passphrase: &str) {
        self.passphrase = Some(passphrase.to_string());
    }

    pub fn clear_passphrase(&mut self) {
        self.passphrase = None;
    }

    fn generate_phrase(entropy: &[u8]) -> String {
        let words: Vec<&str> = WORD_LIST.lines().collect();
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        let checksum = hasher.finalize();
        
        let checksum_bits = (entropy.len() * 8) / 32;
        let mut indices = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0;
        
        for (i, &byte) in entropy.iter().enumerate() {
            buffer = (buffer << 8) | byte as u32;
            bits += 8;
            
            while bits >= 11 && indices.len() < entropy.len() * 8 / 11 {
                bits -= 11;
                let index = (buffer >> bits) & 0x7FF;
                indices.push(index as usize);
                buffer &= (1 << bits) - 1;
            }

            if i == entropy.len() - 1 {
                let checksum_byte = checksum[0];
                buffer = (buffer << checksum_bits) | ((checksum_byte >> (8 - checksum_bits)) as u32);
                bits += checksum_bits;

                while bits >= 11 {
                    bits -= 11;
                    let index = (buffer >> bits) & 0x7FF;
                    indices.push(index as usize);
                    buffer &= (1 << bits) - 1;
                }
            }
        }
        
        indices.iter()
            .map(|&i| words[i])
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn validate_phrase_with_checksum(phrase: &str) -> bool {
        let words: Vec<&str> = WORD_LIST.lines().collect();
        let phrase_words: Vec<&str> = phrase.split_whitespace().collect();
        
        // Check word count
        if ![12, 15, 18, 21, 24].contains(&phrase_words.len()) {
            return false;
        }
        
        // Validate all words exist in wordlist and get their indices
        let mut indices = Vec::new();
        for word in &phrase_words {
            if let Some(index) = words.iter().position(|&w| w == *word) {
                indices.push(index);
            } else {
                return false;
            }
        }
        
        // Convert indices back to entropy and verify checksum
        let mut entropy = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0;
        
        for &index in &indices {
            buffer = (buffer << 11) | index as u32;
            bits += 11;
            
            while bits >= 8 {
                bits -= 8;
                entropy.push((buffer >> bits) as u8);
                buffer &= (1 << bits) - 1;
            }
        }
        
        // Remove checksum bits from entropy
        let checksum_bits = entropy.len() / 4;
        entropy.truncate(entropy.len() - (checksum_bits + 7) / 8);
        
        // Calculate checksum
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        let checksum = hasher.finalize();
        
        // Verify checksum
        let mask = (1 << checksum_bits) - 1;
        let calculated = (checksum[0] >> (8 - checksum_bits)) as u32;
        let actual = buffer & mask;
        
        calculated == actual
    }

    pub fn to_seed(&self) -> Vec<u8> {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;
        
        let salt = match &self.passphrase {
            Some(pass) => format!("mnemonic{}", pass),
            None => "mnemonic".to_string(),
        };
        
        let mut seed = vec![0u8; 64];
        pbkdf2_hmac::<Sha512>(
            self.phrase.as_bytes(),
            salt.as_bytes(),
            2048,
            &mut seed
        );
        seed
    }

    pub fn as_str(&self) -> &str {
        &self.phrase
    }

    pub fn word_count(&self) -> usize {
        self.phrase.split_whitespace().count()
    }

    pub fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }
} 