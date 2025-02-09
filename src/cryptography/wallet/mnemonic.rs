use sha2::{Sha256, Digest};
use crate::cryptography::wallet::WalletError;

const WORD_LIST: &str = include_str!("../../bip39_wordlist.txt");

pub struct Mnemonic {
    phrase: String,
}

impl Mnemonic {
    pub fn generate() -> Self {
        let entropy: [u8; 32] = rand::random();
        let phrase = Self::generate_phrase(&entropy);
        Self { phrase }
    }

    pub fn from_phrase(phrase: &str) -> Result<Self, WalletError> {
        if Self::validate_phrase(phrase) {
            Ok(Self { phrase: phrase.to_string() })
        } else {
            Err(WalletError::InvalidMnemonic("Invalid mnemonic phrase".into()))
        }
    }

    fn generate_phrase(entropy: &[u8]) -> String {
        let words: Vec<&str> = WORD_LIST.lines().collect();
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        let checksum = hasher.finalize();
        
        let mut indices = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0;
        
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
        
        indices.iter()
            .map(|&i| words[i])
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn validate_phrase(phrase: &str) -> bool {
        let words: Vec<&str> = WORD_LIST.lines().collect();
        let phrase_words: Vec<&str> = phrase.split_whitespace().collect();
        
        if ![12, 15, 18, 21, 24].contains(&phrase_words.len()) {
            return false;
        }
        
        phrase_words.iter().all(|word| words.contains(word))
    }

    pub fn to_seed(&self) -> Vec<u8> {
        use pbkdf2::{pbkdf2_hmac, Pbkdf2};
        use sha2::Sha512;
        
        let salt = b"mnemonic";
        let mut seed = vec![0u8; 64];
        pbkdf2_hmac::<Sha512>(
            self.phrase.as_bytes(),
            salt,
            2048,
            &mut seed
        );
        seed
    }

    pub fn as_str(&self) -> &str {
        &self.phrase
    }
} 