use super::traits::{CryptoOperations, Result};
use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium5::{PublicKey, SecretKey, keypair, detached_sign, verify_detached_signature};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature};

pub struct DefaultCrypto;

impl CryptoOperations for DefaultCrypto {
    fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let (pk, sk) = keypair();
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk = SecretKey::from_bytes(private_key)?;
        let signature = detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let pk = PublicKey::from_bytes(public_key)?;
        let sig = pqcrypto_dilithium::dilithium5::DetachedSignature::from_bytes(signature)?;
        Ok(verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PQAddress {
    pub hash: Vec<u8>,
}

impl PQAddress {
    pub fn new(hash: &[u8]) -> Self {
        Self { hash: hash.to_vec() }
    }

    pub fn from_string(s: &str) -> std::result::Result<Self, String> {
        Ok(Self { hash: s.as_bytes().to_vec() })
    }
}

pub struct DilithiumKeypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

pub fn generate_dilithium_keypair() -> DilithiumKeypair {
    let (pk, sk) = keypair();
    DilithiumKeypair {
        public: pk,
        secret: sk,
    }
}

pub fn derive_address_from_pk(pk: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pk);
    hasher.finalize().to_vec()
}

pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if let Ok(pk) = PublicKey::from_bytes(public_key) {
        verify_detached_signature(signature, message, &pk).is_ok()
    } else {
        false
    }
} 