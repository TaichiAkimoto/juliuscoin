use super::traits::CryptoOperations;
use crate::error::Result;

pub struct DefaultCrypto;

impl CryptoOperations for DefaultCrypto {
    fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        // 現在の暗号実装をここに移動
        unimplemented!()
    }

    fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // 現在の署名実装をここに移動
        unimplemented!()
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        // 現在の検証実装をここに移動
        unimplemented!()
    }
} 