pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub trait CryptoOperations {
    fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)>;
    fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool>;
} 