use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium_keypair, sign as dilithium_sign, open as dilithium_open,
    PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
    SignedMessage,
};
use pqcrypto_kyber::kyber1024::{
    keypair as kyber_keypair, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey,
    encapsulate, decapsulate, Ciphertext,
};
use pqcrypto_traits::sign::{
    PublicKey as DilithiumPublicKeyTrait, 
    SecretKey as DilithiumSecretKeyTrait,
    SignedMessage as SignedMessageTrait,
};
use pqcrypto_traits::kem::{
    PublicKey as KyberPublicKeyTrait, 
    SecretKey as KyberSecretKeyTrait, 
    SharedSecret, 
    Ciphertext as KyberCiphertextTrait
};

use serde::{Deserialize, Serialize};

/// Dilithium2の秘密鍵と公開鍵を生成する
pub fn generate_dilithium_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium_keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Dilithiumで署名を作成する
pub fn sign_message(message: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
    let signed = dilithium_sign(message, &DilithiumSecretKey::from_bytes(sk_bytes).unwrap());
    SignedMessageTrait::as_bytes(&signed).to_vec()
}

/// Dilithiumで署名を検証する
pub fn verify_signature(message: &[u8], signature: &[u8], pk_bytes: &[u8]) -> bool {
    let signed_message = SignedMessage::from_bytes(signature).unwrap();
    let opened = dilithium_open(
        &signed_message,
        &DilithiumPublicKey::from_bytes(pk_bytes).unwrap()
    );
    opened.map(|m| m == message).unwrap_or(false)
}

/// Kyber1024の鍵ペア生成
#[allow(dead_code)]
pub fn generate_kyber_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kyber_keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Kyberを使って鍵共有（カプセル化）
#[allow(dead_code)]
pub fn kyber_encapsulate(pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (ciphertext, shared_secret) = encapsulate(&KyberPublicKey::from_bytes(pk_bytes).unwrap());
    (ciphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec())
}

/// Kyberを使って鍵共有（復号・デカプセル化）
#[allow(dead_code)]
pub fn kyber_decapsulate(ct_bytes: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
    let sk = KyberSecretKey::from_bytes(sk_bytes).unwrap();
    let ct = Ciphertext::from_bytes(ct_bytes).unwrap();
    let secret = decapsulate(&ct, &sk);
    secret.as_bytes().to_vec()
}

/// Dilithium公開鍵 & アドレスとして使うハッシュ
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PQAddress {
    pub public_key: Vec<u8>, // Dilithium PublicKey
    pub hash: Vec<u8>,       // 公開鍵をハッシュ化したもの
}

use sha2::{Sha256, Digest};

// シンプルにSha256で公開鍵をハッシュ化し、アドレスっぽく扱う（MVP用）
pub fn derive_address_from_pk(pk: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pk);
    hasher.finalize().to_vec()
}
