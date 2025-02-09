use std::time::Duration;
use serde::Serialize;
use log::info;

/// 暗号操作のサイズ統計
#[derive(Debug, Serialize)]
pub struct CryptoMetrics {
    // Dilithium関連
    pub dilithium_pubkey_size: usize,
    pub dilithium_secret_key_size: usize,
    pub dilithium_signature_size: usize,
    
    // Kyber関連
    pub kyber_pubkey_size: usize,
    pub kyber_secret_key_size: usize,
    pub kyber_ciphertext_size: usize,
    
    // パフォーマンス計測
    pub avg_sign_time: Duration,
    pub avg_verify_time: Duration,
    pub total_operations: u64,
}

impl CryptoMetrics {
    pub fn new() -> Self {
        Self {
            dilithium_pubkey_size: 0,
            dilithium_secret_key_size: 0,
            dilithium_signature_size: 0,
            kyber_pubkey_size: 0,
            kyber_secret_key_size: 0,
            kyber_ciphertext_size: 0,
            avg_sign_time: Duration::new(0, 0),
            avg_verify_time: Duration::new(0, 0),
            total_operations: 0,
        }
    }

    pub fn record_key_sizes(&mut self, pk: &[u8], sk: &[u8]) {
        self.dilithium_pubkey_size = pk.len();
        self.dilithium_secret_key_size = sk.len();
    }

    pub fn record_signature_size(&mut self, sig: &[u8]) {
        self.dilithium_signature_size = sig.len();
    }

    pub fn record_operation_time(&mut self, is_signing: bool, duration: Duration) {
        self.total_operations += 1;
        if is_signing {
            let total_nanos = self.avg_sign_time.as_nanos()
                .saturating_mul((self.total_operations - 1) as u128)
                .saturating_add(duration.as_nanos());
            self.avg_sign_time = Duration::from_nanos((total_nanos / (self.total_operations as u128)) as u64);
        } else {
            let total_nanos = self.avg_verify_time.as_nanos()
                .saturating_mul((self.total_operations - 1) as u128)
                .saturating_add(duration.as_nanos());
            self.avg_verify_time = Duration::from_nanos((total_nanos / (self.total_operations as u128)) as u64);
        }
    }

    pub fn print_stats(&self) {
        info!("=== 量子耐性暗号メトリクス ===");
        info!("Dilithium公開鍵サイズ: {} bytes", self.dilithium_pubkey_size);
        info!("Dilithium秘密鍵サイズ: {} bytes", self.dilithium_secret_key_size);
        info!("Dilithium署名サイズ: {} bytes", self.dilithium_signature_size);
        info!("平均署名時間: {:?}", self.avg_sign_time);
        info!("平均検証時間: {:?}", self.avg_verify_time);
        info!("総操作回数: {}", self.total_operations);
        
        // ECDSAとの比較を表示
        info!("\n=== ECDSA比較 ===");
        info!("ECDSA公開鍵サイズ: 33 bytes");
        info!("ECDSA署名サイズ: 71-72 bytes");
        let size_ratio = self.dilithium_signature_size as f64 / 72.0;
        info!("Dilithium/ECDSA署名サイズ比: {:.1}倍", size_ratio);
    }
}

/// ブロックサイズとトランザクション統計
#[derive(Debug, Serialize)]
pub struct BlockMetrics {
    pub total_block_size: usize,
    pub signature_data_size: usize,
    pub transaction_data_size: usize,
    pub header_size: usize,
    pub transaction_count: usize,
}

impl BlockMetrics {
    pub fn calculate_sizes(block_data: &[u8], signatures_data: &[u8]) -> Self {
        Self {
            total_block_size: block_data.len(),
            signature_data_size: signatures_data.len(),
            transaction_data_size: block_data.len() - signatures_data.len(),
            header_size: 80, // 固定ヘッダーサイズ（例）
            transaction_count: 0, // トランザクション数は別途カウント
        }
    }

    pub fn print_stats(&self) {
        info!("=== ブロックメトリクス ===");
        info!("総ブロックサイズ: {} KB", self.total_block_size / 1024);
        info!("署名データ比率: {:.1}%", 
            (self.signature_data_size as f64 / self.total_block_size as f64) * 100.0);
        info!("トランザクションデータ比率: {:.1}%",
            (self.transaction_data_size as f64 / self.total_block_size as f64) * 100.0);
    }
} 