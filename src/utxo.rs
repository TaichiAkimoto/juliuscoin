use sha2::{Digest, Sha256};
use std::fmt;
use vrf::{VRF, ECVRF};
use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UtxoId {
    pub block_index: u64,
    pub tx_index: u32,
    pub output_index: u32,
}

impl UtxoId {
    pub fn new(block_index: u64, tx_index: u32, output_index: u32) -> Self {
        Self {
            block_index,
            tx_index,
            output_index,
        }
    }

    pub fn genesis(output_index: u32) -> Self {
        Self {
            block_index: 0,
            tx_index: 0,
            output_index,
        }
    }

    pub fn pending(tx_index: u32, output_index: u32) -> Self {
        Self {
            block_index: u64::MAX, // pending transactions use max value to distinguish
            tx_index,
            output_index,
        }
    }

    // UTXOのIDをハッシュ化して16進数文字列として返す
    pub fn to_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.block_index.to_be_bytes());
        hasher.update(self.tx_index.to_be_bytes());
        hasher.update(self.output_index.to_be_bytes());
        
        let result = hasher.finalize();
        hex::encode(result)
    }
}

impl fmt::Display for UtxoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.block_index == u64::MAX {
            write!(f, "pending-txoutput-{}-{}", self.tx_index, self.output_index)
        } else if self.block_index == 0 {
            write!(f, "genesis-utxo-{}", self.output_index)
        } else {
            write!(f, "utxo-{}-{}-{}", self.block_index, self.tx_index, self.output_index)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_id_display() {
        let genesis = UtxoId::genesis(0);
        assert_eq!(genesis.to_string(), "genesis-utxo-0");

        let pending = UtxoId::pending(1, 2);
        assert_eq!(pending.to_string(), "pending-txoutput-1-2");

        let normal = UtxoId::new(1, 2, 3);
        assert_eq!(normal.to_string(), "utxo-1-2-3");
    }

    #[test]
    fn test_utxo_id_hash() {
        let utxo = UtxoId::new(1, 2, 3);
        let hash = utxo.to_hash();
        assert_eq!(hash.len(), 64); // SHA-256は32バイト（64文字の16進数）
    }
}

#[derive(Debug, Clone)]
pub struct Validator {
    pub address: Address,
    pub stake_amount: u64,
    pub vrf_secret_key: [u8; 32],
    pub slashed: bool,
}

#[derive(Debug, Clone)]
pub struct SlashingEvidence {
    pub validator: Address,
    pub block_height: u64,
    pub evidence_type: SlashingType,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum SlashingType {
    DoubleProposal,
    DoubleVoting,
}

impl UTXOSet {
    pub fn select_proposer(&self, seed: &[u8]) -> Option<Address> {
        let validators = self.get_validators();
        if validators.is_empty() {
            return None;
        }

        // VRFを使用して各バリデータのランダム値を生成
        let mut validator_scores: Vec<(Address, f64)> = validators
            .iter()
            .filter(|v| !v.slashed) // スラッシュされたバリデータを除外
            .map(|validator| {
                let vrf = ECVRF::new(&Sha256::default());
                let proof = vrf.prove(&validator.vrf_secret_key, seed).unwrap();
                let hash = vrf.proof_to_hash(&proof).unwrap();
                
                // ハッシュ値を0-1の範囲の浮動小数点数に変換
                let random_value = hash_to_float(&hash);
                // ステーク量による重み付け
                let weighted_score = random_value * (validator.stake_amount as f64);
                
                (validator.address.clone(), weighted_score)
            })
            .collect();

        // スコアでソートして最高スコアのバリデータを選択
        validator_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        validator_scores.first().map(|(addr, _)| addr.clone())
    }

    pub fn slash_validator(&mut self, evidence: SlashingEvidence) -> Result<(), String> {
        let validator = self.get_validator(&evidence.validator)
            .ok_or("Validator not found")?;

        if validator.slashed {
            return Err("Validator already slashed".to_string());
        }

        // スラッシング処理
        match evidence.evidence_type {
            SlashingType::DoubleProposal => {
                // ステーク額の50%を没収
                self.slash_amount(&evidence.validator, validator.stake_amount / 2)?;
            }
            SlashingType::DoubleVoting => {
                // ステーク額の100%を没収
                self.slash_amount(&evidence.validator, validator.stake_amount)?;
            }
        }

        // バリデータをスラッシュ済みとしてマーク
        self.mark_validator_slashed(&evidence.validator)?;
        Ok(())
    }

    fn slash_amount(&mut self, validator: &Address, amount: u64) -> Result<(), String> {
        // スラッシュされた金額を特別なアドレス（バーン用）に送信
        let burn_address = Address::from_string("BURN_ADDRESS")?;
        self.transfer(validator, &burn_address, amount)?;
        Ok(())
    }

    fn mark_validator_slashed(&mut self, validator: &Address) -> Result<(), String> {
        // バリデータのスラッシュフラグを設定
        if let Some(validator_data) = self.validators.get_mut(validator) {
            validator_data.slashed = true;
            Ok(())
        } else {
            Err("Validator not found".to_string())
        }
    }
}

// ヘルパー関数：ハッシュ値を0-1の範囲の浮動小数点数に変換
fn hash_to_float(hash: &[u8]) -> f64 {
    let mut value: u64 = 0;
    for &byte in hash.iter().take(8) {
        value = (value << 8) | (byte as u64);
    }
    value as f64 / u64::MAX as f64
} 