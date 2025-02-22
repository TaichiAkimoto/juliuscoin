//! UTXO (Unspent Transaction Output) management and validation.
//! 
//! This module implements the UTXO model for transaction handling, including:
//! - Unique UTXO identification
//! - UTXO set management
//! - Validator staking and slashing
//! - Transaction validation
//! 
//! The implementation uses a combination of UTXO tracking and validator
//! management to ensure proper transaction processing and consensus participation.

use sha2::{Digest, Sha256};
use std::fmt;
use std::collections::{HashMap, VecDeque};
use serde::{Serialize, Deserialize};
use vrf::openssl::{ECVRF, CipherSuite};
use vrf::VRF;
use crate::cryptography::crypto::PQAddress as Address;
use crate::blockchain::script::Script;

/// Represents an Unspent Transaction Output (UTXO) in the blockchain.
/// 
/// UTXOs are the fundamental unit of value in the blockchain, representing
/// coins that can be spent in future transactions.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UTXO {
    /// The amount of coins in this UTXO
    pub amount: u64,
    /// Hash of the owner's post-quantum address
    pub owner_hash: Vec<u8>,
    /// Script that must be satisfied to spend this UTXO
    pub locking_script: Script,
    pub metadata: Option<String>,
}

impl UTXO {
    /// Creates a new UTXO with the given amount and owner
    pub fn new(amount: u64, owner_hash: Vec<u8>, locking_script: Script) -> Self {
        Self {
            amount,
            owner_hash,
            locking_script,
            metadata: None,
        }
    }

    /// Creates a new P2PKH (Pay to Public Key Hash) UTXO
    pub fn new_p2pkh(amount: u64, owner_hash: Vec<u8>) -> Self {
        let mut script = Script::new();
        script.code = vec![
            0x76, // OP_DUP
            0xa8, // OP_SHA256
            0x88, // OP_EQUALVERIFY
            0xac, // OP_CHECKSIG
        ];
        
        Self::new(amount, owner_hash, script)
    }

    /// Creates a new time-locked UTXO that can only be spent after a certain block height
    pub fn new_timelock(amount: u64, owner_hash: Vec<u8>, unlock_height: u64) -> Self {
        let mut script = Script::new();
        script.code = vec![
            0xb1, // OP_CHECKLOCKTIMEVERIFY
            0x69, // OP_VERIFY
        ];
        
        Self::new(amount, owner_hash, script)
    }

    /// Validates the unlocking script against this UTXO's locking script
    pub fn validate_spend(&self, unlocking_script: &Script, block_height: u64) -> Result<bool, String> {
        // Combine unlocking and locking scripts
        let mut combined_script = Script::new();
        combined_script.code.extend(unlocking_script.code.iter());
        combined_script.code.extend(self.locking_script.code.iter());
        
        // Execute the combined script
        combined_script.execute(VecDeque::new(), block_height)
            .map_err(|e| format!("Script execution failed: {}", e))
    }

    pub fn new_with_metadata(amount: u64, owner_hash: Vec<u8>, locking_script: Script, metadata: String) -> Self {
        Self {
            amount,
            owner_hash,
            locking_script,
            metadata: Some(metadata),
        }
    }
}

/// Unique identifier for an Unspent Transaction Output (UTXO).
/// 
/// UTXOs are identified by their position in the blockchain:
/// - The block they were created in
/// - Their transaction index within that block
/// - Their output index within that transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UtxoId {
    /// Height of the block containing this UTXO
    pub block_index: u64,
    /// Index of the transaction within the block
    pub tx_index: u32,
    /// Index of the output within the transaction
    pub output_index: u32,
}

impl UtxoId {
    /// Creates a new UTXO identifier
    /// 
    /// # Arguments
    /// * `block_index` - Height of the containing block
    /// * `tx_index` - Transaction index in the block
    /// * `output_index` - Output index in the transaction
    pub fn new(block_index: u64, tx_index: u32, output_index: u32) -> Self {
        Self {
            block_index,
            tx_index,
            output_index,
        }
    }

    /// Creates a UTXO identifier for genesis block outputs
    /// 
    /// # Arguments
    /// * `output_index` - Output index in the genesis transaction
    pub fn genesis(output_index: u32) -> Self {
        Self {
            block_index: 0,
            tx_index: 0,
            output_index,
        }
    }

    /// Creates a UTXO identifier for pending transactions
    /// 
    /// # Arguments
    /// * `tx_index` - Index in the pending transaction pool
    /// * `output_index` - Output index in the transaction
    pub fn pending(tx_index: u32, output_index: u32) -> Self {
        Self {
            block_index: u64::MAX, // pending transactions use max value to distinguish
            tx_index,
            output_index,
        }
    }

    /// Computes a unique hash string for this UTXO
    /// 
    /// # Returns
    /// * `String` - SHA-256 hash of the UTXO identifier
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

/// Represents a validator in the PoS system
#[derive(Debug, Clone)]
pub struct Validator {
    /// Post-quantum address of the validator
    pub address: Address,
    /// Amount of coins staked by the validator
    pub stake_amount: u64,
    /// VRF secret key for block proposer selection
    pub vrf_secret_key: [u8; 32],
    /// Whether the validator has been slashed
    pub slashed: bool,
}

/// Evidence of validator misbehavior for slashing
#[derive(Debug, Clone)]
pub struct SlashingEvidence {
    /// Address of the misbehaving validator
    pub validator: Address,
    /// Block height where the offense occurred
    pub block_height: u64,
    /// Type of slashable offense
    pub evidence_type: SlashingType,
    /// Cryptographic proof of misbehavior
    pub proof: Vec<u8>,
}

/// Types of slashable offenses
#[derive(Debug, Clone)]
pub enum SlashingType {
    /// Proposing multiple blocks at the same height
    DoubleProposal,
    /// Voting for conflicting blocks
    DoubleVoting,
}

#[derive(Debug)]
pub struct UTXOSet {
    utxos: HashMap<UtxoId, UTXO>,
    validators: HashMap<Address, Validator>,
}

impl UTXOSet {
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
            validators: HashMap::new(),
        }
    }

    pub fn get_validators(&self) -> Vec<&Validator> {
        self.validators.values().collect()
    }

    pub fn get_validator(&self, address: &Address) -> Option<&Validator> {
        self.validators.get(address)
    }

    pub fn transfer(&mut self, _from: &Address, _to: &Address, _amount: u64) -> Result<(), String> {
        // Implementation needed
        Ok(())
    }

    /// Get a UTXO by its ID
    pub fn get_utxo(&self, id: &UtxoId) -> Option<&UTXO> {
        self.utxos.get(id)
    }

    /// Add a new UTXO to the set
    pub fn add_utxo(&mut self, id: UtxoId, utxo: UTXO) {
        self.utxos.insert(id, utxo);
    }

    /// Remove a UTXO from the set
    pub fn remove_utxo(&mut self, id: &UtxoId) -> Option<UTXO> {
        self.utxos.remove(id)
    }

    /// Get all UTXOs in the set
    pub fn get_all_utxos(&self) -> &HashMap<UtxoId, UTXO> {
        &self.utxos
    }
}

impl UTXOSet {
    /// Selects the next block proposer using VRF
    /// 
    /// # Arguments
    /// * `seed` - Random seed for VRF (usually previous block hash)
    /// 
    /// # Returns
    /// * `Option<Address>` - Address of the selected proposer, if any
    pub fn select_proposer(&self, seed: &[u8]) -> Option<Address> {
        let validators = self.get_validators();
        if validators.is_empty() {
            return None;
        }

        let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
        
        // VRFを使用して各バリデータのランダム値を生成
        let mut validator_scores: Vec<(Address, f64)> = validators
            .iter()
            .filter(|v| !v.slashed) // スラッシュされたバリデータを除外
            .map(|validator| {
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

    /// Slashes a validator for misbehavior
    /// 
    /// # Arguments
    /// * `evidence` - Evidence of validator misbehavior
    /// 
    /// # Returns
    /// * `Result<(), String>` - Ok if slashing succeeded, Err with message if failed
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

    /// Reduces a validator's stake by the specified amount
    /// 
    /// # Arguments
    /// * `validator` - Address of the validator to slash
    /// * `amount` - Amount of stake to slash
    fn slash_amount(&mut self, validator: &Address, amount: u64) -> Result<(), String> {
        // スラッシュされた金額を特別なアドレス（バーン用）に送信
        let burn_address = Address::from_string("BURN_ADDRESS")?;
        self.transfer(validator, &burn_address, amount)?;
        Ok(())
    }

    /// Marks a validator as slashed, preventing future participation
    /// 
    /// # Arguments
    /// * `validator` - Address of the validator to mark as slashed
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

/// Converts a byte array hash to a float value between 0 and 1
/// 
/// # Arguments
/// * `hash` - Byte array to convert
/// 
/// # Returns
/// * `f64` - Float value between 0 and 1
fn hash_to_float(hash: &[u8]) -> f64 {
    let mut value: u64 = 0;
    for &byte in hash.iter().take(8) {
        value = (value << 8) | (byte as u64);
    }
    value as f64 / u64::MAX as f64
} 