use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

use crate::blockchain::utxo::{UTXOSet, UtxoId};
use crate::cryptography::crypto::PQAddress as Address;

/// Maximum size of the mempool in bytes
const MAX_MEMPOOL_SIZE: usize = 1024 * 1024 * 32; // 32MB

/// Maximum number of transactions in the mempool
const MAX_MEMPOOL_TXS: usize = 50_000;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Transaction {
    pub inputs: Vec<UtxoId>,
    pub outputs: Vec<(Address, u64)>,
    pub fee: u64,
    pub signature: Vec<u8>,
    size: usize,
}

#[derive(Debug)]
pub struct MempoolConfig {
    pub max_size: usize,
    pub max_tx_count: usize,
    pub min_fee_per_byte: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: MAX_MEMPOOL_SIZE,
            max_tx_count: MAX_MEMPOOL_TXS,
            min_fee_per_byte: 1,
        }
    }
}

/// Thread-safe transaction pool implementation
pub struct Mempool {
    /// Transactions ordered by fee-per-byte (for prioritization)
    transactions_by_fee: RwLock<BTreeMap<u64, HashSet<Transaction>>>,
    /// Track transaction inputs to prevent double-spends
    used_inputs: RwLock<HashSet<UtxoId>>,
    /// Track total size of mempool
    size: RwLock<usize>,
    /// Configuration
    config: MempoolConfig,
    /// Broadcast channel for new transaction notifications
    tx_updates: broadcast::Sender<Transaction>,
}

impl Mempool {
    pub fn new(config: MempoolConfig) -> Self {
        let (tx_updates, _) = broadcast::channel(1024);
        Self {
            transactions_by_fee: RwLock::new(BTreeMap::new()),
            used_inputs: RwLock::new(HashSet::new()),
            size: RwLock::new(0),
            config,
            tx_updates,
        }
    }

    /// Add a transaction to the mempool
    pub fn add_transaction(&self, tx: Transaction, utxo_set: &UTXOSet) -> Result<(), String> {
        // Validate transaction
        self.validate_transaction(&tx, utxo_set)?;

        let mut txs_by_fee = self.transactions_by_fee.write().unwrap();
        let mut used_inputs = self.used_inputs.write().unwrap();
        let mut size = self.size.write().unwrap();

        // Check if this would exceed size limits
        if *size + tx.size > self.config.max_size {
            self.evict_lowest_fee_transactions(&mut txs_by_fee, &mut used_inputs, &mut size, tx.size)?;
        }

        // Calculate fee per byte
        let fee_per_byte = tx.fee / tx.size as u64;
        if fee_per_byte < self.config.min_fee_per_byte {
            return Err("Fee too low".to_string());
        }

        // Add transaction
        txs_by_fee.entry(fee_per_byte)
            .or_insert_with(HashSet::new)
            .insert(tx.clone());

        // Track inputs
        for input in &tx.inputs {
            used_inputs.insert(input.clone());
        }

        *size += tx.size;

        // Notify subscribers
        let _ = self.tx_updates.send(tx);

        Ok(())
    }

    /// Validate a transaction before adding to mempool
    fn validate_transaction(&self, tx: &Transaction, utxo_set: &UTXOSet) -> Result<(), String> {
        // Check for double spends within mempool
        let used_inputs = self.used_inputs.read().unwrap();
        for input in &tx.inputs {
            if used_inputs.contains(input) {
                return Err("Double spend detected in mempool".to_string());
            }
        }

        // Verify each input exists in UTXO set
        for input in &tx.inputs {
            if utxo_set.get_utxo(input).is_none() {
                return Err("Input UTXO not found".to_string());
            }
        }

        // Verify input amounts >= output amounts + fee
        let input_sum: u64 = tx.inputs.iter()
            .filter_map(|input| utxo_set.get_utxo(input))
            .map(|utxo| utxo.amount)
            .sum();

        let output_sum: u64 = tx.outputs.iter()
            .map(|(_, amount)| *amount)
            .sum();

        if input_sum < output_sum + tx.fee {
            return Err("Insufficient input amounts".to_string());
        }

        Ok(())
    }

    /// Remove lowest fee transactions to make room
    fn evict_lowest_fee_transactions(
        &self,
        txs_by_fee: &mut BTreeMap<u64, HashSet<Transaction>>,
        used_inputs: &mut HashSet<UtxoId>,
        size: &mut usize,
        required_size: usize,
    ) -> Result<(), String> {
        let mut freed_size = 0;

        while let Some((&fee, txs)) = txs_by_fee.iter().next() {
            for tx in txs.iter() {
                freed_size += tx.size;
                for input in &tx.inputs {
                    used_inputs.remove(input);
                }
                *size -= tx.size;

                if freed_size >= required_size {
                    txs_by_fee.remove(&fee);
                    return Ok(());
                }
            }
            txs_by_fee.remove(&fee);
        }

        Err("Could not free enough space".to_string())
    }

    /// Get transactions ordered by fee (highest first) up to size limit
    pub fn get_transactions_for_block(&self, size_limit: usize) -> Vec<Transaction> {
        let txs_by_fee = self.transactions_by_fee.read().unwrap();
        let mut result = Vec::new();
        let mut total_size = 0;

        for txs in txs_by_fee.values().rev() {
            for tx in txs {
                if total_size + tx.size <= size_limit {
                    result.push(tx.clone());
                    total_size += tx.size;
                } else {
                    return result;
                }
            }
        }

        result
    }

    /// Remove transactions that were included in a block
    pub fn remove_transactions(&self, txs: &[Transaction]) {
        let mut txs_by_fee = self.transactions_by_fee.write().unwrap();
        let mut used_inputs = self.used_inputs.write().unwrap();
        let mut size = self.size.write().unwrap();

        for tx in txs {
            // Remove from fee index
            if let Some(fee_per_byte) = tx.fee.checked_div(tx.size as u64) {
                if let Some(tx_set) = txs_by_fee.get_mut(&fee_per_byte) {
                    tx_set.remove(tx);
                    if tx_set.is_empty() {
                        txs_by_fee.remove(&fee_per_byte);
                    }
                }
            }

            // Remove inputs
            for input in &tx.inputs {
                used_inputs.remove(input);
            }

            // Update size
            *size -= tx.size;
        }
    }

    /// Subscribe to new transaction notifications
    pub fn subscribe(&self) -> broadcast::Receiver<Transaction> {
        self.tx_updates.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Add tests here
} 