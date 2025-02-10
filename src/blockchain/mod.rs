pub mod chain;
pub mod consensus;
pub mod utxo;
pub mod mempool;
pub mod script;

// Re-export commonly used types
pub use chain::{Transaction, TxInput, TxOutput, Blockchain};
pub use consensus::{PoSState, Staker};
pub use utxo::{UTXOSet, UtxoId}; 