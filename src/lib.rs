pub mod blockchain {
    pub mod chain;
    pub mod consensus;
    pub mod utxo;
}

pub mod cryptography {
    pub mod crypto;
    pub mod wallet;
}

pub mod networking {
    // Network related modules
}

pub mod governance {
    pub mod metrics;
    pub mod governance;
}

pub mod cli;

// Re-exports for commonly used items
pub use blockchain::{chain::*, consensus::*, utxo::*};
pub use cryptography::{crypto::*, wallet::*};
pub use governance::{governance::*, metrics::*}; 