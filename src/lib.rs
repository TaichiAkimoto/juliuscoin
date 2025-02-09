/*! 
JuliusCoin - A Modern Blockchain Implementation

This crate implements a blockchain system with a focus on security, scalability, and governance.
It uses post-quantum cryptography for future-proof security and implements advanced consensus
mechanisms.

# Main Components

- `blockchain`: Core blockchain implementation including chain management, consensus, and UTXO handling
- `cryptography`: Cryptographic primitives and wallet management using post-quantum algorithms
- `networking`: P2P networking and node communication protocols
- `governance`: On-chain governance and network metrics
- `cli`: Command-line interface for interacting with the blockchain

# Example Usage

```rust
use juliuscoin::{blockchain, cryptography, networking};

// Example code will be added here
```
*/

/// Core blockchain functionality including chain management and consensus.
pub mod blockchain {
    pub mod chain;
    pub mod consensus;
    pub mod utxo;
}

/// Cryptographic primitives and wallet management using post-quantum algorithms.
/// Implements Dilithium for signatures and Kyber for key encapsulation.
pub mod cryptography {
    pub mod crypto;
    pub mod wallet;
}

/// Networking infrastructure for P2P communication between nodes.
pub mod networking {
    // Network related modules
}

/// On-chain governance mechanisms and network metrics collection.
pub mod governance {
    pub mod metrics;
    pub mod governance;
}

/// Command-line interface for interacting with the blockchain.
pub mod cli;

// Re-exports for commonly used items
pub use blockchain::{chain::*, utxo::*};
pub use cryptography::{crypto::*, wallet::*};
pub use governance::{governance::*, metrics::*}; 