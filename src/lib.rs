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
pub mod blockchain;

/// Cryptographic primitives and wallet management using post-quantum algorithms.
/// Implements Dilithium for signatures and Kyber for key encapsulation.
pub mod cryptography;

/// Networking infrastructure for P2P communication between nodes.
pub mod network;

/// On-chain governance mechanisms and network metrics collection.
pub mod governance;

/// Command-line interface for interacting with the blockchain.
pub mod cli;

// Re-export commonly used types
pub use blockchain::chain::{Transaction, TxInput, TxOutput, Blockchain};
pub use blockchain::consensus::{PoSState, Staker};
pub use cryptography::wallet::Wallet;
pub use governance::{Governance, JIPType, JIPStatus, VoteType};
pub use network::P2PNetwork; 