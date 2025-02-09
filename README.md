# Julius Coin

A blockchain implementation in Rust featuring:

- Post-quantum cryptography (Dilithium for signatures, Kyber for encryption)
- Proof of Stake (PoS) consensus
- P2P networking

## Prerequisites

- Rust and Cargo (latest stable version)

## Building

```bash
cargo build
```

## Running

### Single Node

To run a single node with default settings:

```bash
cargo run
```

### Multiple Nodes (P2P Testing)

To test P2P functionality, you can run multiple nodes on different ports:

Terminal 1 (Default port 8333):

```bash
cargo run
```

Terminal 2 (Port 8334):

```bash
P2P_PORT=8334 cargo run
```

Terminal 3 (Port 8335):

```bash
P2P_PORT=8335 cargo run
```

## Logging

To see debug logs, run with:

```bash
RUST_LOG=debug cargo run
```

## Features

- ✅ Basic blockchain structure
- ✅ Post-quantum cryptography integration
- ✅ Simple PoS consensus
- ✅ Basic P2P networking
- ⚠️ Work in progress: Full P2P message handling
- ⚠️ Work in progress: Block synchronization
