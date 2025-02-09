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

## UTXO ID Management

UTXO の ID 管理システムは、以下の形式で UTXO を一意に識別します：

### ID Format

UTXO は 3 つの要素で識別されます：

- `block_index`: ブロックのインデックス
- `tx_index`: トランザクションのインデックス
- `output_index`: トランザクション出力のインデックス

### String Representation

UTXO は状態に応じて以下の形式で文字列表現されます：

- 通常の UTXO: `utxo-{block_index}-{tx_index}-{output_index}`
- ジェネシス UTXO: `genesis-utxo-{output_index}`
- 未確定トランザクションの UTXO: `pending-txoutput-{tx_index}-{output_index}`

### Hash Representation

セキュリティと一意性を確保するため、UTXO は SHA-256 ハッシュとしても表現できます。
ハッシュは`block_index`、`tx_index`、`output_index`を連結してハッシュ化することで生成されます。

### Usage Example

```rust
use juliuscoin::utxo::UtxoId;

// 通常のUTXOの作成
let utxo = UtxoId::new(1, 2, 3);
println!("{}", utxo); // "utxo-1-2-3"
println!("{}", utxo.to_hash()); // SHA-256ハッシュ値

// ジェネシスUTXOの作成
let genesis = UtxoId::genesis(0);
println!("{}", genesis); // "genesis-utxo-0"

// 未確定トランザクションのUTXOの作成
let pending = UtxoId::pending(1, 2);
println!("{}", pending); // "pending-txoutput-1-2"
```
