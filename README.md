# Julius Coin

A blockchain implementation in Rust featuring:

- Post-quantum cryptography (Dilithium for signatures, Kyber for encryption)
- Proof of Stake (PoS) consensus
- P2P networking

## Prerequisites

- Rust (1.70.0 or later) and Cargo

  ```bash
  # Check your Rust version
  rustc --version

  # Update Rust if needed
  rustup update stable
  ```

- OpenSSL development packages
  - For macOS: `brew install openssl`
  - For Ubuntu/Debian: `sudo apt-get install libssl-dev`
  - For Fedora: `sudo dnf install openssl-devel`

## Environment Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/juliuscoin.git
   cd juliuscoin
   ```

2. Install dependencies:

   ```bash
   cargo build
   ```

3. Set up logging (optional):

   ```bash
   # For macOS/Linux
   export RUST_LOG=debug

   # For Windows PowerShell
   $env:RUST_LOG="debug"
   ```

## Cryptographic Performance Metrics

The implementation includes built-in metrics for measuring the performance and size characteristics of quantum-resistant cryptography:

- Signature sizes (Dilithium vs ECDSA comparison)
- Key sizes (public and private keys)
- Operation timing (signing and verification)
- Block metrics (signature data ratio)

Example metrics output:

```
=== 量子耐性暗号メトリクス ===
Dilithium公開鍵サイズ: 1312 bytes
Dilithium秘密鍵サイズ: 2528 bytes
Dilithium署名サイズ: 2420 bytes
平均署名時間: 1.2ms
平均検証時間: 0.4ms

=== ECDSA比較 ===
ECDSA公開鍵サイズ: 33 bytes
ECDSA署名サイズ: 71-72 bytes
Dilithium/ECDSA署名サイズ比: 33.6倍
```

These metrics help in understanding the practical implications of using post-quantum cryptography in a blockchain context.

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

## Proof of Stake (PoS) の実装について

### バリデータ選択の仕組み

本実装では、以下の特徴を持つ PoS システムを実装しています：

1. **VRF ベースのランダム性**:

   - 検証可能ランダム関数(VRF)を使用して、予測不可能かつ検証可能な方法でプロポーザーを選択
   - ステーク量による重み付けを組み合わせることで、公平性を確保

2. **スラッシング機能**:
   - 不正行為に対する罰則として、ステーク額の没収を実装
   - 対象となる不正行為：
     - 二重提案 (Double Proposal): ステーク額の 50%を没収
     - 二重投票 (Double Voting): ステーク額の 100%を没収

### セキュリティ考慮事項

- VRF を使用することで、バリデータ選択の予測不可能性を確保
- スラッシング機能により、不正行為に対する経済的なペナルティを実装
- スラッシュされたバリデータは、以降のブロック提案から除外

## 暗号アルゴリズム

このプロジェクトは、モジュール化された暗号システムを採用しており、以下の暗号アルゴリズムをサポートしています：

- デフォルト実装
  - Dilithium（署名）
  - Kyber（暗号化）
- SPHINCS+（オプション）
- Falcon（オプション）

新しい暗号アルゴリズムを追加するには、`CryptoOperations`トレイトを実装するだけです。

## ウォレット機能

このプロジェクトには基本的なウォレット機能が実装されています。

### 主な機能

- キーペアの生成と管理
- ウォレットデータのファイル保存/読み込み
- メッセージの署名

### 使用例

```rust
use std::path::PathBuf;
use juliuscoin::wallet::Wallet;

// ウォレットの作成
let wallet_path = PathBuf::from("wallet.dat");
let wallet = Wallet::new(wallet_path).expect("Failed to create wallet");

// メッセージの署名
let message = b"Hello, World!";
let signature = wallet.sign(message);

// 公開鍵の取得
let public_key = wallet.public_key();
```

### セキュリティに関する注意

現在の実装は基本的な機能のみを提供しています。実運用環境では以下の機能の追加を検討してください：

- ウォレットデータの暗号化
- シードフレーズ（ニーモニック）によるバックアップ
- ハードウェアウォレットのサポート
- 複数アドレスの管理
- より強固な鍵管理システム

### 将来の拡張予定

- [ ] AES 暗号化によるウォレットデータの保護
- [ ] BIP39 準拠のシードフレーズ実装
- [ ] HD ウォレット（階層的決定性ウォレット）対応
- [ ] ハードウェアウォレットインターフェースの実装

## ライセンス

MIT License

## 貢献

プルリクエストは大歓迎です。大きな変更を加える場合は、まず issue を開いて変更内容を議論してください。

## 免責事項

このプロジェクトは実験的な実装であり、実運用での使用は推奨されません。

## Example Output

When you run the node, you should see output similar to this:

```
=== Julius Coin MVPノードを起動します ===
[2024-03-xx xx:xx:xx INFO] 新規ウォレットを生成
[2024-03-xx xx:xx:xx INFO] 自分のアドレスHash = 7f8e9d...
[2024-03-xx xx:xx:xx INFO] トランザクションを含むブロック生成を試みます...
[2024-03-xx xx:xx:xx INFO] チェーンのブロック数: 2
[2024-03-xx xx:xx:xx INFO] Block #0 => Tx数: 0
[2024-03-xx xx:xx:xx INFO] (Genesis Block)
[2024-03-xx xx:xx:xx INFO] Block #1 => Tx数: 1
[2024-03-xx xx:xx:xx INFO] P2Pネットワークを起動します...
```

## Troubleshooting

### Common Issues

1. **Build Fails with Crypto-Related Errors**

   ```
   error: failed to run custom build command for `pqcrypto-dilithium`
   ```

   Solution: Make sure you have OpenSSL development packages installed (see Prerequisites section).

2. **P2P Network Connection Issues**

   ```
   Error: Address already in use (os error 48)
   ```

   Solution: Change the P2P port using the P2P_PORT environment variable:

   ```bash
   P2P_PORT=8334 cargo run
   ```

3. **Wallet Loading Errors**

   ```
   Error: Failed to load wallet from file
   ```

   Solution: Delete the existing wallet file and let the system create a new one:

   ```bash
   rm wallet.bin
   cargo run
   ```

4. **High CPU Usage During Block Creation**
   This is normal during the Proof of Stake calculations and cryptographic operations. The system will stabilize after block creation.

### Performance Optimization

For better performance, you can build in release mode:

```bash
cargo build --release
cargo run --release
```

### Debug Mode

For detailed logging and debugging:

```bash
RUST_LOG=debug RUST_BACKTRACE=1 cargo run
```
