# lemma — Core Blockchain

> Lemma core chain: consensus, VM, compiler, node, CLI.

## Crates

| Crate | Description | Build Order |
|-------|-------------|-------------|
| `lemma-core` | Core types (Address, Hash, Block, Transaction) | 1 |
| `lemma-crypto` | Ed25519 + Dilithium + Blake3 | 2 |
| `lemma-storage` | RocksDB + Merkle Patricia Trie | 3 |
| `lemma-network` | libp2p P2P networking | 4 |
| `lemma-mempool` | TX pool + Shield + rate limiting + QoS | 5 |
| `lemma-consensus` | DAG: Surge + Pulse + PoS | 6 |
| `lemma-vm` | LemmaVM (WASM/wasmer) + Flux parallel | 7 |
| `lemma-lang` | Lem compiler (lexer→parser→typechecker→codegen) | 8 |
| `lemma-transpiler` | Solidity → Lem converter | 9 |
| `lemma-privacy` | Veil (ZK, Penumbra/Sapling/arkworks) | 10 |
| `lemma-rpc` | JSON-RPC + WebSocket + GraphQL | 11 |
| `lemma-node` | Full node binary | 12 |
| `lemma-cli` | CLI tools (`lemma` command) | 12 |

## Setup

```bash
# Requires Rust nightly
rustup toolchain install nightly
rustup component add rustfmt clippy

# Build all crates
cargo build

# Run tests
cargo test

# Run node
cargo run --bin lemma-node
```

## Architecture

See the [BUILD_GUIDE](https://github.com/lemmachain/lemma-root) for detailed build instructions.

---

*"Proven by Lemma."*
