//! # lemma-storage
//!
//! Persistent storage for the Lemma blockchain.
//!
//! Provides a RocksDB-backed store with column families for accounts, blocks,
//! transactions, receipts, and contract storage, plus a Blake3 Merkle Patricia
//! Trie for world-state proofs and state snapshot management.
//!
//! ## Crate structure
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | `error` | [`StorageError`] — single error type for all storage ops |
//! | `db` *(Step 2)* | RocksDB wrapper, column families, batch writes |
//! | `account` *(Step 3)* | [`Account`] struct |
//! | `trie` *(Steps 4–6)* | Blake3 Merkle Patricia Trie + proofs |
//! | `state` *(Step 7)* | [`WorldState`] — typed account + contract storage access |
//! | `snapshot` *(Step 8)* | State snapshots for crash recovery |

pub mod error;

pub use error::StorageError;
