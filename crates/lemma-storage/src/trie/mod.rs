//! Merkle Patricia Trie for Lemma's world state.
//!
//! The trie maps 32-byte keys (derived from account addresses, contract
//! storage slots, etc.) to arbitrary byte values. The root hash of the trie
//! is committed to every [`BlockHeader`]'s `state_root` and `tx_root` fields,
//! providing a cryptographic commitment to the entire chain state.
//!
//! ## Modules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`node`] | [`TrieNode`] variants (Branch/Extension/Leaf) + [`NibblePath`] |
//! | [`trie`] *(Step 5)* | [`MerklePatriciaTrie`] — insert, get, root |
//! | [`proof`] *(Step 6)* | [`MerkleProof`] — generate + verify |
//!
//! ## Hashing
//!
//! Each node is stored in the `trie_nodes` RocksDB column family, keyed by
//! its Blake3 hash. The hash is computed by `TrieNode::hash()`, which
//! serializes the node with `bincode` then hashes the bytes via
//! `lemma_crypto::hash` — the canonical typed hasher (AGENTS.md §2.1).
//!
//! ## Performance
//!
//! Each [`MerklePatriciaTrie::insert`] commits one `WriteBatch` covering all
//! nodes for that key-value pair (node-level atomicity). Block-level batching
//! (one RocksDB write per block across all trie inserts) will be added in
//! `WorldState` (Step 7). See `trie.rs` module doc for details.
//!
//! [`BlockHeader`]: lemma_core::BlockHeader

pub mod node;
pub mod trie;

pub use node::{NibblePath, TrieNode};
pub use trie::MerklePatriciaTrie;
