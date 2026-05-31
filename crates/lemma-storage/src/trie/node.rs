//! Trie node types for Lemma's Merkle Patricia Trie.
//!
//! The Merkle Patricia Trie (MPT) uses three node types:
//!
//! | Variant | Purpose |
//! |---------|---------|
//! | [`TrieNode::Branch`] | 16-way branch (one child per nibble, optional value) |
//! | [`TrieNode::Extension`] | Compressed shared prefix + single child hash |
//! | [`TrieNode::Leaf`] | Terminal: remaining path + stored value |
//!
//! Keys are decomposed into [`NibblePath`]s (sequences of 4-bit nibbles) for
//! traversal. A 32-byte key produces 64 nibbles.
//!
//! ## Node hashing
//!
//! Every node's hash is computed by [`TrieNode::hash`]:
//!
//! 1. Serialize the node with `bincode` (fixint, little-endian — same as
//!    `lemma_crypto::hash`).
//! 2. Hash the bytes with Blake3 via [`lemma_crypto::hash`].
//!
//! The resulting [`Hash`] is both the storage key in the `trie_nodes` column
//! family and the child reference used in Branch/Extension nodes.
//!
//! ## Determinism
//!
//! All serialization uses `bincode::serialize` with default options (fixint
//! encoding, little-endian). Never switch to varint or big-endian — this
//! would break the consensus state root (AGENTS.md §7.1).

use lemma_core::Hash;
use serde::{Deserialize, Serialize};

use crate::StorageError;

// ─── NibblePath ───────────────────────────────────────────────────────────────

/// A sequence of nibbles (4-bit values in range `0..=15`).
///
/// Keys in the Merkle Patricia Trie are decomposed into nibble paths for
/// traversal. A byte slice is converted by splitting each byte into its high
/// nibble (bits 7–4) and low nibble (bits 3–0), high nibble first. A 32-byte
/// key produces a 64-nibble path.
///
/// `NibblePath` is the unit of path manipulation in the trie: the trie uses
/// it to share prefixes (Extension nodes) and branch (Branch nodes index
/// children by the *next* nibble in the path).
///
/// # Invariant
///
/// Every nibble value is in `0..=15`. Constructors that accept raw bytes
/// enforce this by construction. [`NibblePath::from_nibbles`] validates at
/// runtime and returns `None` on invalid input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NibblePath {
    /// Nibbles stored one per byte. Each value is in `0..=15`.
    nibbles: Vec<u8>,
}

impl NibblePath {
    /// Construct a `NibblePath` from a byte slice.
    ///
    /// Each byte is split into its high nibble (`byte >> 4`) and low nibble
    /// (`byte & 0x0F`), high nibble first. A 32-byte key becomes 64 nibbles.
    pub fn from_bytes(key: &[u8]) -> Self {
        let mut nibbles = Vec::with_capacity(key.len() * 2);
        for &byte in key {
            nibbles.push(byte >> 4);
            nibbles.push(byte & 0x0F);
        }
        Self { nibbles }
    }

    /// Construct a `NibblePath` from a `Vec<u8>` of nibble values.
    ///
    /// Returns `None` if any value exceeds `15`.
    ///
    /// [`from_bytes`]: NibblePath::from_bytes
    pub fn from_nibbles(nibbles: Vec<u8>) -> Option<Self> {
        if nibbles.iter().any(|&n| n > 15) {
            return None;
        }
        Some(Self { nibbles })
    }

    /// Number of nibbles in the path.
    pub fn len(&self) -> usize {
        self.nibbles.len()
    }

    /// Returns `true` if the path contains no nibbles.
    pub fn is_empty(&self) -> bool {
        self.nibbles.is_empty()
    }

    /// Get the nibble at `index`, or `None` if out of bounds.
    pub fn get(&self, index: usize) -> Option<u8> {
        self.nibbles.get(index).copied()
    }

    /// Return a new `NibblePath` with the first `n` nibbles removed.
    ///
    /// If `n >= self.len()`, returns an empty path.
    pub fn skip(&self, n: usize) -> Self {
        let start = n.min(self.nibbles.len());
        Self {
            nibbles: self.nibbles[start..].to_vec(),
        }
    }

    /// Return a new `NibblePath` containing only the first `n` nibbles.
    ///
    /// If `n >= self.len()`, returns a clone of the full path.
    pub fn take(&self, n: usize) -> Self {
        let end = n.min(self.nibbles.len());
        Self {
            nibbles: self.nibbles[..end].to_vec(),
        }
    }

    /// Count the number of leading nibbles shared between `self` and `other`.
    ///
    /// Returns 0 if the paths diverge immediately or either is empty.
    pub fn common_prefix_len(&self, other: &NibblePath) -> usize {
        self.nibbles
            .iter()
            .zip(other.nibbles.iter())
            .take_while(|(a, b)| a == b)
            .count()
    }

    /// Returns `true` if `self` begins with all nibbles of `prefix`.
    ///
    /// An empty `prefix` always returns `true`.
    pub fn starts_with(&self, prefix: &NibblePath) -> bool {
        self.nibbles.starts_with(&prefix.nibbles)
    }

    /// Borrow the underlying nibble slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.nibbles
    }

    /// Return a new `NibblePath` that is `self` followed by all nibbles of `other`.
    ///
    /// Used during trie restructuring when merging an Extension prefix with a
    /// remaining path segment (e.g. when splitting an Extension node).
    pub fn concat(&self, other: &NibblePath) -> Self {
        let mut nibbles = Vec::with_capacity(self.nibbles.len() + other.nibbles.len());
        nibbles.extend_from_slice(&self.nibbles);
        nibbles.extend_from_slice(&other.nibbles);
        Self { nibbles }
    }

    /// Return a new `NibblePath` with `nibble` prepended before all existing nibbles.
    ///
    /// `nibble` must be in `0..=15`. Used when reconstructing an Extension
    /// node's prefix after a Branch split — the branching nibble becomes the
    /// first element of the new Extension prefix.
    ///
    /// A `debug_assert!` enforces the nibble range in debug builds.
    pub fn prepend_nibble(&self, nibble: u8) -> Self {
        debug_assert!(nibble <= 15, "prepend_nibble: nibble > 15");
        let mut nibbles = Vec::with_capacity(self.nibbles.len() + 1);
        nibbles.push(nibble);
        nibbles.extend_from_slice(&self.nibbles);
        Self { nibbles }
    }
}

// ─── TrieNode ─────────────────────────────────────────────────────────────────

/// A node in Lemma's Merkle Patricia Trie.
///
/// ## Variant semantics
///
/// - **Branch**: reached when the current path diverges across multiple
///   children. Holds up to 16 child hashes (indexed by the *next* nibble)
///   and an optional inline value for keys that terminate at this branch.
///
/// - **Extension**: a path compression optimisation. When a subtree shares
///   a common prefix with no branch in between, an Extension node stores
///   that prefix and a single child hash. During traversal, if the remaining
///   path starts with `prefix`, advance by `prefix.len()` and descend to
///   `child`.
///
/// - **Leaf**: a terminal node. `path` is the remaining nibbles after all
///   Branch and Extension nodes have been consumed; `value` is the stored
///   byte slice (e.g. a bincode-encoded `Account`).
///
/// ## Storage key
///
/// Each node is stored in the `trie_nodes` column family keyed by
/// `TrieNode::hash()`. Branch and Extension nodes reference their children
/// by their hashes — never by in-memory pointers.
// The `Branch` variant is intentionally large: it holds `[Option<Hash>; 16]`
// (552 bytes) to represent a 16-way branch. Boxing would change the bincode
// layout and break the consensus state root — not allowed (AGENTS.md §7.1).
// All TrieNode values are behind RocksDB / WriteBatch — not on the hot stack.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrieNode {
    /// A 16-way branch node.
    ///
    /// `children[i]` is `Some(hash)` if there is a child for nibble `i`,
    /// or `None` if no key with nibble `i` at this depth exists.
    ///
    /// `value` is `Some(bytes)` if a key terminates exactly at this branch
    /// (i.e. the key was consumed entirely to reach this node).
    Branch {
        /// 16 child hashes, one per nibble (0x0–0xF).
        children: [Option<Hash>; 16],
        /// Optional value stored at this node's key prefix.
        value: Option<Vec<u8>>,
    },

    /// A path-compressed extension node.
    ///
    /// Stores a shared `prefix` and a single `child` hash. Traversal: if the
    /// remaining path starts with `prefix`, skip `prefix.len()` nibbles and
    /// descend to `child`. If not, the key does not exist in the trie.
    Extension {
        /// The shared nibble prefix this extension compresses.
        prefix: NibblePath,
        /// Hash of the child node at the end of `prefix`.
        child: Hash,
    },

    /// A terminal leaf node.
    ///
    /// `path` is the remaining nibble path after all ancestors have been
    /// consumed. `value` is the serialized data stored at this key.
    Leaf {
        /// Remaining nibble path from this node's depth to the key end.
        path: NibblePath,
        /// The value stored at this key (e.g. bincode-encoded `Account`).
        value: Vec<u8>,
    },
}

impl TrieNode {
    /// Compute the Blake3 hash of this node's canonical serialization.
    ///
    /// Uses `lemma_crypto::hash` (bincode fixint + Blake3) — the same
    /// canonical typed hasher used for transactions and block headers
    /// (AGENTS.md §2.1). This guarantees every node produces the same hash
    /// for the same content on every Lemma node.
    ///
    /// The returned [`Hash`] is used as:
    /// - The storage key in the `trie_nodes` column family.
    /// - A child reference in [`Branch`] and [`Extension`] nodes.
    ///
    /// # Serialization format (do not change — consensus-critical)
    ///
    /// - `NibblePath` serializes as a length-prefixed `Vec<u8>` (one nibble
    ///   per byte, values 0–15).
    /// - `Hash` serializes as a length-prefixed UTF-8 hex string (8 + 64
    ///   bytes). This is Lemma's canonical binary format — **not** raw 32
    ///   bytes. All Lemma nodes and SDKs use `lemma_core::Hash` which defines
    ///   this encoding. Changing it breaks the consensus state root.
    /// - This format is intentional and human-inspectable (same as
    ///   `Account.code_hash` on disk — see `account/tests.rs` size pin).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SerializationFailed`] if `bincode` cannot
    /// serialize this node. In practice this should never happen for valid
    /// `TrieNode` values — all field types implement `Serialize` correctly.
    ///
    /// [`Branch`]: TrieNode::Branch
    /// [`Extension`]: TrieNode::Extension
    pub fn hash(&self) -> Result<Hash, StorageError> {
        lemma_crypto::hash(self).map_err(|e| StorageError::SerializationFailed {
            reason: e.to_string(),
        })
    }

    // ── Type predicates ───────────────────────────────────────────────────────

    /// Returns `true` if this is a [`Branch`] node.
    ///
    /// [`Branch`]: TrieNode::Branch
    pub fn is_branch(&self) -> bool {
        matches!(self, TrieNode::Branch { .. })
    }

    /// Returns `true` if this is an [`Extension`] node.
    ///
    /// [`Extension`]: TrieNode::Extension
    pub fn is_extension(&self) -> bool {
        matches!(self, TrieNode::Extension { .. })
    }

    /// Returns `true` if this is a [`Leaf`] node.
    ///
    /// [`Leaf`]: TrieNode::Leaf
    pub fn is_leaf(&self) -> bool {
        matches!(self, TrieNode::Leaf { .. })
    }
}

// ─── TrieNode constructors ────────────────────────────────────────────────────

impl TrieNode {
    /// Create a new empty [`Branch`] node with no children and no value.
    ///
    /// [`Branch`]: TrieNode::Branch
    pub fn empty_branch() -> Self {
        TrieNode::Branch {
            children: [None; 16],
            value: None,
        }
    }

    /// Create a [`Leaf`] node with the given path and value.
    ///
    /// [`Leaf`]: TrieNode::Leaf
    pub fn leaf(path: NibblePath, value: Vec<u8>) -> Self {
        TrieNode::Leaf { path, value }
    }

    /// Create an [`Extension`] node with the given prefix and child hash.
    ///
    /// [`Extension`]: TrieNode::Extension
    pub fn extension(prefix: NibblePath, child: Hash) -> Self {
        TrieNode::Extension { prefix, child }
    }
}

// ─── TrieNode branch accessors ────────────────────────────────────────────────

impl TrieNode {
    /// Set child at `nibble` (0–15) of a [`Branch`] node to `hash`.
    ///
    /// Returns `Some(())` on success. Returns `None` if `self` is not a
    /// Branch or `nibble > 15`.
    ///
    /// [`Branch`]: TrieNode::Branch
    pub fn set_child(&mut self, nibble: usize, hash: Hash) -> Option<()> {
        match self {
            TrieNode::Branch { children, .. } => {
                *children.get_mut(nibble)? = Some(hash);
                Some(())
            }
            _ => None,
        }
    }

    /// Get the child hash at `nibble` (0–15) of a [`Branch`] node.
    ///
    /// Returns `None` if `self` is not a Branch, `nibble > 15`, or the
    /// child slot is empty (`None`).
    ///
    /// [`Branch`]: TrieNode::Branch
    pub fn get_child(&self, nibble: usize) -> Option<Hash> {
        match self {
            TrieNode::Branch { children, .. } => *children.get(nibble)?,
            _ => None,
        }
    }

    /// Count the non-`None` children of a [`Branch`] node.
    ///
    /// Returns `None` if `self` is not a Branch. The trie delete algorithm
    /// uses this to detect when a Branch has been reduced to a single child
    /// and should be collapsed into an Extension node.
    ///
    /// [`Branch`]: TrieNode::Branch
    pub fn child_count(&self) -> Option<usize> {
        match self {
            TrieNode::Branch { children, .. } => {
                Some(children.iter().filter(|c| c.is_some()).count())
            }
            _ => None,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
