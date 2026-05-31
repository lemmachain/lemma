//! Tests for `lemma_storage::trie::node`.
//!
//! Covers NibblePath construction, accessors, slicing, and comparison;
//! TrieNode constructors, predicates, hash determinism, and bincode
//! round-trips for all three variants.
//! 100% public API coverage per AGENTS.md §11.1.

use lemma_core::Hash;

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn empty_path() -> NibblePath {
    NibblePath::from_nibbles(vec![])
}

fn path_from_nibbles(nibbles: &[u8]) -> NibblePath {
    NibblePath::from_nibbles(nibbles.to_vec())
}

fn path_from_byte(byte: u8) -> NibblePath {
    NibblePath::from_bytes(&[byte])
}

fn nonzero_hash(fill: u8) -> Hash {
    Hash::from_bytes([fill; 32])
}

fn leaf_node(nibbles: &[u8], value: &[u8]) -> TrieNode {
    TrieNode::leaf(path_from_nibbles(nibbles), value.to_vec())
}

fn extension_node(nibbles: &[u8], child_fill: u8) -> TrieNode {
    TrieNode::extension(path_from_nibbles(nibbles), nonzero_hash(child_fill))
}

fn branch_all_none() -> TrieNode {
    TrieNode::empty_branch()
}

fn branch_with_child(nibble: usize, child_fill: u8) -> TrieNode {
    let mut children = [None; 16];
    children[nibble] = Some(nonzero_hash(child_fill));
    TrieNode::Branch { children, value: None }
}

// ── NibblePath::from_bytes ────────────────────────────────────────────────────

#[test]
fn from_bytes_empty_slice_produces_empty_path() {
    assert_eq!(NibblePath::from_bytes(&[]).len(), 0);
}

#[test]
fn from_bytes_single_byte_produces_two_nibbles() {
    let path = path_from_byte(0xAB);
    assert_eq!(path.len(), 2);
    assert_eq!(path.get(0), Some(0xA)); // high nibble
    assert_eq!(path.get(1), Some(0xB)); // low nibble
}

#[test]
fn from_bytes_zero_byte_produces_two_zero_nibbles() {
    let path = path_from_byte(0x00);
    assert_eq!(path.get(0), Some(0x0));
    assert_eq!(path.get(1), Some(0x0));
}

#[test]
fn from_bytes_ff_produces_two_fifteen_nibbles() {
    let path = path_from_byte(0xFF);
    assert_eq!(path.get(0), Some(0xF));
    assert_eq!(path.get(1), Some(0xF));
}

#[test]
fn from_bytes_two_bytes_produce_four_nibbles_in_order() {
    let path = NibblePath::from_bytes(&[0x12, 0x34]);
    assert_eq!(path.len(), 4);
    assert_eq!(path.get(0), Some(0x1));
    assert_eq!(path.get(1), Some(0x2));
    assert_eq!(path.get(2), Some(0x3));
    assert_eq!(path.get(3), Some(0x4));
}

#[test]
fn from_bytes_32_bytes_produce_64_nibbles() {
    // 32-byte account address → 64-nibble trie path.
    let key = [0xABu8; 32];
    assert_eq!(NibblePath::from_bytes(&key).len(), 64);
}

// ── NibblePath::from_nibbles ──────────────────────────────────────────────────

#[test]
fn from_nibbles_preserves_values() {
    let path = path_from_nibbles(&[0, 1, 2, 15]);
    assert_eq!(path.as_slice(), &[0, 1, 2, 15]);
}

#[test]
fn from_nibbles_empty_produces_empty_path() {
    assert!(empty_path().is_empty());
}

// ── NibblePath::get ───────────────────────────────────────────────────────────

#[test]
fn get_returns_none_for_out_of_bounds_index() {
    let path = path_from_nibbles(&[1, 2, 3]);
    assert_eq!(path.get(3), None);
    assert_eq!(path.get(100), None);
}

#[test]
fn get_returns_correct_nibble_at_last_index() {
    let path = path_from_nibbles(&[5, 10, 15]);
    assert_eq!(path.get(2), Some(15));
}

// ── NibblePath::skip ──────────────────────────────────────────────────────────

#[test]
fn skip_zero_returns_full_path() {
    let path = path_from_nibbles(&[1, 2, 3]);
    assert_eq!(path.skip(0).as_slice(), &[1, 2, 3]);
}

#[test]
fn skip_partial_removes_leading_nibbles() {
    let path = path_from_nibbles(&[1, 2, 3, 4]);
    assert_eq!(path.skip(2).as_slice(), &[3, 4]);
}

#[test]
fn skip_all_produces_empty_path() {
    let path = path_from_nibbles(&[1, 2, 3]);
    assert!(path.skip(3).is_empty());
}

#[test]
fn skip_more_than_length_produces_empty_path() {
    let path = path_from_nibbles(&[1, 2]);
    assert!(path.skip(99).is_empty());
}

// ── NibblePath::take ──────────────────────────────────────────────────────────

#[test]
fn take_zero_produces_empty_path() {
    let path = path_from_nibbles(&[1, 2, 3]);
    assert!(path.take(0).is_empty());
}

#[test]
fn take_partial_returns_leading_nibbles() {
    let path = path_from_nibbles(&[5, 6, 7, 8]);
    assert_eq!(path.take(2).as_slice(), &[5, 6]);
}

#[test]
fn take_all_returns_full_path() {
    let path = path_from_nibbles(&[3, 4]);
    assert_eq!(path.take(2).as_slice(), &[3, 4]);
}

#[test]
fn take_more_than_length_returns_full_path() {
    let path = path_from_nibbles(&[9, 10]);
    assert_eq!(path.take(99).as_slice(), &[9, 10]);
}

// ── NibblePath::common_prefix_len ─────────────────────────────────────────────

#[test]
fn common_prefix_len_identical_paths_equals_full_length() {
    let a = path_from_nibbles(&[1, 2, 3, 4]);
    let b = path_from_nibbles(&[1, 2, 3, 4]);
    assert_eq!(a.common_prefix_len(&b), 4);
}

#[test]
fn common_prefix_len_no_common_prefix_returns_zero() {
    let a = path_from_nibbles(&[1, 2, 3]);
    let b = path_from_nibbles(&[4, 5, 6]);
    assert_eq!(a.common_prefix_len(&b), 0);
}

#[test]
fn common_prefix_len_partial_match() {
    let a = path_from_nibbles(&[1, 2, 3, 4]);
    let b = path_from_nibbles(&[1, 2, 9, 9]);
    assert_eq!(a.common_prefix_len(&b), 2);
}

#[test]
fn common_prefix_len_empty_paths_return_zero() {
    assert_eq!(empty_path().common_prefix_len(&empty_path()), 0);
}

#[test]
fn common_prefix_len_one_empty_returns_zero() {
    let a = path_from_nibbles(&[1, 2]);
    assert_eq!(a.common_prefix_len(&empty_path()), 0);
}

// ── NibblePath::starts_with ───────────────────────────────────────────────────

#[test]
fn starts_with_empty_prefix_is_always_true() {
    assert!(path_from_nibbles(&[1, 2]).starts_with(&empty_path()));
    assert!(empty_path().starts_with(&empty_path()));
}

#[test]
fn starts_with_full_match_returns_true() {
    let path = path_from_nibbles(&[1, 2, 3]);
    let prefix = path_from_nibbles(&[1, 2, 3]);
    assert!(path.starts_with(&prefix));
}

#[test]
fn starts_with_partial_match_returns_true() {
    let path = path_from_nibbles(&[1, 2, 3, 4]);
    let prefix = path_from_nibbles(&[1, 2]);
    assert!(path.starts_with(&prefix));
}

#[test]
fn starts_with_mismatch_returns_false() {
    let path = path_from_nibbles(&[1, 2, 3]);
    let prefix = path_from_nibbles(&[1, 9]);
    assert!(!path.starts_with(&prefix));
}

#[test]
fn starts_with_longer_prefix_returns_false() {
    let path = path_from_nibbles(&[1, 2]);
    let prefix = path_from_nibbles(&[1, 2, 3]);
    assert!(!path.starts_with(&prefix));
}

// ── NibblePath — Clone + PartialEq ───────────────────────────────────────────

#[test]
fn nibble_path_clone_equals_original() {
    let path = path_from_nibbles(&[3, 7, 11]);
    assert_eq!(path.clone(), path);
}

#[test]
fn nibble_paths_with_same_nibbles_are_equal() {
    assert_eq!(path_from_nibbles(&[1, 2]), path_from_nibbles(&[1, 2]));
}

#[test]
fn nibble_paths_with_different_nibbles_are_not_equal() {
    assert_ne!(path_from_nibbles(&[1, 2]), path_from_nibbles(&[1, 3]));
}

// ── TrieNode::empty_branch ────────────────────────────────────────────────────

#[test]
fn empty_branch_has_all_none_children() {
    let TrieNode::Branch { children, value } = branch_all_none() else {
        panic!("expected Branch");
    };
    assert!(children.iter().all(|c| c.is_none()));
    assert!(value.is_none());
}

#[test]
fn empty_branch_is_branch_returns_true() {
    assert!(branch_all_none().is_branch());
}

#[test]
fn empty_branch_is_not_leaf_or_extension() {
    let branch = branch_all_none();
    assert!(!branch.is_leaf());
    assert!(!branch.is_extension());
}

// ── TrieNode::leaf ────────────────────────────────────────────────────────────

#[test]
fn leaf_node_is_leaf_returns_true() {
    assert!(leaf_node(&[1, 2], b"val").is_leaf());
}

#[test]
fn leaf_node_is_not_branch_or_extension() {
    let leaf = leaf_node(&[1], b"v");
    assert!(!leaf.is_branch());
    assert!(!leaf.is_extension());
}

#[test]
fn leaf_node_stores_correct_path_and_value() {
    let TrieNode::Leaf { path, value } = leaf_node(&[3, 5], b"hello") else {
        panic!("expected Leaf");
    };
    assert_eq!(path.as_slice(), &[3, 5]);
    assert_eq!(value, b"hello");
}

// ── TrieNode::extension ───────────────────────────────────────────────────────

#[test]
fn extension_node_is_extension_returns_true() {
    assert!(extension_node(&[1, 2], 0xAA).is_extension());
}

#[test]
fn extension_node_is_not_branch_or_leaf() {
    let ext = extension_node(&[1], 0x11);
    assert!(!ext.is_branch());
    assert!(!ext.is_leaf());
}

#[test]
fn extension_node_stores_correct_prefix_and_child() {
    let child_hash = nonzero_hash(0xCC);
    let TrieNode::Extension { prefix, child } = TrieNode::extension(
        path_from_nibbles(&[7, 8]),
        child_hash,
    ) else {
        panic!("expected Extension");
    };
    assert_eq!(prefix.as_slice(), &[7, 8]);
    assert_eq!(child, child_hash);
}

// ── TrieNode::hash — determinism ──────────────────────────────────────────────

#[test]
fn hash_same_leaf_produces_same_hash() {
    let a = leaf_node(&[1, 2], b"value");
    let b = leaf_node(&[1, 2], b"value");
    assert_eq!(a.hash().unwrap(), b.hash().unwrap());
}

#[test]
fn hash_different_leaf_values_produce_different_hashes() {
    let a = leaf_node(&[1, 2], b"value_a");
    let b = leaf_node(&[1, 2], b"value_b");
    assert_ne!(a.hash().unwrap(), b.hash().unwrap());
}

#[test]
fn hash_different_leaf_paths_produce_different_hashes() {
    let a = leaf_node(&[1, 2], b"value");
    let b = leaf_node(&[1, 3], b"value");
    assert_ne!(a.hash().unwrap(), b.hash().unwrap());
}

#[test]
fn hash_branch_and_leaf_with_similar_content_produce_different_hashes() {
    // A Branch and a Leaf with the same value must hash differently —
    // their serialized forms must include the variant discriminant.
    let leaf = leaf_node(&[], b"val");
    let branch = branch_all_none();
    assert_ne!(leaf.hash().unwrap(), branch.hash().unwrap());
}

#[test]
fn hash_extension_with_different_children_produces_different_hashes() {
    let a = extension_node(&[1], 0xAA);
    let b = extension_node(&[1], 0xBB);
    assert_ne!(a.hash().unwrap(), b.hash().unwrap());
}

#[test]
fn hash_returns_non_zero_hash_for_non_empty_leaf() {
    let h = leaf_node(&[1], b"data").hash().unwrap();
    assert!(!h.is_zero());
}

#[test]
fn hash_result_is_non_empty_storage_error_on_success() {
    // hash() must return Ok — bincode serialize of TrieNode never fails.
    assert!(branch_all_none().hash().is_ok());
    assert!(leaf_node(&[1, 2], b"v").hash().is_ok());
    assert!(extension_node(&[3], 0xAA).hash().is_ok());
}

// ── Bincode round-trips ───────────────────────────────────────────────────────

#[test]
fn bincode_roundtrip_leaf() {
    let original = leaf_node(&[0, 1, 2, 15], b"account_bytes");
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: TrieNode = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_roundtrip_extension() {
    let original = extension_node(&[5, 6, 7], 0xDE);
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: TrieNode = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_roundtrip_branch_all_none() {
    let original = branch_all_none();
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: TrieNode = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_roundtrip_branch_with_some_children() {
    let original = branch_with_child(0xA, 0xDE);
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: TrieNode = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_roundtrip_branch_with_value() {
    let mut children = [None; 16];
    children[3] = Some(nonzero_hash(0x11));
    let original = TrieNode::Branch {
        children,
        value: Some(b"inline_value".to_vec()),
    };
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: TrieNode = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_encoded_nibble_path_is_deterministic() {
    let path = path_from_nibbles(&[1, 2, 3]);
    let enc1 = bincode::serialize(&path).unwrap();
    let enc2 = bincode::serialize(&path).unwrap();
    assert_eq!(enc1, enc2);
}
