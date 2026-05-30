//! Tests for `lemma_core::hash`.
//!
//! Covers construction, display, parsing, serde, and all derived/manual trait
//! implementations. 100% public API coverage per AGENTS.md §11.1.

use std::collections::HashMap;
use std::str::FromStr;

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// A known non-zero 32-byte array for deterministic test assertions.
fn known_bytes() -> [u8; 32] {
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]
}

const KNOWN_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

fn known_hash() -> Hash {
    Hash::from_bytes(known_bytes())
}

// ── zero() ────────────────────────────────────────────────────────────────────

#[test]
fn zero_returns_all_zero_bytes() {
    assert_eq!(Hash::zero().as_bytes(), &[0u8; 32]);
}

#[test]
fn zero_is_zero_returns_true() {
    assert!(Hash::zero().is_zero());
}

#[test]
fn zero_displays_as_64_zero_hex_chars() {
    assert_eq!(Hash::zero().to_string(), "0".repeat(64));
}

// ── from_bytes() ──────────────────────────────────────────────────────────────

#[test]
fn from_bytes_roundtrips_to_as_bytes() {
    let bytes = known_bytes();
    let hash = Hash::from_bytes(bytes);
    assert_eq!(hash.as_bytes(), &bytes);
}

#[test]
fn from_bytes_is_const_evaluable() {
    // Ensure const fn compiles and produces the correct value at compile time.
    const H: Hash = Hash::from_bytes([0xffu8; 32]);
    assert_eq!(H.as_bytes(), &[0xffu8; 32]);
}

// ── from_slice() ──────────────────────────────────────────────────────────────

#[test]
fn from_slice_accepts_exactly_32_bytes() {
    let hash = Hash::from_slice(&[0xabu8; 32]).expect("32-byte slice must succeed");
    assert_eq!(hash.as_bytes(), &[0xabu8; 32]);
}

#[test]
fn from_slice_rejects_slice_shorter_than_32_bytes() {
    let err = Hash::from_slice(&[0u8; 16]).unwrap_err();
    assert_eq!(err, crate::error::HashError::InvalidLength { got: 16 });
}

#[test]
fn from_slice_rejects_slice_longer_than_32_bytes() {
    let err = Hash::from_slice(&[0u8; 33]).unwrap_err();
    assert_eq!(err, crate::error::HashError::InvalidLength { got: 33 });
}

#[test]
fn from_slice_rejects_empty_slice() {
    let err = Hash::from_slice(&[]).unwrap_err();
    assert_eq!(err, crate::error::HashError::InvalidLength { got: 0 });
}

// ── to_hex() ─────────────────────────────────────────────────────────────────

#[test]
fn to_hex_produces_lowercase_64_char_string() {
    let hex = known_hash().to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex
        .chars()
        .all(|c| c.is_ascii_alphanumeric() && !c.is_uppercase()));
}

#[test]
fn to_hex_matches_known_value() {
    assert_eq!(known_hash().to_hex(), KNOWN_HEX);
}

// ── is_zero() ─────────────────────────────────────────────────────────────────

#[test]
fn is_zero_returns_false_for_nonzero_hash() {
    assert!(!known_hash().is_zero());
}

#[test]
fn is_zero_returns_false_for_single_nonzero_byte() {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    assert!(!Hash::from_bytes(bytes).is_zero());
}

// ── Display ───────────────────────────────────────────────────────────────────

#[test]
fn display_matches_to_hex() {
    let hash = known_hash();
    assert_eq!(hash.to_string(), hash.to_hex());
}

#[test]
fn display_is_lowercase() {
    let hash = known_hash();
    let s = hash.to_string();
    assert_eq!(s, s.to_lowercase());
}

// ── Debug ─────────────────────────────────────────────────────────────────────

#[test]
fn debug_wraps_hex_in_hash_prefix() {
    let hash = known_hash();
    assert_eq!(format!("{:?}", hash), format!("Hash({})", KNOWN_HEX));
}

#[test]
fn debug_zero_hash_shows_all_zeros() {
    assert_eq!(
        format!("{:?}", Hash::zero()),
        format!("Hash({})", "0".repeat(64))
    );
}

// ── FromStr ───────────────────────────────────────────────────────────────────

#[test]
fn from_str_parses_valid_lowercase_hex() {
    let hash = Hash::from_str(KNOWN_HEX).unwrap();
    assert_eq!(hash, known_hash());
}

#[test]
fn from_str_roundtrips_display() {
    let original = known_hash();
    let parsed = Hash::from_str(&original.to_string()).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn from_str_rejects_non_hex_characters() {
    let err = Hash::from_str(&"g".repeat(64)).unwrap_err();
    assert!(matches!(err, crate::error::HashError::InvalidHex { .. }));
}

#[test]
fn from_str_rejects_hex_string_too_short() {
    // 62 hex chars = 31 bytes
    let err = Hash::from_str(&"aa".repeat(31)).unwrap_err();
    assert_eq!(err, crate::error::HashError::InvalidLength { got: 31 });
}

#[test]
fn from_str_rejects_hex_string_too_long() {
    // 66 hex chars = 33 bytes
    let err = Hash::from_str(&"aa".repeat(33)).unwrap_err();
    assert_eq!(err, crate::error::HashError::InvalidLength { got: 33 });
}

#[test]
fn from_str_rejects_empty_string() {
    let err = Hash::from_str("").unwrap_err();
    assert_eq!(err, crate::error::HashError::InvalidLength { got: 0 });
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[test]
fn serialize_to_json_produces_hex_string() {
    let hash = known_hash();
    let json = serde_json::to_string(&hash).unwrap();
    // JSON string wraps value in quotes
    assert_eq!(json, format!("\"{}\"", KNOWN_HEX));
}

#[test]
fn deserialize_from_json_hex_string_roundtrips() {
    let hash = known_hash();
    let json = serde_json::to_string(&hash).unwrap();
    let decoded: Hash = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, hash);
}

#[test]
fn deserialize_rejects_invalid_hex_json() {
    let result = serde_json::from_str::<Hash>("\"not-hex\"");
    assert!(result.is_err());
}

#[test]
fn serialize_zero_hash_to_json_is_all_zero_hex() {
    let json = serde_json::to_string(&Hash::zero()).unwrap();
    assert_eq!(json, format!("\"{}\"", "00".repeat(32)));
}

// ── Clone + Copy ──────────────────────────────────────────────────────────────

#[test]
fn clone_produces_equal_hash() {
    let original = known_hash();
    // Deliberately exercise the `Clone` impl (distinct from the `Copy` test below).
    // `Hash` is `Copy`, so clippy flags this — but the explicit `.clone()` call IS
    // the unit under test here. Targeted allow per AGENTS.md §4.1.
    #[allow(clippy::clone_on_copy)]
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn copy_semantics_work_correctly() {
    let original = known_hash();
    let copied = original; // Copy, not move
                           // Both are usable after copy
    assert_eq!(original, copied);
    assert_eq!(original.to_hex(), copied.to_hex());
}

// ── PartialEq + Eq ────────────────────────────────────────────────────────────

#[test]
fn equal_hashes_are_equal() {
    assert_eq!(known_hash(), known_hash());
}

#[test]
fn different_hashes_are_not_equal() {
    assert_ne!(known_hash(), Hash::zero());
}

#[test]
fn hash_that_differs_by_one_byte_is_not_equal() {
    let mut bytes = known_bytes();
    bytes[0] ^= 0xff;
    assert_ne!(Hash::from_bytes(bytes), known_hash());
}

// ── std::hash::Hash (usable in HashMap/HashSet) ───────────────────────────────

#[test]
fn hash_can_be_used_as_hashmap_key() {
    let mut map: HashMap<Hash, &str> = HashMap::new();
    map.insert(known_hash(), "block_a");
    map.insert(Hash::zero(), "genesis");

    assert_eq!(*map.get(&known_hash()).unwrap(), "block_a");
    assert_eq!(*map.get(&Hash::zero()).unwrap(), "genesis");
}

#[test]
fn same_hash_bytes_produce_same_map_lookup() {
    let mut map: HashMap<Hash, u64> = HashMap::new();
    map.insert(known_hash(), 42);

    // Construct the same hash a second way — must produce the same key
    let same_hash = Hash::from_slice(&known_bytes()).unwrap();
    assert_eq!(*map.get(&same_hash).unwrap(), 42);
}
