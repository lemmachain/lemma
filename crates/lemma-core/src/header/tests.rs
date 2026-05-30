//! Tests for `lemma_core::header`.
//!
//! Covers `BlockHeader`: construction, validation rules, predicates,
//! gas accounting, serde round-trips, and derived traits.
//! 100% public API coverage per AGENTS.md §11.1.

use super::*;
use crate::{address::Address, amount::Amount, hash::Hash};

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn state_root() -> Hash {
    Hash::from_bytes([0xABu8; 32])
}

fn proposer() -> Address {
    Address::zero()
}

fn base_fee() -> Amount {
    Amount::from_drop(1_000_000_000) // 1 Drip
}

/// Minimal valid genesis header (height 0, gas_used 0).
fn genesis_header() -> BlockHeader {
    BlockHeader::new(
        0,
        1_700_000_000,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        30_000_000,
        0,
        base_fee(),
        vec![],
    )
    .unwrap()
}

/// Minimal valid non-genesis header (height 1, gas_used exactly at 50%).
fn block_1_header() -> BlockHeader {
    BlockHeader::new(
        1,
        1_700_000_001,
        Hash::from_bytes([0x01u8; 32]), // parent = some block hash
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        30_000_000,
        15_000_000, // exactly 50% — not above target
        base_fee(),
        vec![],
    )
    .unwrap()
}

// ── Construction ──────────────────────────────────────────────────────────────

#[test]
fn new_genesis_header_with_valid_fields_succeeds() {
    let h = genesis_header();
    assert_eq!(h.height, 0);
    assert_eq!(h.gas_used, 0);
    assert_eq!(h.gas_limit, 30_000_000);
}

#[test]
fn new_non_genesis_header_with_valid_fields_succeeds() {
    let h = block_1_header();
    assert_eq!(h.height, 1);
    assert_eq!(h.gas_used, 15_000_000);
}

#[test]
fn new_header_with_gas_used_equal_to_limit_succeeds() {
    let result = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        21_000,
        21_000, // gas_used == gas_limit is valid
        base_fee(),
        vec![],
    );
    assert!(result.is_ok());
}

#[test]
fn new_header_stores_all_fields_correctly() {
    let extra = vec![0x01, 0x02, 0x03];
    let tx_root = Hash::from_bytes([0xBBu8; 32]);
    let rcpt_root = Hash::from_bytes([0xCCu8; 32]);
    let custom_fee = Amount::from_drop(2_000_000_000);

    let h = BlockHeader::new(
        5,
        1_700_005_000,
        Hash::zero(),
        tx_root,
        state_root(),
        rcpt_root,
        Address::burn(),
        50_000_000,
        10_000_000,
        custom_fee,
        extra.clone(),
    )
    .unwrap();

    assert_eq!(h.height, 5);
    assert_eq!(h.timestamp, 1_700_005_000);
    assert_eq!(h.parent_hash, Hash::zero());
    assert_eq!(h.transactions_root, tx_root);
    assert_eq!(h.state_root, state_root());
    assert_eq!(h.receipts_root, rcpt_root);
    assert_eq!(h.proposer, Address::burn());
    assert_eq!(h.gas_limit, 50_000_000);
    assert_eq!(h.gas_used, 10_000_000);
    assert_eq!(h.base_fee, custom_fee);
    assert_eq!(h.extra_data, extra);
}

// ── Validation failures ───────────────────────────────────────────────────────

#[test]
fn new_header_rejects_zero_gas_limit() {
    let result = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0, // gas_limit = 0 — invalid
        0,
        base_fee(),
        vec![],
    );
    assert_eq!(result.unwrap_err(), BlockError::GasLimitZero);
}

#[test]
fn new_header_rejects_gas_used_exceeding_gas_limit() {
    let result = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        21_000,
        21_001, // gas_used > gas_limit
        base_fee(),
        vec![],
    );
    assert!(matches!(
        result.unwrap_err(),
        BlockError::GasExceeded {
            used: 21_001,
            limit: 21_000
        }
    ));
}

// ── validate — happy path ─────────────────────────────────────────────────────

#[test]
fn validate_returns_ok_for_valid_genesis_header() {
    assert!(genesis_header().validate().is_ok());
}

#[test]
fn validate_returns_ok_for_valid_non_genesis_header() {
    assert!(block_1_header().validate().is_ok());
}

// ── validate — negative paths (direct construction bypasses new()) ────────────

#[test]
fn validate_rejects_zero_gas_limit_on_deserialized_header() {
    // Bypass new() to simulate a tampered deserialized header — the exact
    // scenario validate() guards against post-deserialization.
    let h = BlockHeader {
        height: 1,
        timestamp: 1_700_000_001,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: state_root(),
        receipts_root: Hash::zero(),
        proposer: proposer(),
        gas_limit: 0, // tampered
        gas_used: 0,
        base_fee: base_fee(),
        extra_data: vec![],
    };
    assert_eq!(h.validate().unwrap_err(), BlockError::GasLimitZero);
}

#[test]
fn validate_rejects_gas_exceeded_on_deserialized_header() {
    let h = BlockHeader {
        height: 1,
        timestamp: 1_700_000_001,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: state_root(),
        receipts_root: Hash::zero(),
        proposer: proposer(),
        gas_limit: 1_000,
        gas_used: 2_000, // tampered
        base_fee: base_fee(),
        extra_data: vec![],
    };
    assert!(matches!(
        h.validate().unwrap_err(),
        BlockError::GasExceeded {
            used: 2_000,
            limit: 1_000
        }
    ));
}

// ── is_genesis ────────────────────────────────────────────────────────────────

#[test]
fn is_genesis_returns_true_for_height_zero() {
    assert!(genesis_header().is_genesis());
}

#[test]
fn is_genesis_returns_false_for_height_one() {
    assert!(!block_1_header().is_genesis());
}

#[test]
fn is_genesis_returns_false_for_large_height() {
    let mut h = genesis_header();
    h.height = 1_000_000;
    assert!(!h.is_genesis());
}

// ── is_above_target_gas ───────────────────────────────────────────────────────

#[test]
fn is_above_target_gas_false_when_gas_used_is_zero() {
    assert!(!genesis_header().is_above_target_gas());
}

#[test]
fn is_above_target_gas_false_when_gas_used_equals_target() {
    // gas_limit = 30_000_000 → target = 15_000_000
    // gas_used = 15_000_000 — equal to target, not above it
    assert!(!block_1_header().is_above_target_gas());
}

#[test]
fn is_above_target_gas_true_when_gas_used_exceeds_half() {
    let h = BlockHeader::new(
        2,
        1_700_000_002,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        30_000_000,
        15_000_001, // one unit above target
        base_fee(),
        vec![],
    )
    .unwrap();
    assert!(h.is_above_target_gas());
}

#[test]
fn is_above_target_gas_true_when_block_is_full() {
    let h = BlockHeader::new(
        2,
        1_700_000_002,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        30_000_000,
        30_000_000, // 100% full
        base_fee(),
        vec![],
    )
    .unwrap();
    assert!(h.is_above_target_gas());
}

#[test]
fn is_above_target_gas_false_when_gas_limit_is_one_and_gas_used_is_zero() {
    // gas_limit=1 → target = 1/2 = 0 (truncates). gas_used=0 → 0 > 0 is false.
    let h = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        1,
        0,
        base_fee(),
        vec![],
    )
    .unwrap();
    assert!(!h.is_above_target_gas());
}

#[test]
fn is_above_target_gas_true_when_gas_limit_is_one_and_gas_used_is_one() {
    // gas_limit=1 → target = 0. gas_used=1 → 1 > 0 is true.
    let h = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        1,
        1,
        base_fee(),
        vec![],
    )
    .unwrap();
    assert!(h.is_above_target_gas());
}

// ── gas_remaining ─────────────────────────────────────────────────────────────

#[test]
fn gas_remaining_equals_limit_when_gas_used_is_zero() {
    assert_eq!(genesis_header().gas_remaining(), 30_000_000);
}

#[test]
fn gas_remaining_returns_correct_headroom() {
    assert_eq!(block_1_header().gas_remaining(), 15_000_000);
}

#[test]
fn gas_remaining_is_zero_when_block_is_full() {
    let h = BlockHeader::new(
        2,
        1_700_000_002,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        21_000,
        21_000,
        base_fee(),
        vec![],
    )
    .unwrap();
    assert_eq!(h.gas_remaining(), 0);
}

#[test]
fn gas_remaining_is_correct_at_max_gas_limit() {
    // Verifies the subtraction doesn't overflow at the u64 boundary.
    // validate() guarantees gas_used <= gas_limit, making this subtraction safe.
    let h = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        u64::MAX,
        u64::MAX - 1,
        base_fee(),
        vec![],
    )
    .unwrap();
    assert_eq!(h.gas_remaining(), 1);
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[test]
fn genesis_header_roundtrips_through_json() {
    let original = genesis_header();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: BlockHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn header_with_extra_data_roundtrips_through_json() {
    let original = BlockHeader::new(
        3,
        1_700_000_003,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        30_000_000,
        5_000_000,
        base_fee(),
        vec![0x1E, 0x8A, 0xAA],
    )
    .unwrap();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: BlockHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

// ── Clone / PartialEq ─────────────────────────────────────────────────────────

#[test]
fn header_clone_equals_original() {
    let h = genesis_header();
    assert_eq!(h.clone(), h);
}

#[test]
fn headers_with_different_heights_are_not_equal() {
    let h0 = genesis_header();
    let h1 = block_1_header();
    assert_ne!(h0, h1);
}

#[test]
fn headers_with_different_state_roots_are_not_equal() {
    let h1 = genesis_header();
    let mut h2 = genesis_header();
    h2.state_root = Hash::from_bytes([0xFFu8; 32]);
    assert_ne!(h1, h2);
}
