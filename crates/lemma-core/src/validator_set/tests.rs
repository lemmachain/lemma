//! Tests for `lemma_core::validator_set`.
//!
//! Covers `ValidatorSet` and `Member`: hash determinism, accessors,
//! and serde round-trips.
//! 100% public API coverage per AGENTS.md §11.1.

use std::collections::BTreeMap;

use super::*;
use crate::amount::Amount;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn test_consensus_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952])
}

fn single_member_set() -> ValidatorSet {
    let mut members = BTreeMap::new();
    let power = VotingPower(Amount::from_drop(1_000));
    members.insert(
        Address::zero(),
        Member {
            consensus_pubkey: test_consensus_key(),
            power,
        },
    );
    ValidatorSet {
        epoch: 0,
        members,
        total_power: Amount::from_drop(1_000),
    }
}

// ── hash ─────────────────────────────────────────────────────────────────────

#[test]
fn validator_set_hash_is_deterministic() {
    let set = single_member_set();
    let h1 = set.hash();
    let h2 = set.hash();
    assert_eq!(h1, h2);
}

#[test]
fn validator_set_hash_differs_for_different_members() {
    let set1 = single_member_set();

    let mut members2 = BTreeMap::new();
    members2.insert(
        Address::burn(), // different address
        Member {
            consensus_pubkey: test_consensus_key(),
            power: VotingPower(Amount::from_drop(1_000)),
        },
    );
    let set2 = ValidatorSet {
        epoch: 0,
        members: members2,
        total_power: Amount::from_drop(1_000),
    };

    assert_ne!(set1.hash(), set2.hash());
}

#[test]
fn validator_set_hash_differs_for_different_power() {
    let set1 = single_member_set();

    let mut members2 = BTreeMap::new();
    members2.insert(
        Address::zero(), // same address
        Member {
            consensus_pubkey: test_consensus_key(),
            power: VotingPower(Amount::from_drop(2_000)), // different power
        },
    );
    let set2 = ValidatorSet {
        epoch: 0,
        members: members2,
        total_power: Amount::from_drop(2_000),
    };

    assert_ne!(set1.hash(), set2.hash());
}

// ── len / is_empty ───────────────────────────────────────────────────────────

#[test]
fn validator_set_len_and_is_empty() {
    let empty = ValidatorSet {
        epoch: 0,
        members: BTreeMap::new(),
        total_power: Amount::zero(),
    };
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());

    let non_empty = single_member_set();
    assert_eq!(non_empty.len(), 1);
    assert!(!non_empty.is_empty());
}

// ── Serde ────────────────────────────────────────────────────────────────────

#[test]
fn validator_set_serde_roundtrip() {
    let original = single_member_set();
    let json = serde_json::to_string(&original).expect("ValidatorSet should serialize");
    let decoded: ValidatorSet =
        serde_json::from_str(&json).expect("ValidatorSet should deserialize");
    assert_eq!(decoded, original);
}
