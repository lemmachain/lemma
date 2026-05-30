//! Tests for `lemma_core::epoch`.
//!
//! Covers `Epoch`: construction, field storage, and serde round-trip.
//! 100% public API coverage per AGENTS.md §11.1.

use std::collections::BTreeMap;

use super::*;
use crate::{
    address::Address,
    amount::Amount,
    validator::ConsensusKey,
    validator::VotingPower,
    validator_set::{Member, ValidatorSet},
};

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn test_epoch() -> Epoch {
    let mut members = BTreeMap::new();
    members.insert(
        Address::zero(),
        Member {
            consensus_pubkey: ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952]),
            power: VotingPower(Amount::from_drop(1_000)),
        },
    );
    Epoch {
        number: 0,
        start_height: 0,
        start_timestamp: 1_700_000_000,
        validators: ValidatorSet {
            epoch: 0,
            members,
            total_power: Amount::from_drop(1_000),
        },
    }
}

// ── Construction / fields ────────────────────────────────────────────────────

#[test]
fn epoch_stores_all_fields() {
    let e = test_epoch();
    assert_eq!(e.number, 0);
    assert_eq!(e.start_height, 0);
    assert_eq!(e.start_timestamp, 1_700_000_000);
    assert_eq!(e.validators.epoch, 0);
    assert_eq!(e.validators.len(), 1);
}

// ── Serde ────────────────────────────────────────────────────────────────────

#[test]
fn epoch_serde_roundtrip() {
    let original = test_epoch();
    let json = serde_json::to_string(&original).expect("Epoch should serialize");
    let decoded: Epoch = serde_json::from_str(&json).expect("Epoch should deserialize");
    assert_eq!(decoded, original);
}
