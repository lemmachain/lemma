//! Tests for `lemma_core::genesis`.
//!
//! Covers `GenesisConfig`: construction, validation rules, predicates,
//! accessors, serde round-trips, and derived traits.
//! 100% public API coverage per AGENTS.md §11.1.

use std::collections::BTreeMap;

use super::*;
use crate::{
    address::Address,
    amount::Amount,
    error::{BlockError, CoreError, ValidatorError},
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus},
};

// NOTE: Each constraint in validate() must have a corresponding negative test
// here. Current constraints: initial_gas_limit > 0, genesis_validators non-empty,
// genesis validators have non-zero active stake.

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn base_fee() -> Amount {
    Amount::from_drop(1_000_000_000) // 1 Drip
}

fn funded_address() -> Address {
    Address::zero()
}

fn other_address() -> Address {
    Address::burn()
}

fn one_lem() -> Amount {
    Amount::from_lem(1).unwrap()
}

fn half_drip() -> Amount {
    Amount::from_drop(500_000)
}

fn test_validator() -> Validator {
    Validator {
        address: Address::zero(),
        consensus_pubkey: ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952]),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active: Amount::from_drop(1_000_000_000_000_000_000), // 1 LEM
            pending_active: Amount::zero(),
            pending_inactive: Vec::new(),
            inactive: Amount::zero(),
        },
        delegated: Amount::zero(),
        commission_bps: 500, // 5%
        jailed_until: None,
    }
}

/// Minimal genesis with no pre-funded accounts and no validators.
/// NOT valid for `validate()` — use `genesis_with_validators()` for tests
/// that call `validate()` and expect `Ok(())`.
fn empty_genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: 1,
        genesis_timestamp: 1_700_000_000,
        initial_gas_limit: 30_000_000,
        initial_base_fee: base_fee(),
        initial_balances: BTreeMap::new(),
        genesis_validators: BTreeMap::new(),
    }
}

/// Genesis with one pre-funded account but no validators.
/// NOT valid for `validate()` — use `genesis_with_validators()` for tests
/// that call `validate()` and expect `Ok(())`.
fn funded_genesis() -> GenesisConfig {
    let mut balances = BTreeMap::new();
    balances.insert(funded_address(), one_lem());
    GenesisConfig {
        chain_id: 1,
        genesis_timestamp: 1_700_000_000,
        initial_gas_limit: 30_000_000,
        initial_base_fee: base_fee(),
        initial_balances: balances,
        genesis_validators: BTreeMap::new(),
    }
}

/// Minimal valid genesis with one validator — passes `validate()`.
fn genesis_with_validators() -> GenesisConfig {
    let val = test_validator();
    let mut validators = BTreeMap::new();
    validators.insert(val.address, val);
    GenesisConfig {
        genesis_validators: validators,
        ..empty_genesis()
    }
}

// ── validate — happy path ─────────────────────────────────────────────────────

#[test]
fn validate_returns_ok_for_genesis_with_validators() {
    assert!(genesis_with_validators().validate().is_ok());
}

#[test]
fn validate_accepts_valid_genesis_with_zero_base_fee() {
    let config = GenesisConfig {
        initial_base_fee: Amount::zero(),
        ..genesis_with_validators()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_valid_genesis_with_funded_accounts() {
    let mut balances = BTreeMap::new();
    balances.insert(funded_address(), one_lem());
    let config = GenesisConfig {
        initial_balances: balances,
        ..genesis_with_validators()
    };
    assert!(config.validate().is_ok());
}

// ── validate — negative paths ─────────────────────────────────────────────────

#[test]
fn validate_rejects_zero_initial_gas_limit() {
    // gas_limit == 0 is checked before validators, so empty validators is fine here.
    let config = GenesisConfig {
        initial_gas_limit: 0, // invalid
        ..empty_genesis()
    };
    assert!(matches!(
        config.validate().unwrap_err(),
        CoreError::Block(BlockError::GasLimitZero)
    ));
}

#[test]
fn validate_rejects_empty_genesis_validators() {
    // empty_genesis() has no validators — validate() should reject it.
    let config = empty_genesis();
    assert!(matches!(
        config.validate().unwrap_err(),
        CoreError::Validator(ValidatorError::EmptyGenesisValidators)
    ));
}

#[test]
fn validate_rejects_zero_stake_genesis_validator() {
    let mut val = test_validator();
    val.self_stake.active = Amount::zero(); // invalid — zero active stake
    let mut validators = BTreeMap::new();
    validators.insert(val.address, val);
    let config = GenesisConfig {
        genesis_validators: validators,
        ..empty_genesis()
    };
    assert!(matches!(
        config.validate().unwrap_err(),
        CoreError::Validator(ValidatorError::ZeroGenesisStake { .. })
    ));
}

// ── is_empty ──────────────────────────────────────────────────────────────────

#[test]
fn is_empty_returns_true_for_genesis_with_no_balances() {
    assert!(empty_genesis().is_empty());
}

#[test]
fn is_empty_returns_false_for_genesis_with_balances() {
    assert!(!funded_genesis().is_empty());
}

// ── account_count ─────────────────────────────────────────────────────────────

#[test]
fn account_count_returns_zero_for_empty_genesis() {
    assert_eq!(empty_genesis().account_count(), 0);
}

#[test]
fn account_count_returns_one_for_single_funded_account() {
    assert_eq!(funded_genesis().account_count(), 1);
}

#[test]
fn account_count_returns_correct_count_for_multiple_accounts() {
    let mut balances = BTreeMap::new();
    balances.insert(funded_address(), one_lem());
    balances.insert(other_address(), half_drip());
    let config = GenesisConfig {
        initial_balances: balances,
        ..empty_genesis()
    };
    assert_eq!(config.account_count(), 2);
}

// ── balance_of ────────────────────────────────────────────────────────────────

#[test]
fn balance_of_returns_some_for_funded_address() {
    assert_eq!(
        funded_genesis().balance_of(&funded_address()),
        Some(&one_lem())
    );
}

#[test]
fn balance_of_returns_none_for_unfunded_address() {
    assert!(empty_genesis().balance_of(&funded_address()).is_none());
}

#[test]
fn balance_of_returns_none_for_address_not_in_genesis() {
    // funded_genesis only has funded_address(); other_address() has no entry.
    assert!(funded_genesis().balance_of(&other_address()).is_none());
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[test]
fn empty_genesis_roundtrips_through_json() {
    let original = empty_genesis();
    let json = serde_json::to_string(&original).expect("GenesisConfig should serialize to JSON");
    let decoded: GenesisConfig =
        serde_json::from_str(&json).expect("GenesisConfig should deserialize from JSON");
    assert_eq!(decoded, original);
}

#[test]
fn funded_genesis_roundtrips_through_json() {
    let original = funded_genesis();
    let json = serde_json::to_string(&original).expect("GenesisConfig should serialize to JSON");
    let decoded: GenesisConfig =
        serde_json::from_str(&json).expect("GenesisConfig should deserialize from JSON");
    assert_eq!(decoded, original);
}

#[test]
fn genesis_with_multiple_accounts_roundtrips_through_json() {
    let mut balances = BTreeMap::new();
    balances.insert(funded_address(), one_lem());
    balances.insert(other_address(), Amount::from_drop(500_000));
    let original = GenesisConfig {
        initial_balances: balances,
        ..empty_genesis()
    };

    let json = serde_json::to_string(&original).expect("GenesisConfig should serialize to JSON");
    let decoded: GenesisConfig =
        serde_json::from_str(&json).expect("GenesisConfig should deserialize from JSON");
    assert_eq!(decoded, original);
}

#[test]
fn genesis_with_validators_roundtrips_through_json() {
    let original = genesis_with_validators();
    let json = serde_json::to_string(&original).expect("GenesisConfig should serialize to JSON");
    let decoded: GenesisConfig =
        serde_json::from_str(&json).expect("GenesisConfig should deserialize from JSON");
    assert_eq!(decoded, original);
}

#[test]
fn genesis_deserialized_from_json_literal_has_correct_chain_id() {
    // Validates that real genesis JSON files (as would be shipped with the node)
    // deserialize correctly. The key names must match the serde field names.
    let json = r#"{
        "chain_id": 2,
        "genesis_timestamp": 1700000000,
        "initial_gas_limit": 30000000,
        "initial_base_fee": "1000000000",
        "initial_balances": {},
        "genesis_validators": {}
    }"#;
    let config: GenesisConfig =
        serde_json::from_str(json).expect("Literal genesis JSON should deserialize correctly");
    assert_eq!(config.chain_id, 2);
    assert_eq!(config.genesis_timestamp, 1_700_000_000);
    assert_eq!(config.initial_gas_limit, 30_000_000);
    assert_eq!(config.initial_base_fee, Amount::from_drop(1_000_000_000));
    assert!(config.initial_balances.is_empty());
    assert!(config.genesis_validators.is_empty());
}

// ── Clone / PartialEq ─────────────────────────────────────────────────────────

#[test]
fn genesis_clone_equals_original() {
    let config = funded_genesis();
    assert_eq!(config.clone(), config);
}

#[test]
fn genesis_configs_with_different_chain_ids_are_not_equal() {
    let g1 = GenesisConfig {
        chain_id: 1,
        ..empty_genesis()
    };
    let g2 = GenesisConfig {
        chain_id: 2,
        ..empty_genesis()
    };
    assert_ne!(g1, g2);
}

#[test]
fn genesis_configs_with_different_balances_are_not_equal() {
    let g1 = empty_genesis();
    let g2 = funded_genesis();
    assert_ne!(g1, g2);
}

// ── BTreeMap ordering guarantee ───────────────────────────────────────────────

#[test]
fn initial_balances_iteration_is_deterministic_regardless_of_insertion_order() {
    // BTreeMap always iterates in key-sorted order — two configs with the same
    // entries but inserted in different order must produce the same serialized JSON.
    // This is required for reproducible genesis state root computation (AGENTS.md §7.1).
    let mut b1 = BTreeMap::new();
    b1.insert(funded_address(), one_lem());
    b1.insert(other_address(), half_drip());

    let mut b2 = BTreeMap::new();
    b2.insert(other_address(), half_drip()); // reversed insertion order
    b2.insert(funded_address(), one_lem());

    let c1 = GenesisConfig {
        initial_balances: b1,
        ..empty_genesis()
    };
    let c2 = GenesisConfig {
        initial_balances: b2,
        ..empty_genesis()
    };

    // PartialEq on BTreeMap compares entries, not insertion order.
    assert_eq!(c1, c2);
    // Serialization must also be identical (JSON key order follows BTreeMap order).
    let json1 = serde_json::to_string(&c1).unwrap();
    let json2 = serde_json::to_string(&c2).unwrap();
    assert_eq!(json1, json2);
}
