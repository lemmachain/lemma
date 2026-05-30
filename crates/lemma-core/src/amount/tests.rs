//! Tests for `lemma_core::amount`.
//!
//! Covers constants, construction, access, checked arithmetic, display
//! formats, serde, and all derived/manual trait implementations.
//! 100% public API coverage per AGENTS.md §11.1.

// HashMap is used only for key-lookup tests (no iteration — no order dependency).
// For any test requiring deterministic iteration, use BTreeMap per AGENTS.md §7.1.
use std::collections::HashMap;

use super::*;
use crate::error::AmountError;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn one_lem() -> Amount {
    Amount::from_lem(1).expect("1 LEM must not overflow")
}

fn one_drip() -> Amount {
    Amount::from_drip(1).expect("1 Drip must not overflow")
}

fn half_lem() -> Amount {
    Amount::from_drop(DROPS_PER_LEM / 2)
}

// ── Unit constants ────────────────────────────────────────────────────────────

#[test]
fn drops_per_lem_is_1e18() {
    assert_eq!(DROPS_PER_LEM, 1_000_000_000_000_000_000u128);
}

#[test]
fn drips_per_lem_is_1e9() {
    assert_eq!(DRIPS_PER_LEM, 1_000_000_000u128);
}

#[test]
fn drops_per_drip_is_1e9() {
    assert_eq!(DROPS_PER_DRIP, 1_000_000_000u128);
}

#[test]
fn drops_per_lem_equals_drips_per_lem_times_drops_per_drip() {
    // Invariant: 1 LEM = DRIPS_PER_LEM Drips = DROPS_PER_LEM Drops
    assert_eq!(DRIPS_PER_LEM * DROPS_PER_DRIP, DROPS_PER_LEM);
}

// ── zero() ────────────────────────────────────────────────────────────────────

#[test]
fn zero_returns_zero_drop_count() {
    assert_eq!(Amount::zero().as_drop(), 0);
}

#[test]
fn zero_is_zero_returns_true() {
    assert!(Amount::zero().is_zero());
}

// ── from_drop() ───────────────────────────────────────────────────────────────

#[test]
fn from_drop_stores_exact_value() {
    assert_eq!(Amount::from_drop(42).as_drop(), 42);
}

#[test]
fn from_drop_accepts_zero() {
    assert_eq!(Amount::from_drop(0).as_drop(), 0);
}

#[test]
fn from_drop_accepts_u128_max() {
    assert_eq!(Amount::from_drop(u128::MAX).as_drop(), u128::MAX);
}

// ── from_lem() ────────────────────────────────────────────────────────────────

#[test]
fn from_lem_converts_one_lem_to_drops() {
    assert_eq!(one_lem().as_drop(), DROPS_PER_LEM);
}

#[test]
fn from_lem_converts_zero_lem_to_zero_drops() {
    assert_eq!(Amount::from_lem(0).unwrap().as_drop(), 0);
}

#[test]
fn from_lem_converts_multiple_lem_correctly() {
    let five = Amount::from_lem(5).unwrap();
    assert_eq!(five.as_drop(), 5 * DROPS_PER_LEM);
}

#[test]
fn from_lem_returns_overflow_error_on_very_large_value() {
    // u128::MAX / DROPS_PER_LEM ≈ 340. Values above this overflow.
    let result = Amount::from_lem(u128::MAX);
    assert!(matches!(result, Err(AmountError::Overflow { .. })));
}

#[test]
fn from_lem_overflow_error_contains_operands() {
    let lem = u128::MAX;
    match Amount::from_lem(lem) {
        Err(AmountError::Overflow { lhs, rhs }) => {
            assert_eq!(lhs, lem);
            assert_eq!(rhs, DROPS_PER_LEM);
        }
        _ => panic!("expected Overflow error"),
    }
}

// ── from_drip() ───────────────────────────────────────────────────────────────

#[test]
fn from_drip_converts_one_drip_to_drops() {
    assert_eq!(one_drip().as_drop(), DROPS_PER_DRIP);
}

#[test]
fn from_drip_converts_zero_drips_to_zero_drops() {
    assert_eq!(Amount::from_drip(0).unwrap().as_drop(), 0);
}

#[test]
fn from_drip_converts_multiple_drips_correctly() {
    let gas_price = Amount::from_drip(10).unwrap();
    assert_eq!(gas_price.as_drop(), 10 * DROPS_PER_DRIP);
}

#[test]
fn from_drip_returns_overflow_error_on_very_large_value() {
    let result = Amount::from_drip(u128::MAX);
    assert!(matches!(result, Err(AmountError::Overflow { .. })));
}

#[test]
fn from_drip_overflow_error_contains_operands() {
    let drips = u128::MAX;
    match Amount::from_drip(drips) {
        Err(AmountError::Overflow { lhs, rhs }) => {
            assert_eq!(lhs, drips);
            assert_eq!(rhs, DROPS_PER_DRIP);
        }
        _ => panic!("expected Overflow error with operands"),
    }
}

// ── as_drop() ─────────────────────────────────────────────────────────────────

#[test]
fn as_drop_returns_raw_u128_value() {
    let raw = 999_999_999_999_999_999u128;
    assert_eq!(Amount::from_drop(raw).as_drop(), raw);
}

// ── is_zero() ─────────────────────────────────────────────────────────────────

#[test]
fn is_zero_returns_false_for_nonzero_amount() {
    assert!(!one_lem().is_zero());
}

#[test]
fn is_zero_returns_false_for_single_drop() {
    assert!(!Amount::from_drop(1).is_zero());
}

// ── checked_add() ────────────────────────────────────────────────────────────

#[test]
fn checked_add_sums_two_amounts() {
    let sum = one_lem().checked_add(one_drip()).unwrap();
    assert_eq!(sum.as_drop(), DROPS_PER_LEM + DROPS_PER_DRIP);
}

#[test]
fn checked_add_zero_returns_original() {
    assert_eq!(one_lem().checked_add(Amount::zero()).unwrap(), one_lem());
}

#[test]
fn checked_add_returns_overflow_error_at_u128_max() {
    let max = Amount::from_drop(u128::MAX);
    let one = Amount::from_drop(1);
    let result = max.checked_add(one);
    assert!(matches!(
        result,
        Err(AmountError::Overflow {
            lhs: u128::MAX,
            rhs: 1
        })
    ));
}

// ── checked_sub() ────────────────────────────────────────────────────────────

#[test]
fn checked_sub_returns_correct_difference() {
    let diff = one_lem().checked_sub(one_drip()).unwrap();
    assert_eq!(diff.as_drop(), DROPS_PER_LEM - DROPS_PER_DRIP);
}

#[test]
fn checked_sub_zero_returns_original() {
    assert_eq!(one_lem().checked_sub(Amount::zero()).unwrap(), one_lem());
}

#[test]
fn checked_sub_equal_amounts_returns_zero() {
    assert_eq!(one_lem().checked_sub(one_lem()).unwrap(), Amount::zero());
}

#[test]
fn checked_sub_returns_underflow_error_when_rhs_exceeds_lhs() {
    let result = one_drip().checked_sub(one_lem());
    assert!(matches!(result, Err(AmountError::Underflow { .. })));
}

#[test]
fn checked_sub_underflow_error_contains_operands() {
    let lhs = DROPS_PER_DRIP;
    let rhs = DROPS_PER_LEM;
    match Amount::from_drop(lhs).checked_sub(Amount::from_drop(rhs)) {
        Err(AmountError::Underflow { lhs: l, rhs: r }) => {
            assert_eq!(l, lhs);
            assert_eq!(r, rhs);
        }
        _ => panic!("expected Underflow error"),
    }
}

// ── checked_mul() ────────────────────────────────────────────────────────────

#[test]
fn checked_mul_scales_amount_correctly() {
    let result = one_drip().checked_mul(1_000).unwrap();
    assert_eq!(result.as_drop(), 1_000 * DROPS_PER_DRIP);
}

#[test]
fn checked_mul_by_zero_returns_zero() {
    assert_eq!(one_lem().checked_mul(0).unwrap(), Amount::zero());
}

#[test]
fn checked_mul_by_one_returns_original() {
    assert_eq!(one_lem().checked_mul(1).unwrap(), one_lem());
}

#[test]
fn checked_mul_returns_overflow_error_on_large_product() {
    let result = Amount::from_drop(u128::MAX).checked_mul(2);
    assert!(matches!(result, Err(AmountError::Overflow { .. })));
}

#[test]
fn checked_mul_overflow_error_contains_operands() {
    match Amount::from_drop(u128::MAX).checked_mul(2) {
        Err(AmountError::Overflow { lhs, rhs }) => {
            assert_eq!(lhs, u128::MAX);
            assert_eq!(rhs, 2);
        }
        _ => panic!("expected Overflow error with operands"),
    }
}

// ── checked_div() ────────────────────────────────────────────────────────────

#[test]
fn checked_div_divides_correctly() {
    let half = one_lem().checked_div(2).unwrap();
    assert_eq!(half, half_lem());
}

#[test]
fn checked_div_by_one_returns_original() {
    assert_eq!(one_lem().checked_div(1).unwrap(), one_lem());
}

#[test]
fn checked_div_truncates_toward_zero() {
    // 3 Drop / 2 = 1 Drop (integer division)
    let result = Amount::from_drop(3).checked_div(2).unwrap();
    assert_eq!(result.as_drop(), 1);
}

#[test]
fn checked_div_zero_by_nonzero_returns_zero() {
    assert_eq!(Amount::zero().checked_div(100).unwrap(), Amount::zero());
}

#[test]
fn checked_div_returns_division_by_zero_error() {
    let result = one_lem().checked_div(0);
    assert!(matches!(
        result,
        Err(AmountError::DivisionByZero { lhs: DROPS_PER_LEM })
    ));
}

// ── Display ───────────────────────────────────────────────────────────────────

#[test]
fn display_zero_amount_shows_zero_lem() {
    assert_eq!(Amount::zero().to_string(), "0 LEM");
}

#[test]
fn display_one_lem_shows_one_lem() {
    assert_eq!(one_lem().to_string(), "1 LEM");
}

#[test]
fn display_half_lem_shows_decimal() {
    // DROPS_PER_LEM / 2 = 0.5 LEM
    assert_eq!(half_lem().to_string(), "0.5 LEM");
}

#[test]
fn display_one_drop_shows_full_precision() {
    assert_eq!(Amount::from_drop(1).to_string(), "0.000000000000000001 LEM");
}

#[test]
fn display_trims_trailing_decimal_zeros() {
    // 1_500_000_000_000_000_000 Drop = 1.5 LEM — must not show trailing zeros
    let one_and_half_lem = Amount::from_drop(1_500_000_000_000_000_000);
    let s = one_and_half_lem.to_string();
    assert!(!s.ends_with("000000000000000000 LEM"));
    assert_eq!(s, "1.5 LEM");
}

#[test]
fn display_one_drip_shows_correct_fractional() {
    // 1 Drip = 10^9 Drop = 0.000000001 LEM
    assert_eq!(one_drip().to_string(), "0.000000001 LEM");
}

#[test]
fn display_large_whole_amount_shows_no_decimal() {
    let large = Amount::from_lem(1_000_000).unwrap();
    assert_eq!(large.to_string(), "1000000 LEM");
}

// ── Debug ─────────────────────────────────────────────────────────────────────

#[test]
fn debug_shows_raw_drop_count() {
    assert_eq!(format!("{:?}", Amount::zero()), "Amount(0 Drop)");
}

#[test]
fn debug_shows_exact_drop_value() {
    assert_eq!(
        format!("{:?}", one_lem()),
        format!("Amount({} Drop)", DROPS_PER_LEM)
    );
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[test]
fn serialize_to_json_produces_decimal_string() {
    let json = serde_json::to_string(&one_lem()).unwrap();
    assert_eq!(json, format!("\"{}\"", DROPS_PER_LEM));
}

#[test]
fn deserialize_from_json_decimal_string_roundtrips() {
    let original = one_lem();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Amount = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn serialize_zero_to_json_produces_zero_string() {
    assert_eq!(serde_json::to_string(&Amount::zero()).unwrap(), "\"0\"");
}

#[test]
fn deserialize_rejects_non_numeric_string() {
    let result = serde_json::from_str::<Amount>("\"not-a-number\"");
    assert!(result.is_err());
}

#[test]
fn deserialize_rejects_negative_string() {
    let result = serde_json::from_str::<Amount>("\"-1\"");
    assert!(result.is_err());
}

#[test]
fn deserialize_rejects_float_string() {
    let result = serde_json::from_str::<Amount>("\"1.5\"");
    assert!(result.is_err());
}

// ── Clone + Copy ──────────────────────────────────────────────────────────────

#[test]
fn clone_produces_equal_amount() {
    let original = one_lem();
    assert_eq!(original.clone(), original);
}

#[test]
fn copy_semantics_work_correctly() {
    let original = one_lem();
    let copied = original; // Copy, not move
    assert_eq!(original, copied);
}

// ── PartialEq + Eq ────────────────────────────────────────────────────────────

#[test]
fn equal_amounts_are_equal() {
    assert_eq!(one_lem(), one_lem());
}

#[test]
fn different_amounts_are_not_equal() {
    assert_ne!(one_lem(), Amount::zero());
}

// ── PartialOrd + Ord ─────────────────────────────────────────────────────────

#[test]
fn larger_amount_is_greater_than_smaller() {
    assert!(one_lem() > one_drip());
}

#[test]
fn smaller_amount_is_less_than_larger() {
    assert!(Amount::zero() < one_drip());
}

#[test]
fn equal_amounts_are_not_less_than_each_other() {
    // Deliberately assert the `<` and `>` operators themselves return false for
    // equal values. Clippy suggests rewriting to `>=`/`<=`, which would test the
    // OPPOSITE operators and defeat the test's intent. Targeted allow per AGENTS.md §4.1.
    #[allow(clippy::nonminimal_bool)]
    {
        assert!(!(one_lem() < one_lem()));
        assert!(!(one_lem() > one_lem()));
    }
}

#[test]
fn ordering_is_consistent_with_drop_value() {
    let mut amounts = vec![one_lem(), Amount::zero(), one_drip(), half_lem()];
    amounts.sort();
    assert_eq!(
        amounts,
        vec![Amount::zero(), one_drip(), half_lem(), one_lem()]
    );
}

// ── Hash (usable in HashMap) ──────────────────────────────────────────────────

#[test]
fn amount_can_be_used_as_hashmap_key() {
    let mut map: HashMap<Amount, &str> = HashMap::new();
    map.insert(one_lem(), "balance_a");
    map.insert(Amount::zero(), "empty");
    assert_eq!(*map.get(&one_lem()).unwrap(), "balance_a");
    assert_eq!(*map.get(&Amount::zero()).unwrap(), "empty");
}
