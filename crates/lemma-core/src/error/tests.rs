//! Tests for `lemma_core::error`.
//!
//! Covers Display output, Clone round-trips, PartialEq, and all `From`
//! conversions on every public variant. 100% public API coverage required
//! per AGENTS.md §11.1.

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn addr_invalid_length() -> AddressError {
    AddressError::InvalidLength { got: 32 }
}

fn hash_invalid_length() -> HashError {
    HashError::InvalidLength { got: 16 }
}

fn amount_overflow() -> AmountError {
    AmountError::Overflow {
        lhs: u128::MAX,
        rhs: 1,
    }
}

fn block_gas_exceeded() -> BlockError {
    BlockError::GasExceeded {
        used: 1_000_000,
        limit: 500_000,
    }
}

fn ser_binary_error() -> SerializationError {
    SerializationError::Binary {
        reason: "eof".to_string(),
    }
}

// ── AddressError — Display ────────────────────────────────────────────────────

#[test]
fn address_error_displays_invalid_length() {
    assert_eq!(
        addr_invalid_length().to_string(),
        "invalid address length: expected 20 bytes, got 32",
    );
}

#[test]
fn address_error_displays_invalid_bech32() {
    let err = AddressError::InvalidBech32 {
        reason: "bad checksum".to_string(),
    };
    assert_eq!(err.to_string(), "invalid Bech32m encoding: bad checksum");
}

#[test]
fn address_error_displays_invalid_hrp() {
    let err = AddressError::InvalidHrp {
        got: "eth".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "invalid HRP: expected one of [lem, tlem, dlem], got \"eth\"",
    );
}

#[test]
fn address_error_displays_unknown_type_byte() {
    let err = AddressError::UnknownAddressType { byte: 0xAB };
    assert_eq!(err.to_string(), "unknown address type byte: 0xab");
}

#[test]
fn address_error_displays_invalid_payload_length() {
    let err = AddressError::InvalidPayloadLength { got: 10 };
    assert_eq!(
        err.to_string(),
        "invalid decoded payload length: expected 21 bytes, got 10",
    );
}

// ── AddressError — Clone + PartialEq ─────────────────────────────────────────

#[test]
fn address_error_clones_equal_to_original() {
    let err = addr_invalid_length();
    assert_eq!(err.clone(), err);
}

#[test]
fn address_error_different_variants_are_not_equal() {
    let a = AddressError::InvalidLength { got: 32 };
    let b = AddressError::InvalidPayloadLength { got: 32 };
    assert_ne!(a, b);
}

#[test]
fn address_error_same_variant_different_fields_are_not_equal() {
    let a = AddressError::InvalidLength { got: 20 };
    let b = AddressError::InvalidLength { got: 32 };
    assert_ne!(a, b);
}

// ── HashError — Display ───────────────────────────────────────────────────────

#[test]
fn hash_error_displays_invalid_length() {
    assert_eq!(
        hash_invalid_length().to_string(),
        "invalid hash length: expected 32 bytes, got 16",
    );
}

#[test]
fn hash_error_displays_invalid_hex() {
    let err = HashError::InvalidHex {
        reason: "invalid char 'g'".to_string(),
    };
    assert_eq!(err.to_string(), "invalid hex encoding: invalid char 'g'");
}

// ── HashError — Clone + PartialEq ─────────────────────────────────────────────

#[test]
fn hash_error_clones_equal_to_original() {
    let err = hash_invalid_length();
    assert_eq!(err.clone(), err);
}

#[test]
fn hash_error_different_variants_are_not_equal() {
    let a = HashError::InvalidLength { got: 16 };
    let b = HashError::InvalidHex {
        reason: "bad".to_string(),
    };
    assert_ne!(a, b);
}

// ── AmountError — Display ─────────────────────────────────────────────────────

#[test]
fn amount_error_displays_overflow_with_operands() {
    assert_eq!(
        amount_overflow().to_string(),
        format!("amount overflow: operands {} and {}", u128::MAX, 1),
    );
}

#[test]
fn amount_error_displays_underflow_with_operands() {
    let err = AmountError::Underflow { lhs: 5, rhs: 10 };
    assert_eq!(
        err.to_string(),
        "amount underflow: 5 - 10 would be negative"
    );
}

#[test]
fn amount_error_displays_division_by_zero_with_dividend() {
    let err = AmountError::DivisionByZero { lhs: 42 };
    assert_eq!(err.to_string(), "amount division by zero: 42 / 0");
}

#[test]
fn amount_error_division_by_zero_with_zero_dividend() {
    // Edge case: 0 / 0 — must produce a valid, non-panicking error.
    let err = AmountError::DivisionByZero { lhs: 0 };
    assert_eq!(err.to_string(), "amount division by zero: 0 / 0");
}

// ── AmountError — Clone + PartialEq ──────────────────────────────────────────

#[test]
fn amount_error_clones_equal_to_original() {
    let err = amount_overflow();
    assert_eq!(err.clone(), err);
}

#[test]
fn amount_error_different_variants_are_not_equal() {
    let a = AmountError::Overflow { lhs: 1, rhs: 2 };
    let b = AmountError::Underflow { lhs: 1, rhs: 2 };
    assert_ne!(a, b);
}

// ── TransactionError — Display ────────────────────────────────────────────────

#[test]
fn transaction_error_displays_missing_recipient() {
    let err = TransactionError::MissingRecipient {
        tx_type: "Transfer".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "transaction of type Transfer requires a recipient address",
    );
}

#[test]
fn transaction_error_displays_unexpected_recipient() {
    assert_eq!(
        TransactionError::UnexpectedRecipient.to_string(),
        "contract deploy transaction must not have a recipient address",
    );
}

#[test]
fn transaction_error_displays_missing_calldata() {
    let err = TransactionError::MissingCalldata {
        tx_type: "ContractCall".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "transaction of type ContractCall requires calldata",
    );
}

#[test]
fn transaction_error_displays_zero_gas_limit() {
    assert_eq!(
        TransactionError::ZeroGasLimit.to_string(),
        "gas limit must be greater than zero",
    );
}

#[test]
fn transaction_error_displays_hash_mismatch_with_both_hashes() {
    let err = TransactionError::HashMismatch {
        stored: "aabbcc".to_string(),
        computed: "ddeeff".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "transaction hash mismatch: stored aabbcc, computed ddeeff",
    );
}

// ── BlockError — Display ──────────────────────────────────────────────────────

#[test]
fn block_error_displays_invalid_height() {
    let err = BlockError::InvalidHeight {
        expected: 42,
        got: 99,
    };
    assert_eq!(err.to_string(), "invalid block height: expected 42, got 99");
}

#[test]
fn block_error_displays_gas_exceeded() {
    assert_eq!(
        block_gas_exceeded().to_string(),
        "gas used (1000000) exceeds gas limit (500000)",
    );
}

#[test]
fn block_error_displays_receipt_count_mismatch() {
    let err = BlockError::ReceiptCountMismatch {
        transactions: 5,
        receipts: 3,
    };
    assert_eq!(
        err.to_string(),
        "receipt count (3) does not match transaction count (5)",
    );
}

#[test]
fn block_error_receipt_count_mismatch_with_equal_counts_is_constructable() {
    // Boundary: equal counts should still produce a valid (if logically odd) error.
    // The caller is responsible for not emitting this error when counts match.
    let err = BlockError::ReceiptCountMismatch {
        transactions: 3,
        receipts: 3,
    };
    assert_eq!(
        err.to_string(),
        "receipt count (3) does not match transaction count (3)",
    );
}

// ── SerializationError — Display + From ───────────────────────────────────────

#[test]
fn serialization_error_displays_json_with_reason() {
    let err = SerializationError::Json {
        reason: "missing field `hash`".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "JSON serialization error: missing field `hash`"
    );
}

#[test]
fn serialization_error_displays_binary_with_reason() {
    assert_eq!(ser_binary_error().to_string(), "binary codec error: eof",);
}

#[test]
fn serialization_error_converts_from_serde_json_error() {
    let json_err = serde_json::from_str::<serde_json::Value>("{bad json").unwrap_err();
    let ser_err: SerializationError = json_err.into();
    assert!(matches!(ser_err, SerializationError::Json { .. }));
    assert!(ser_err.to_string().starts_with("JSON serialization error:"));
}

// ── SerializationError — Clone + PartialEq ────────────────────────────────────

#[test]
fn serialization_error_clones_equal_to_original() {
    let err = ser_binary_error();
    assert_eq!(err.clone(), err);
}

// ── TransactionError — Clone + PartialEq ─────────────────────────────────────

#[test]
fn transaction_error_clones_equal_to_original() {
    let err = TransactionError::ZeroGasLimit;
    assert_eq!(err.clone(), err);
}

#[test]
fn transaction_error_different_variants_are_not_equal() {
    let a = TransactionError::ZeroGasLimit;
    let b = TransactionError::UnexpectedRecipient;
    assert_ne!(a, b);
}

// ── BlockError — Clone + PartialEq ────────────────────────────────────────────

#[test]
fn block_error_clones_equal_to_original() {
    let err = block_gas_exceeded();
    assert_eq!(err.clone(), err);
}

#[test]
fn block_error_different_variants_are_not_equal() {
    let a = BlockError::GasExceeded {
        used: 100,
        limit: 50,
    };
    let b = BlockError::InvalidHeight {
        expected: 1,
        got: 2,
    };
    assert_ne!(a, b);
}

// ── CoreError — From conversions ──────────────────────────────────────────────

#[test]
fn core_error_wraps_address_error_via_from() {
    let core_err: CoreError = addr_invalid_length().into();
    assert!(core_err.to_string().starts_with("address error:"));
}

#[test]
fn core_error_wraps_hash_error_via_from() {
    let core_err: CoreError = hash_invalid_length().into();
    assert!(core_err.to_string().starts_with("hash error:"));
}

#[test]
fn core_error_wraps_amount_error_via_from() {
    let core_err: CoreError = AmountError::Underflow { lhs: 1, rhs: 2 }.into();
    assert!(core_err.to_string().starts_with("amount error:"));
}

#[test]
fn core_error_wraps_transaction_error_via_from() {
    let core_err: CoreError = TransactionError::ZeroGasLimit.into();
    assert!(core_err.to_string().starts_with("transaction error:"));
}

#[test]
fn core_error_wraps_block_error_via_from() {
    let core_err: CoreError = block_gas_exceeded().into();
    assert!(core_err.to_string().starts_with("block error:"));
}

#[test]
fn core_error_wraps_serialization_error_via_from() {
    let core_err: CoreError = ser_binary_error().into();
    assert!(core_err.to_string().starts_with("serialization error:"));
}

// ── CoreError — Clone + PartialEq ─────────────────────────────────────────────

#[test]
fn core_error_clones_equal_to_original() {
    let err: CoreError = addr_invalid_length().into();
    assert_eq!(err.clone(), err);
}

#[test]
fn core_error_different_variants_are_not_equal() {
    let a: CoreError = addr_invalid_length().into();
    let b: CoreError = hash_invalid_length().into();
    assert_ne!(a, b);
}

#[test]
fn core_error_same_variant_same_inner_are_equal() {
    let a: CoreError = AddressError::InvalidLength { got: 32 }.into();
    let b: CoreError = AddressError::InvalidLength { got: 32 }.into();
    assert_eq!(a, b);
}
