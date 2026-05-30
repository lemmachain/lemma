//! Tests for `lemma_core::signature`.
//!
//! Covers all four variants, byte access methods, predicates,
//! serde round-trips, and derived traits.
//! 100% public API coverage per AGENTS.md §11.1.

use std::collections::HashMap;

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn classical_bytes() -> Vec<u8> {
    vec![0xC1u8; 64] // 64 bytes — Ed25519 size
}

fn quantum_bytes() -> Vec<u8> {
    vec![0xD1u8; 2420] // 2420 bytes — Dilithium3 size
}

fn classical_sig() -> Signature {
    Signature::Classical {
        bytes: classical_bytes(),
    }
}

fn quantum_sig() -> Signature {
    Signature::PostQuantum {
        bytes: quantum_bytes(),
    }
}

fn hybrid_sig() -> Signature {
    Signature::Hybrid {
        classical: classical_bytes(),
        quantum: quantum_bytes(),
    }
}

// ── Signature::Unsigned ───────────────────────────────────────────────────────

#[test]
fn unsigned_is_unsigned_returns_true() {
    assert!(Signature::Unsigned.is_unsigned());
}

#[test]
fn unsigned_is_signed_returns_false() {
    assert!(!Signature::Unsigned.is_signed());
}

#[test]
fn unsigned_is_hybrid_returns_false() {
    assert!(!Signature::Unsigned.is_hybrid());
}

#[test]
fn unsigned_classical_bytes_returns_none() {
    assert!(Signature::Unsigned.as_classical_bytes().is_none());
}

#[test]
fn unsigned_quantum_bytes_returns_none() {
    assert!(Signature::Unsigned.as_quantum_bytes().is_none());
}

// ── Signature::Classical ──────────────────────────────────────────────────────

#[test]
fn classical_is_signed_returns_true() {
    assert!(classical_sig().is_signed());
}

#[test]
fn classical_is_unsigned_returns_false() {
    assert!(!classical_sig().is_unsigned());
}

#[test]
fn classical_is_hybrid_returns_false() {
    assert!(!classical_sig().is_hybrid());
}

#[test]
fn classical_classical_bytes_returns_some() {
    assert_eq!(
        classical_sig().as_classical_bytes(),
        Some(classical_bytes().as_slice())
    );
}

#[test]
fn classical_quantum_bytes_returns_none() {
    assert!(classical_sig().as_quantum_bytes().is_none());
}

#[test]
fn classical_stores_arbitrary_byte_lengths() {
    // lemma-core does not enforce 64-byte length — that is lemma-crypto's job.
    let short = Signature::Classical {
        bytes: vec![0u8; 1],
    };
    assert_eq!(short.as_classical_bytes().unwrap().len(), 1);
}

// ── Signature::PostQuantum ────────────────────────────────────────────────────

#[test]
fn post_quantum_is_signed_returns_true() {
    assert!(quantum_sig().is_signed());
}

#[test]
fn post_quantum_is_unsigned_returns_false() {
    assert!(!quantum_sig().is_unsigned());
}

#[test]
fn post_quantum_is_hybrid_returns_false() {
    assert!(!quantum_sig().is_hybrid());
}

#[test]
fn post_quantum_quantum_bytes_returns_some() {
    assert_eq!(
        quantum_sig().as_quantum_bytes(),
        Some(quantum_bytes().as_slice())
    );
}

#[test]
fn post_quantum_classical_bytes_returns_none() {
    assert!(quantum_sig().as_classical_bytes().is_none());
}

#[test]
fn post_quantum_stores_arbitrary_byte_lengths() {
    // lemma-core does not enforce Dilithium length — that is lemma-crypto's job.
    let short = Signature::PostQuantum {
        bytes: vec![0u8; 1],
    };
    assert_eq!(short.as_quantum_bytes().unwrap().len(), 1);
}

// ── Signature::Hybrid ─────────────────────────────────────────────────────────

#[test]
fn hybrid_is_signed_returns_true() {
    assert!(hybrid_sig().is_signed());
}

#[test]
fn hybrid_is_unsigned_returns_false() {
    assert!(!hybrid_sig().is_unsigned());
}

#[test]
fn hybrid_is_hybrid_returns_true() {
    assert!(hybrid_sig().is_hybrid());
}

#[test]
fn hybrid_classical_bytes_returns_classical_field() {
    assert_eq!(
        hybrid_sig().as_classical_bytes(),
        Some(classical_bytes().as_slice())
    );
}

#[test]
fn hybrid_quantum_bytes_returns_quantum_field() {
    assert_eq!(
        hybrid_sig().as_quantum_bytes(),
        Some(quantum_bytes().as_slice())
    );
}

#[test]
fn hybrid_classical_and_quantum_bytes_are_independent() {
    let sig = Signature::Hybrid {
        classical: vec![0xAAu8; 64],
        quantum: vec![0xBBu8; 2420],
    };
    assert_eq!(sig.as_classical_bytes().unwrap()[0], 0xAA);
    assert_eq!(sig.as_quantum_bytes().unwrap()[0], 0xBB);
}

// ── Serde — all variants ──────────────────────────────────────────────────────

#[test]
fn unsigned_serializes_to_tagged_json() {
    let json = serde_json::to_string(&Signature::Unsigned).unwrap();
    assert!(json.contains("\"type\":\"unsigned\""), "got: {}", json);
}

#[test]
fn unsigned_deserializes_from_tagged_json() {
    let json = r#"{"type":"unsigned"}"#;
    let sig: Signature = serde_json::from_str(json).unwrap();
    assert_eq!(sig, Signature::Unsigned);
}

#[test]
fn classical_roundtrips_through_json() {
    let original = classical_sig();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn post_quantum_roundtrips_through_json() {
    let original = quantum_sig();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn hybrid_roundtrips_through_json() {
    let original = hybrid_sig();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn classical_json_contains_type_tag() {
    let json = serde_json::to_string(&classical_sig()).unwrap();
    assert!(json.contains("\"type\":\"classical\""), "got: {}", json);
}

#[test]
fn post_quantum_json_contains_type_tag() {
    let json = serde_json::to_string(&quantum_sig()).unwrap();
    assert!(json.contains("\"type\":\"post_quantum\""), "got: {}", json);
}

#[test]
fn hybrid_json_contains_classical_and_quantum_fields() {
    let json = serde_json::to_string(&hybrid_sig()).unwrap();
    assert!(json.contains("\"classical\""), "got: {}", json);
    assert!(json.contains("\"quantum\""), "got: {}", json);
}

#[test]
fn deserialize_rejects_unknown_type_tag() {
    let bad_json = r#"{"type":"bls","bytes":[1,2,3]}"#;
    let result = serde_json::from_str::<Signature>(bad_json);
    assert!(result.is_err());
}

#[test]
fn deserialize_rejects_missing_type_field() {
    let result = serde_json::from_str::<Signature>(r#"{"bytes":[1,2,3]}"#);
    assert!(result.is_err());
}

// ── Clone ─────────────────────────────────────────────────────────────────────

#[test]
fn clone_unsigned_equals_original() {
    assert_eq!(Signature::Unsigned.clone(), Signature::Unsigned);
}

#[test]
fn clone_classical_equals_original() {
    let sig = classical_sig();
    assert_eq!(sig.clone(), sig);
}

#[test]
fn clone_post_quantum_equals_original() {
    let sig = quantum_sig();
    assert_eq!(sig.clone(), sig);
}

#[test]
fn clone_hybrid_equals_original() {
    let sig = hybrid_sig();
    assert_eq!(sig.clone(), sig);
}

// ── PartialEq + Eq ────────────────────────────────────────────────────────────

#[test]
fn same_classical_bytes_are_equal() {
    assert_eq!(classical_sig(), classical_sig());
}

#[test]
fn different_classical_bytes_are_not_equal() {
    let a = Signature::Classical {
        bytes: vec![0u8; 64],
    };
    let b = Signature::Classical {
        bytes: vec![1u8; 64],
    };
    assert_ne!(a, b);
}

#[test]
fn same_post_quantum_bytes_are_equal() {
    assert_eq!(quantum_sig(), quantum_sig());
}

#[test]
fn different_post_quantum_bytes_are_not_equal() {
    let a = Signature::PostQuantum {
        bytes: vec![0u8; 2420],
    };
    let b = Signature::PostQuantum {
        bytes: vec![1u8; 2420],
    };
    assert_ne!(a, b);
}

#[test]
fn different_variants_are_not_equal() {
    assert_ne!(classical_sig(), quantum_sig());
    assert_ne!(classical_sig(), hybrid_sig());
    assert_ne!(quantum_sig(), Signature::Unsigned);
    assert_ne!(hybrid_sig(), Signature::Unsigned);
}

#[test]
fn unsigned_equals_unsigned() {
    assert_eq!(Signature::Unsigned, Signature::Unsigned);
}

// ── Hash (usable in HashMap) ──────────────────────────────────────────────────

// HashMap used only for key-lookup tests (no iteration — no order dependency).
// For any test requiring deterministic iteration, use BTreeMap per AGENTS.md §7.1.
#[test]
fn signature_can_be_used_as_hashmap_key() {
    let mut map: HashMap<Signature, &str> = HashMap::new();
    map.insert(Signature::Unsigned, "pending");
    map.insert(classical_sig(), "signed");

    assert_eq!(*map.get(&Signature::Unsigned).unwrap(), "pending");
    assert_eq!(*map.get(&classical_sig()).unwrap(), "signed");
}
