//! Signature type — a raw-bytes wrapper for embedding in transactions and headers.
//!
//! `lemma-core` defines **only the type**; all cryptographic operations
//! (key generation, signing, verification) live in `lemma-crypto`. This crate
//! has no dependency on `ed25519-dalek` or `pqcrypto-dilithium`.
//!
//! # Signature scheme
//!
//! Lemma uses a **hybrid** signature model: both an Ed25519 classical signature
//! and a Dilithium post-quantum signature are required on every transaction.
//! Verifying either alone is insufficient — `lemma-crypto` enforces the
//! "both must verify" rule. See `docs/04-BUILD_GUIDE.md` Section 2.2.
//!
//! # Serde format
//!
//! Serialized as a tagged JSON object:
//!
//! ```json
//! {"type": "classical",   "bytes": [1, 2, 3, ...]}
//! {"type": "post_quantum","bytes": [1, 2, 3, ...]}
//! {"type": "hybrid",      "classical": [...], "quantum": [...]}
//! {"type": "unsigned"}
//! ```
//!
//! The `bytes` fields carry raw signature bytes. Validation of lengths and
//! mathematical correctness is `lemma-crypto`'s responsibility.

use serde::{Deserialize, Serialize};

// ─── Signature ────────────────────────────────────────────────────────────────

/// A raw-bytes signature, embedded in [`Transaction`](crate::Transaction) and
/// [`BlockHeader`](crate::BlockHeader).
///
/// Bytes are stored as-is; `lemma-core` performs no cryptographic validation.
/// Call `lemma_crypto::verify` to verify a signature against a public key.
///
/// # Variants
///
/// - [`Signature::Classical`] — 64-byte Ed25519 signature.
/// - [`Signature::PostQuantum`] — ~2.4 KB Dilithium signature.
/// - [`Signature::Hybrid`] — both classical **and** quantum must verify.
/// - [`Signature::Unsigned`] — placeholder for unsigned transactions.
///
/// # Why `#[non_exhaustive]`
///
/// Future signature schemes (BLS, FROST, etc.) will be added as new variants
/// without breaking downstream `match` arms.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Signature {
    /// Ed25519 classical signature — 64 bytes.
    ///
    /// The byte length is not validated here; `lemma-crypto` enforces the
    /// exact 64-byte requirement during verification.
    Classical { bytes: Vec<u8> },

    /// Dilithium post-quantum signature — approximately 2.4 KB.
    ///
    /// Exact length depends on the Dilithium parameter set used.
    PostQuantum { bytes: Vec<u8> },

    /// Hybrid signature: both classical (Ed25519) **and** quantum (Dilithium)
    /// signatures, both of which must independently verify.
    ///
    /// This is the standard Lemma transaction signature. Neither field alone
    /// is sufficient — `lemma-crypto` enforces the conjunction.
    Hybrid {
        /// Ed25519 signature bytes (64 bytes when valid).
        classical: Vec<u8>,
        /// Dilithium signature bytes (~2.4 KB when valid).
        quantum: Vec<u8>,
    },

    /// Transaction not yet signed.
    ///
    /// Used when constructing unsigned transactions before calling
    /// `lemma-crypto::KeyPair::sign`. A transaction with this variant
    /// will be rejected by the mempool.
    Unsigned,
}

impl Signature {
    // ── Predicates ────────────────────────────────────────────────────────────

    /// Returns `true` if this signature is not [`Signature::Unsigned`].
    ///
    /// Does **not** validate cryptographic correctness — use `lemma-crypto`
    /// for that.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !matches!(self, Self::Unsigned)
    }

    /// Returns `true` if this is the [`Signature::Unsigned`] placeholder.
    #[must_use]
    pub fn is_unsigned(&self) -> bool {
        matches!(self, Self::Unsigned)
    }

    /// Returns `true` if this is a [`Signature::Hybrid`] (both classical and
    /// post-quantum bytes present).
    #[must_use]
    pub fn is_hybrid(&self) -> bool {
        matches!(self, Self::Hybrid { .. })
    }

    // ── Byte access ───────────────────────────────────────────────────────────

    /// Return the classical (Ed25519) signature bytes, if present.
    ///
    /// - [`Signature::Classical`]: returns `Some(&bytes)`.
    /// - [`Signature::Hybrid`]: returns `Some(&classical)`.
    /// - All others: returns `None`.
    pub fn as_classical_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Classical { bytes } => Some(bytes),
            Self::Hybrid { classical, .. } => Some(classical),
            _ => None,
        }
    }

    /// Return the post-quantum (Dilithium) signature bytes, if present.
    ///
    /// - [`Signature::PostQuantum`]: returns `Some(&bytes)`.
    /// - [`Signature::Hybrid`]: returns `Some(&quantum)`.
    /// - All others: returns `None`.
    pub fn as_quantum_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::PostQuantum { bytes } => Some(bytes),
            Self::Hybrid { quantum, .. } => Some(quantum),
            _ => None,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
