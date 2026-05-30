//! # Lemma Crypto
//!
//! Cryptographic primitives for the Lemma blockchain.
//!
//! Hybrid classical (Ed25519) + post-quantum (Dilithium3) signatures,
//! Blake3 / SHA-256 / Keccak-256 hashing, and key management.
//!
//! ## Modules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`error`] | [`CryptoError`] — single error enum for all crypto ops |
//! | [`hashing`] | [`hash_bytes`], [`hash`], [`sha256`], [`keccak256`] → [`lemma_core::Hash`] |
//! | `keypair` | key generation + address derivation *(coming soon)* |
//! | `signing` | sign + verify (hybrid Ed25519 + ML-DSA, constant-time) *(coming soon)* |

pub mod error;
pub mod hashing;
pub mod keypair;

pub use error::CryptoError;
pub use hashing::{hash, hash_bytes, keccak256, sha256};
pub use keypair::{verify, HybridSignature, KeyPair, PublicKey};
