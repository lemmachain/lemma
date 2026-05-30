//! # Lemma Crypto
//!
//! Cryptographic primitives for the Lemma blockchain.
//!
//! Hybrid classical (Ed25519) + post-quantum (Dilithium3) signatures,
//! Blake3 / SHA-256 hashing, and key management.
//!
//! ## Modules
//!
//! - [`error`] — [`CryptoError`] enum
//! - `hashing` — hash functions → produce [`lemma_core::Hash`] *(coming soon)*
//! - `keypair` — key generation + address derivation *(coming soon)*
//! - `signing` — sign + verify (hybrid, constant-time) *(coming soon)*

pub mod error;

pub use error::CryptoError;
