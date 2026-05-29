//! # lemma-core
//!
//! Foundational types for the Lemma blockchain.
//!
//! This crate is the single source of truth for all shared types:
//! `Address`, `Hash`, `Amount`, `Transaction`, `Block`, and their typed errors.
//! All other crates in the workspace import from here — never duplicate types.
//!
//! Full re-exports and module documentation are added incrementally as each
//! module is implemented. See `docs/04-BUILD_GUIDE.md` Section 2.1.

pub mod error;
