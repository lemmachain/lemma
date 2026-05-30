//! ValidatorSet — the committee for a single epoch.
//!
//! A `ValidatorSet` is frozen for the duration of its epoch — voting power
//! cannot change mid-epoch (BFT safety requirement). Mutations are requested
//! during an epoch and applied at the boundary by `advance_epoch`
//! (`docs/13-VALIDATOR_EPOCH_SPEC §4`).
//!
//! # Determinism
//!
//! `members` is a [`BTreeMap`] keyed by [`Address`] — iteration order is
//! deterministic across all nodes (AGENTS.md §7.1). `ValidatorSet::hash()`
//! hashes the canonically-sorted `(address, consensus_pubkey, power)` tuples
//! via Blake3, producing the value committed as `BlockHeader.validators_hash`.
//!
//! See `docs/13-VALIDATOR_EPOCH_SPEC §1` and `§4.4`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    address::Address,
    amount::Amount,
    hash::Hash,
    validator::{ConsensusKey, VotingPower},
};

// ─── Member ──────────────────────────────────────────────────────────────────

/// A single committee member: consensus public key + voting power.
///
/// Stored in [`ValidatorSet::members`] keyed by the validator's [`Address`].
/// The public key is needed by light clients to verify quorum certificates
/// (`docs/12-NETWORK_SYNC_SPEC §3.2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Hybrid consensus public key (Ed25519 + ML-DSA-65) as raw bytes.
    pub consensus_pubkey: ConsensusKey,
    /// Voting power for this epoch (= active stake).
    pub power: VotingPower,
}

// ─── ValidatorSet ────────────────────────────────────────────────────────────

/// The committee for one epoch — frozen for the epoch's duration.
///
/// `members` is a `BTreeMap<Address, Member>` so iteration is canonically
/// sorted by address. `hash()` produces the value committed as
/// `BlockHeader.validators_hash` and `BlockHeader.next_validators_hash`.
///
/// # Epoch-change proof
///
/// The 2f+1 quorum commit on the end-of-epoch boundary block IS the
/// epoch-change proof. A light client that trusts epoch N's committee verifies
/// the boundary block's quorum cert, reads `next_validators_hash`, and
/// transitively trusts epoch N+1's committee. See `docs/13-VALIDATOR_EPOCH_SPEC §4.4`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// The epoch this committee is active for.
    pub epoch: u64,
    /// Committee members keyed by operator address.
    ///
    /// `BTreeMap` guarantees deterministic iteration order across all nodes
    /// (AGENTS.md §7.1) — required for `hash()` to produce identical results.
    pub members: BTreeMap<Address, Member>,
    /// Sum of all members' voting power. Cached for O(1) threshold checks.
    ///
    /// Quorum = `signed * 3 > total_power * 2` (strict 2f+1, integer form).
    pub total_power: Amount,
}

impl ValidatorSet {
    /// Compute the Blake3 hash of this validator set.
    ///
    /// Hashes the canonically-sorted `(address, consensus_pubkey, power)` tuples.
    /// This is the value committed as `BlockHeader.validators_hash` and
    /// `BlockHeader.next_validators_hash` (spec §4.4).
    ///
    /// Uses `blake3::Hasher` directly (not `lemma_crypto::hash`) because
    /// `lemma-core` cannot depend on `lemma-crypto` (circular dependency).
    /// The hash is deterministic: `BTreeMap` iteration order is sorted by key.
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for (addr, member) in &self.members {
            hasher.update(addr.as_bytes());
            hasher.update(&member.consensus_pubkey.classical);
            hasher.update(&member.consensus_pubkey.quantum);
            // VotingPower wraps Amount which wraps u128 — hash the big-endian
            // bytes for deterministic cross-platform representation.
            hasher.update(&member.power.as_amount().as_drop().to_be_bytes());
        }
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Return the number of committee members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Return `true` if the committee has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
