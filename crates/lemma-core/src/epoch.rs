//! Epoch — a validator-set era with a fixed committee.
//!
//! An epoch is a contiguous range of block heights during which the validator
//! set (committee) is frozen. All power-affecting mutations are requested
//! mid-epoch and applied at the boundary by `advance_epoch`
//! (`docs/13-VALIDATOR_EPOCH_SPEC §4`).
//!
//! Epoch 0 starts from the genesis validator set — the out-of-band trust root
//! from which the committee hash-chain begins (`docs/13-VALIDATOR_EPOCH_SPEC §8.1`).
//!
//! See `docs/13-VALIDATOR_EPOCH_SPEC §1`.

use serde::{Deserialize, Serialize};

use crate::validator_set::ValidatorSet;

// ─── Epoch ───────────────────────────────────────────────────────────────────

/// A validator-set era: a contiguous range of block heights with a frozen
/// committee.
///
/// # Fields
///
/// - `number` — epoch index (0 = genesis).
/// - `start_height` — first block height of this epoch.
/// - `start_timestamp` — consensus `block.time` (seconds) of the first block.
///   Never set from `SystemTime::now()` (AGENTS.md §7.1).
/// - `validators` — the committee for this epoch (frozen for the duration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Epoch {
    /// Epoch index — 0 for genesis, monotonically increasing.
    pub number: u64,
    /// First block height of this epoch.
    pub start_height: u64,
    /// Consensus `block.time` (seconds) of the epoch's first block.
    ///
    /// Derived from the finalized DAG, never from `SystemTime` (AGENTS.md §7.1).
    pub start_timestamp: u64,
    /// The committee for this epoch — frozen for the epoch's duration.
    pub validators: ValidatorSet,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
