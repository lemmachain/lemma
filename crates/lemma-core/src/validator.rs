//! Validator identity, stake accounting, and consensus key types.
//!
//! # Dependency note
//!
//! `lemma-core` cannot depend on `lemma-crypto` (circular — `lemma-crypto`
//! already depends on `lemma-core`). [`ConsensusKey`] therefore mirrors the
//! raw-bytes representation of `lemma_crypto::PublicKey` without importing it.
//! This is the same pattern used by [`Signature`](crate::Signature): raw bytes
//! in `lemma-core`, crypto operations in `lemma-crypto` which adds
//! `From<lemma_crypto::PublicKey> for ConsensusKey` on its side.
//!
//! # Determinism
//!
//! All collections that affect staking / voting power use `BTreeMap`/`BTreeSet`
//! or sorted `Vec` — never `HashMap`/`HashSet` (AGENTS.md §7.1).
//! All arithmetic uses `Amount::checked_*` (AGENTS.md §7.4).
//!
//! See `docs/13-VALIDATOR_EPOCH_SPEC.md` §1 and §2.

use serde::{Deserialize, Serialize};

use crate::{address::Address, amount::Amount};

// ─── ConsensusKey ─────────────────────────────────────────────────────────────

/// Raw consensus public key stored in a validator record.
///
/// Carries both the Ed25519 verifying key (32 bytes) and the ML-DSA-65 public
/// key (1952 bytes) as raw byte vectors. This is the `lemma-core` storage type;
/// crypto operations live in `lemma-crypto`, which converts
/// `lemma_crypto::PublicKey → ConsensusKey` via a `From` impl on its side.
///
/// # Why raw bytes?
///
/// `lemma-core` cannot import `lemma-crypto` (circular dependency — `lemma-crypto`
/// depends on `lemma-core`). The same pattern applies to [`crate::Signature`]:
/// raw bytes in `lemma-core`, verification in `lemma-crypto`.
///
/// # Hashing for `validators_hash`
///
/// `ValidatorSet::hash` (see [`crate::ValidatorSet`]) hashes
/// `(address, consensus_pubkey, power)` tuples deterministically. `ConsensusKey`
/// must implement `Hash` for use in `BTreeMap` and for the Blake3 hash of the
/// validator set.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusKey {
    /// Ed25519 verifying key bytes — always 32 bytes when valid.
    pub classical: Vec<u8>,
    /// ML-DSA-65 public key bytes — always 1952 bytes when valid.
    pub quantum: Vec<u8>,
}

impl ConsensusKey {
    /// Construct a `ConsensusKey` from raw Ed25519 + ML-DSA-65 bytes.
    ///
    /// No cryptographic validation is performed here — validation is
    /// `lemma-crypto`'s responsibility. Use `lemma_crypto::PublicKey` for
    /// validated construction.
    #[must_use]
    pub fn from_bytes(classical: Vec<u8>, quantum: Vec<u8>) -> Self {
        Self { classical, quantum }
    }
}

// ─── VotingPower ─────────────────────────────────────────────────────────────

/// A validator's voting power for a given epoch — a newtype over [`Amount`].
///
/// Prevents accidentally mixing raw token balances with voting-power values in
/// arithmetic (AGENTS.md §4.3 newtype pattern). Voting power = a validator's
/// `active` stake.
///
/// # Ordering
///
/// `VotingPower` is ordered by its inner `Amount`, enabling BTreeMap/BTreeSet
/// use and deterministic threshold arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VotingPower(pub Amount);

impl VotingPower {
    /// The zero voting power (no stake active).
    #[must_use]
    pub fn zero() -> Self {
        Self(Amount::zero())
    }

    /// Return the inner [`Amount`].
    #[must_use]
    pub fn as_amount(self) -> Amount {
        self.0
    }
}

// ─── ValidatorStatus ─────────────────────────────────────────────────────────

/// The state-machine status of a validator (Cosmos 3-status model).
///
/// Transitions:
/// - `Unbonded` → `Bonded` (via `request_add_validator` at epoch boundary)
/// - `Bonded` → `Unbonding` (via `request_remove_validator` or forced removal)
/// - `Unbonding` → `Unbonded` (after the 14-day unbonding window elapses)
///
/// **`Bonded → Unbonded` directly is forbidden** — stake must pass through
/// `Unbonding` to remain slashable for the full evidence window
/// (`docs/13-VALIDATOR_EPOCH_SPEC §2.1`).
///
/// Tombstoning (permanent ban) is a `bool` flag on [`Validator`], not a status
/// variant — a tombstoned validator retains its last status for audit purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Not in the active set. Can receive delegations. Not slashable.
    Unbonded,
    /// In the active set. Signs blocks, earns rewards. **Slashable.**
    Bonded,
    /// Left the active set. Not signing or earning. **Still slashable** until
    /// the unbonding window elapses.
    Unbonding,
}

// ─── UnbondingEntry ──────────────────────────────────────────────────────────

/// A single unbonding stake entry, **dated** so slashing can target only
/// entries that began *after* an infraction (AGENTS.md §7.4; spec §5.1).
///
/// A single `Amount` cannot represent "post-infraction unbonding" — the slash
/// rule requires knowing when each entry started relative to `infraction_height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbondingEntry {
    /// The stake amount at the time unbonding was requested.
    ///
    /// This is the slash basis — slashed fraction is applied to `initial_balance`,
    /// capped so the result is never negative (AGENTS.md §7.4).
    pub initial_balance: Amount,
    /// Consensus block height at which the unbonding was requested.
    ///
    /// Used to determine whether this entry is "post-infraction" for slashing
    /// (`start_height > infraction_height` → slashable).
    pub start_height: u64,
    /// Consensus `block.time` (seconds) at which the 14-day window matures.
    ///
    /// Set at creation: `start_time + UNBONDING_PERIOD_SECONDS`. Never set
    /// from `SystemTime::now()` — always derived from consensus (AGENTS.md §7.1).
    pub complete_time: u64,
    /// If `true`, unbonding completion is frozen while slashing evidence pends
    /// (slash-evasion guard, spec §2.3). Set via `PutUnbondingOnHold` equivalent.
    pub on_hold: bool,
}

// ─── Stake ────────────────────────────────────────────────────────────────────

/// Per-validator 4-bucket stake accounting (Aptos model).
///
/// All mutations are **requested** mid-epoch but **applied** only at the epoch
/// boundary (`advance_epoch`, `docs/13-VALIDATOR_EPOCH_SPEC §4`). This freezes
/// voting power for the entire epoch duration — a BFT safety requirement.
///
/// # Bucket semantics
///
/// | Bucket | Meaning | Voting power |
/// |--------|---------|-------------|
/// | `active` | Counts toward current-epoch voting power | ✅ |
/// | `pending_active` | Added this epoch | ❌ (next boundary) |
/// | `pending_inactive` | Unbonding requested (dated entries) | ❌ (next boundary) |
/// | `inactive` | Matured; withdrawable after 14 days | ❌ |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stake {
    /// Counts toward the current epoch's voting power.
    pub active: Amount,
    /// Added during this epoch; becomes `active` at the next epoch boundary.
    pub pending_active: Amount,
    /// Unbonding-requested stake. Each entry is dated so slashing can target
    /// only entries that started *after* an infraction (spec §5.1).
    pub pending_inactive: Vec<UnbondingEntry>,
    /// Matured unbonded stake — withdrawable by the delegator.
    pub inactive: Amount,
}

impl Stake {
    /// A fresh stake record with all buckets at zero.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            active:           Amount::zero(),
            pending_active:   Amount::zero(),
            pending_inactive: Vec::new(),
            inactive:         Amount::zero(),
        }
    }

    /// Total staked (active + pending_active + sum of pending_inactive entries).
    ///
    /// Does NOT include `inactive` (already unbonded, not slashable).
    /// Returns `Err` on overflow (AGENTS.md §7.4).
    pub fn total_bonded(&self) -> Result<Amount, crate::AmountError> {
        let pending_inactive_sum = self
            .pending_inactive
            .iter()
            .try_fold(Amount::zero(), |acc, e| acc.checked_add(e.initial_balance))?;

        self.active
            .checked_add(self.pending_active)?
            .checked_add(pending_inactive_sum)
    }
}

// ─── Validator ────────────────────────────────────────────────────────────────

/// A Lemma validator: identity, consensus key, stake accounting, and status.
///
/// Stored in [`crate::GenesisConfig::genesis_validators`] (genesis trust root)
/// and maintained by `lemma-consensus` through epoch transitions.
///
/// # Status machine
///
/// See [`ValidatorStatus`] for the allowed transitions.
/// `tombstoned = true` is permanent — a tombstoned validator can never re-bond,
/// regardless of status.
///
/// # Commission
///
/// `commission_bps` is in basis points (0 = 0%, 10_000 = 100%). Applied
/// off-the-top during reward distribution (`advance_epoch`, spec §4/§7).
/// Integer-only — no floats (AGENTS.md §3.3/§7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// The validator's operator address (`lem1...`).
    pub address: Address,
    /// Consensus public key — both Ed25519 and ML-DSA-65 components as raw bytes.
    ///
    /// Crypto operations (signature verification) use `lemma_crypto::PublicKey`,
    /// converted from this field via `From<ConsensusKey>` on that side.
    pub consensus_pubkey: ConsensusKey,
    /// Current state-machine status.
    pub status: ValidatorStatus,
    /// If `true`, the consensus key is permanently banned from re-bonding.
    ///
    /// Set on double-sign evidence. Tombstoned validators retain their last
    /// status for audit purposes but can never participate again.
    pub tombstoned: bool,
    /// Self-delegated stake in the 4-bucket model.
    pub self_stake: Stake,
    /// Total stake delegated by external delegators.
    ///
    /// Individual delegator records are tracked by the F1 distribution module
    /// in `lemma-consensus` (spec §7); only the aggregate is stored here.
    pub delegated: Amount,
    /// Commission rate in basis points (0–10_000). Applied off-the-top during
    /// reward distribution.
    pub commission_bps: u16,
    /// Consensus `block.time` (seconds) after which the validator may re-bond.
    ///
    /// `None` = not jailed. Set on downtime or share-withholding slash
    /// (spec §5.4/§5.5). Never set from `SystemTime` (AGENTS.md §7.1).
    pub jailed_until: Option<u64>,
}

impl Validator {
    /// Return the validator's current voting power (active self-stake + delegated).
    ///
    /// Returns `Err` on overflow (AGENTS.md §7.4).
    pub fn voting_power(&self) -> Result<VotingPower, crate::AmountError> {
        self.self_stake
            .active
            .checked_add(self.delegated)
            .map(VotingPower)
    }

    /// Returns `true` if the validator is eligible to participate in consensus
    /// (Bonded, not tombstoned, not jailed).
    ///
    /// Note: jailed_until comparison requires the current block.time — callers
    /// must supply it. This method only checks the structural flags.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Bonded && !self.tombstoned && self.jailed_until.is_none()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
