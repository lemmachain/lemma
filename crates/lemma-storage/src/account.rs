//! Account model for Lemma's world state.
//!
//! [`Account`] is the unit of state stored in the `state` column family of
//! [`LemmaDb`]. Every address on the Lemma chain has exactly one `Account`,
//! even if it has never been written to — in that case the implicit default
//! is all-zero fields (zero balance, zero nonce, zero hashes).
//!
//! ## Externally-Owned Accounts vs Contracts
//!
//! | Field | EOA | Contract |
//! |-------|-----|----------|
//! | `code_hash` | `Hash::zero()` | Blake3 hash of deployed bytecode |
//! | `storage_root` | `Hash::zero()` | Merkle root of contract storage trie |
//!
//! Use [`Account::is_contract`] / [`Account::is_eoa`] to branch on account
//! type without comparing hashes manually.
//!
//! ## Balance vs Staked
//!
//! - `balance` — liquid LEM; can be transferred, spent on gas, or staked.
//! - `staked` — LEM locked in the validator staking system; non-transferable
//!   until fully unbonded. Tracked here as a simple total so the execution
//!   layer can reject transfers that would overdraw liquid balance without
//!   a full walk of the validator registry. The per-validator unbonding detail
//!   lives in [`lemma_core::Stake`].
//!
//! ## Serialization
//!
//! `Account` is serialized with `bincode` for storage in RocksDB. Both
//! `Amount` (decimal string) and `Hash` (hex string) use their custom
//! `Serialize`/`Deserialize` impls, so the on-disk format is not raw bytes —
//! it is deterministic and human-inspectable with `bincode` decode tools.
//!
//! [`LemmaDb`]: crate::LemmaDb
//! [`lemma_core::Stake`]: lemma_core::Stake

use lemma_core::{Amount, Hash};
use serde::{Deserialize, Serialize};

// ─── Account ──────────────────────────────────────────────────────────────────

/// An account in Lemma's world state.
///
/// Stored in the `state` column family keyed by the account's [`Address`]
/// (20 bytes). Every address has an implicit all-zero account if no entry
/// exists in storage — callers at the `state.rs` layer return
/// [`StorageError::AccountNotFound`] when an account is *required* to exist.
///
/// `Account` is `Copy` because all fields are either primitive integers or
/// copy-safe newtypes (`Amount` wraps `u128`; `Hash` wraps `[u8; 32]`).
///
/// [`Address`]: lemma_core::Address
/// [`StorageError::AccountNotFound`]: crate::StorageError::AccountNotFound
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Transaction sequence counter. Incremented by one for every transaction
    /// sent from this account, including failed transactions.
    ///
    /// Nonce is used to prevent replay attacks: a transaction with a nonce
    /// lower than the account's current nonce is rejected by the mempool.
    pub nonce: u64,

    /// Liquid LEM balance, denominated in Drop (1 LEM = 10¹⁸ Drop).
    ///
    /// This is the *transferable* balance. Staked LEM is tracked separately
    /// in [`staked`] so the execution layer can quickly validate transfers
    /// without touching the validator registry.
    ///
    /// [`staked`]: Account::staked
    pub balance: Amount,

    /// Blake3 hash of the account's deployed contract bytecode.
    ///
    /// `Hash::zero()` for externally-owned accounts (EOAs) — no code. Non-zero
    /// for contract accounts. The bytecode itself is stored separately, keyed
    /// by this hash, so it is not duplicated if two contracts share identical
    /// code (rare in practice, but the model is sound).
    pub code_hash: Hash,

    /// Merkle Patricia Trie root of this contract's storage slots.
    ///
    /// `Hash::zero()` for EOAs (no storage) and freshly deployed contracts
    /// (empty storage). Updated atomically alongside the world state root at
    /// the end of each block's execution.
    pub storage_root: Hash,

    /// LEM locked in the validator staking system, denominated in Drop.
    ///
    /// Non-transferable while bonded or unbonding. The four-bucket unbonding
    /// detail (`pending_active`, `pending_inactive`, etc.) lives in
    /// [`lemma_core::Stake`] on the validator record. This field is the
    /// account-level summary of locked LEM.
    ///
    /// **Only [`balance`] is available for transfers and gas payment** —
    /// `staked` is locked and must never be counted as spendable. The total
    /// LEM held by this account (liquid + locked) is
    /// `balance.checked_add(staked)`, but callers that need the spendable
    /// amount must use [`available_balance`].
    ///
    /// [`balance`]: Account::balance
    /// [`available_balance`]: Account::available_balance
    /// [`lemma_core::Stake`]: lemma_core::Stake
    pub staked: Amount,
}

// ─── Constructors ─────────────────────────────────────────────────────────────

impl Account {
    /// Create a new externally-owned account (EOA) with the given balance.
    ///
    /// `code_hash` and `storage_root` are set to [`Hash::zero()`], marking
    /// this account as an EOA. `nonce` starts at 0. `staked` starts at zero.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use lemma_core::Amount;
    /// use lemma_storage::account::Account;
    ///
    /// let acc = Account::new_eoa(Amount::from_drop(1_000));
    /// assert!(acc.is_eoa());
    /// assert!(!acc.is_contract());
    /// ```
    pub fn new_eoa(balance: Amount) -> Self {
        Self {
            nonce: 0,
            balance,
            code_hash: Hash::zero(),
            storage_root: Hash::zero(),
            staked: Amount::zero(),
        }
    }

    /// Create a new contract account with the given code hash.
    ///
    /// `storage_root` starts as [`Hash::zero()`] (empty storage trie).
    /// `balance` and `staked` start at zero — a contract account typically
    /// receives LEM via `ContractDeploy` calldata or subsequent transfers.
    /// `nonce` starts at 0.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use lemma_core::Hash;
    /// use lemma_storage::account::Account;
    ///
    /// let code_hash = Hash::from_bytes([0xab; 32]);
    /// let acc = Account::new_contract(code_hash);
    /// assert!(acc.is_contract());
    /// assert!(!acc.is_eoa());
    /// ```
    pub fn new_contract(code_hash: Hash) -> Self {
        Self {
            nonce: 0,
            balance: Amount::zero(),
            code_hash,
            storage_root: Hash::zero(),
            staked: Amount::zero(),
        }
    }
}

// ─── Predicates ───────────────────────────────────────────────────────────────

impl Account {
    /// Returns `true` if this is an externally-owned account (no contract code).
    ///
    /// An EOA has `code_hash == Hash::zero()`. This is the fast path for the
    /// execution layer to skip bytecode loading and dispatch directly to a
    /// value transfer.
    pub fn is_eoa(&self) -> bool {
        self.code_hash.is_zero()
    }

    /// Returns `true` if this account has deployed contract code.
    ///
    /// A contract account has a non-zero `code_hash`. The bytecode is fetched
    /// from the `code` store (keyed by `code_hash`) and executed by LemmaVM.
    pub fn is_contract(&self) -> bool {
        !self.code_hash.is_zero()
    }

    /// Returns `true` if the liquid balance is zero.
    ///
    /// Note: a zero-balance account may still have a non-zero `staked` amount.
    /// Use `account.staked.is_zero()` to check staked balance separately.
    pub fn is_zero_balance(&self) -> bool {
        self.balance.is_zero()
    }

    /// Returns the liquid balance available for transfers and gas payment.
    ///
    /// This is always `balance` — `staked` LEM is locked and cannot be
    /// spent until fully unbonded. Callers **must** use this method (not
    /// `balance + staked`) when validating whether a transfer is affordable.
    ///
    /// To compute total LEM held (liquid + locked) use
    /// `account.balance.checked_add(account.staked)` explicitly — the
    /// intentional verbosity discourages accidental use as a spendable amount.
    pub fn available_balance(&self) -> Amount {
        self.balance
    }
}

// ─── Default ──────────────────────────────────────────────────────────────────

impl Default for Account {
    /// The implicit zero-state account: nonce 0, zero balance, zero hashes.
    ///
    /// This matches the semantics of "account has never been written to" —
    /// all addresses in Lemma have an implicit default account that is
    /// indistinguishable from a freshly-created EOA with zero balance.
    ///
    /// # Why not `#[derive(Default)]`?
    ///
    /// `Amount` does not implement `Default` — its canonical zero is
    /// `Amount::zero()` (a `const fn`), not `Default::default()`. This
    /// explicit impl calls `Amount::zero()` directly.
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: Amount::zero(),
            code_hash: Hash::zero(),
            storage_root: Hash::zero(),
            staked: Amount::zero(),
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
