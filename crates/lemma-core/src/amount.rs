//! Amount newtype — a token quantity measured in Drop (the smallest unit).
//!
//! # Unit system
//!
//! | Unit | Value | Purpose |
//! |------|-------|---------|
//! | Drop | 1 | Smallest unit (analogous to Wei) |
//! | Drip | 10⁹ Drop | Gas price unit (analogous to Gwei) |
//! | LEM  | 10¹⁸ Drop | Display / human unit |
//!
//! All arithmetic is checked. Overflow or underflow returns an
//! [`AmountError`](crate::error::AmountError) with the operands included.
//!
//! Serialized as a decimal string (e.g. `"1000000000000000000"`) to avoid
//! JSON precision loss on `u128` values above `i64::MAX`.
//!
//! See `docs/04-BUILD_GUIDE.md` Section 2.1.

use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::AmountError;

// ─── Unit constants ───────────────────────────────────────────────────────────

/// Number of Drop in one LEM (10¹⁸).
pub const DROPS_PER_LEM: u128 = 1_000_000_000_000_000_000;

/// Number of Drip in one LEM (10⁹).
///
/// One Drip = 10⁹ Drop. Used as the gas price unit.
pub const DRIPS_PER_LEM: u128 = 1_000_000_000;

/// Number of Drop in one Drip (10⁹).
///
/// Derived: `DROPS_PER_LEM / DRIPS_PER_LEM`.
pub const DROPS_PER_DRIP: u128 = DROPS_PER_LEM / DRIPS_PER_LEM;

// ─── Amount ───────────────────────────────────────────────────────────────────

/// A non-negative token quantity stored internally in Drop (the smallest unit).
///
/// Construct via [`Amount::from_drop`], [`Amount::from_lem`], or
/// [`Amount::from_drip`]. Perform arithmetic via the `checked_*` methods —
/// never use raw `+`/`-`/`*`/`/` on amounts.
///
/// # Examples
///
/// ```no_run
/// use lemma_core::amount::{Amount, DROPS_PER_LEM};
///
/// let one_lem = Amount::from_lem(1).unwrap();
/// let fee     = Amount::from_drop(500_000);
/// let total   = one_lem.checked_add(fee).unwrap();
/// assert_eq!(total.as_drop(), DROPS_PER_LEM + 500_000);
/// ```
// `Debug` and `Serialize`/`Deserialize` are implemented manually below:
// - `Debug`: to produce `Amount({n} Drop)` for unambiguous raw-unit output
// - `Serialize`/`Deserialize`: to use decimal strings, avoiding JSON u128 precision loss
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u128);

impl Amount {
    // ── Construction ─────────────────────────────────────────────────────────

    /// The zero amount (0 Drop).
    pub const fn zero() -> Self {
        Amount(0)
    }

    /// Create an `Amount` directly from a raw Drop count.
    ///
    /// Infallible — Drop is the base unit, no conversion needed.
    pub const fn from_drop(drops: u128) -> Self {
        Amount(drops)
    }

    /// Create an `Amount` from a whole LEM count, converting to Drop.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::Overflow`] if `lem * DROPS_PER_LEM` overflows
    /// `u128`. In practice the total LEM supply fits well within `u128`.
    pub fn from_lem(lem: u128) -> Result<Self, AmountError> {
        lem.checked_mul(DROPS_PER_LEM)
            .map(Amount)
            .ok_or(AmountError::Overflow {
                lhs: lem,
                rhs: DROPS_PER_LEM,
            })
    }

    /// Create an `Amount` from a Drip count, converting to Drop.
    ///
    /// Primarily used for gas prices: `1 Drip = 1_000_000_000 Drop`.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::Overflow`] if `drips * DROPS_PER_DRIP` overflows `u128`.
    pub fn from_drip(drips: u128) -> Result<Self, AmountError> {
        drips
            .checked_mul(DROPS_PER_DRIP)
            .map(Amount)
            .ok_or(AmountError::Overflow {
                lhs: drips,
                rhs: DROPS_PER_DRIP,
            })
    }

    // ── Access ───────────────────────────────────────────────────────────────

    /// Return the raw value in Drop (the base unit).
    ///
    /// Use this for arithmetic, storage, and wire-format encoding.
    /// Prefer [`Amount::to_string`] for human-readable output.
    pub fn as_drop(&self) -> u128 {
        self.0
    }

    /// Returns `true` if this amount is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    // ── Checked arithmetic ────────────────────────────────────────────────────
    //
    // All token arithmetic uses checked operations per AGENTS.md §7.4.
    // Overflow/underflow returns an error with both operands included.

    /// Add two amounts.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::Overflow`] with both operands if the result
    /// exceeds `u128::MAX`.
    pub fn checked_add(self, rhs: Self) -> Result<Self, AmountError> {
        self.0
            .checked_add(rhs.0)
            .map(Amount)
            .ok_or(AmountError::Overflow {
                lhs: self.0,
                rhs: rhs.0,
            })
    }

    /// Subtract `rhs` from `self`.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::Underflow`] with both operands if the result
    /// would be negative.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, AmountError> {
        self.0
            .checked_sub(rhs.0)
            .map(Amount)
            .ok_or(AmountError::Underflow {
                lhs: self.0,
                rhs: rhs.0,
            })
    }

    /// Multiply the amount by a scalar.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::Overflow`] with both operands if the result
    /// exceeds `u128::MAX`.
    pub fn checked_mul(self, rhs: u128) -> Result<Self, AmountError> {
        self.0
            .checked_mul(rhs)
            .map(Amount)
            .ok_or(AmountError::Overflow { lhs: self.0, rhs })
    }

    /// Divide the amount by a scalar (integer division, truncates toward zero).
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::DivisionByZero`] if `rhs` is zero.
    pub fn checked_div(self, rhs: u128) -> Result<Self, AmountError> {
        self.0
            .checked_div(rhs)
            .map(Amount)
            .ok_or(AmountError::DivisionByZero { lhs: self.0 })
    }
}

// ─── Display & Debug ─────────────────────────────────────────────────────────

impl fmt::Display for Amount {
    /// Human-readable LEM display, trimming trailing decimal zeros.
    ///
    /// Examples: `"0 LEM"`, `"1 LEM"`, `"1.5 LEM"`,
    /// `"0.000000000000000001 LEM"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lem = self.0 / DROPS_PER_LEM;
        let frac = self.0 % DROPS_PER_LEM;
        if frac == 0 {
            write!(f, "{} LEM", lem)
        } else {
            // Pad fractional part to 18 digits, then trim trailing zeros.
            let frac_str = format!("{:018}", frac);
            let frac_trimmed = frac_str.trim_end_matches('0');
            write!(f, "{}.{} LEM", lem, frac_trimmed)
        }
    }
}

impl fmt::Debug for Amount {
    /// Raw Drop count for unambiguous debug output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({} Drop)", self.0)
    }
}

// ─── Serde ───────────────────────────────────────────────────────────────────

// Decimal string encoding prevents JSON precision loss on u128 values that
// exceed i64::MAX (~9.2 × 10¹⁸, just above DROPS_PER_LEM).
impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<u128>().map(Amount).map_err(de::Error::custom)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
