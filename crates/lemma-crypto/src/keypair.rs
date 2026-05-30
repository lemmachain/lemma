//! Hybrid keypair — Ed25519 (classical) + ML-DSA-65 (post-quantum).
//!
//! This module provides the **single canonical key type** for Lemma validators
//! and users (AGENTS.md §2.2). All signing uses both schemes; verification
//! requires BOTH to pass.
//!
//! # Why hybrid?
//!
//! Hybrid signatures are "harvest now, decrypt later" resistant: a classical-only
//! signature is vulnerable to a future quantum adversary who recorded the
//! ciphertext. Requiring an ML-DSA-65 signature alongside Ed25519 ensures that
//! breaking one scheme is not sufficient to forge a signature.
//!
//! # Address derivation
//!
//! A Lemma address is derived from the **Ed25519** public key only:
//! `Address::from_public_key(&classical_pubkey_bytes)` = `Blake3(bytes)[0..20]`.
//! ML-DSA keys are too large (1952 bytes) for the 20-byte address space.
//!
//! # Security
//!
//! - `KeyPair` is intentionally **not `Clone`** — secret keys must not be
//!   duplicated accidentally. Persist via the OS keystore, never via clone.
//! - Signature verification uses the constant-time path inside `ed25519-dalek`
//!   (which uses `subtle::ConstantTimeEq` throughout scalar arithmetic),
//!   satisfying AGENTS.md §7.3.
//! - pqcrypto 0.1.x does not support deriving a public key from a secret key
//!   after generation. Therefore `KeyPair` stores the ML-DSA-65 public key at
//!   generation time. Never reconstruct the PQ keypair from the secret key
//!   alone — the derived public key would be for a different keypair.
//!
//! See `docs/04-BUILD_GUIDE.md` §2.2 and `docs/13-VALIDATOR_EPOCH_SPEC.md` §1.

use ed25519_dalek::{Signer as _, Verifier as _};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as PqPublicKeyTrait,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use lemma_core::{Address, Signature};

use crate::CryptoError;

// ─── PublicKey ───────────────────────────────────────────────────────────────

/// The public half of a Lemma hybrid keypair.
///
/// Stores both the Ed25519 verifying key (32 bytes) and the ML-DSA-65 public
/// key (1952 bytes) as raw bytes so the type is fully `Serialize + Deserialize
/// + PartialEq + Hash` — required for `ValidatorSet::members` and
/// `validators_hash` computation (see `docs/13-VALIDATOR_EPOCH_SPEC.md` §1/§4.4).
///
/// # Reconstruction
///
/// Use [`PublicKey::classical_verifying_key`] and [`PublicKey::quantum_public_key`]
/// to reconstruct the dalek / pqcrypto types for signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey {
    /// Ed25519 verifying key bytes — always exactly 32 bytes.
    pub classical: Vec<u8>,
    /// ML-DSA-65 public key bytes — always exactly 1952 bytes.
    pub quantum: Vec<u8>,
}

impl PublicKey {
    /// Reconstruct the Ed25519 verifying key from the stored bytes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidPublicKeyBytes`] if the bytes are not a valid
    /// Ed25519 curve point or have the wrong length.
    pub fn classical_verifying_key(
        &self,
    ) -> Result<ed25519_dalek::VerifyingKey, CryptoError> {
        let bytes: &[u8; 32] = self.classical.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidPublicKeyBytes {
                reason: format!("expected 32 bytes, got {}", self.classical.len()),
            }
        })?;
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKeyBytes { reason: e.to_string() })
    }

    /// Reconstruct the ML-DSA-65 public key from the stored bytes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidQuantumPublicKeyBytes`] if the bytes are not a
    /// valid ML-DSA-65 public key.
    pub fn quantum_public_key(&self) -> Result<mldsa65::PublicKey, CryptoError> {
        mldsa65::PublicKey::from_bytes(&self.quantum).map_err(|e| {
            CryptoError::InvalidQuantumPublicKeyBytes { reason: e.to_string() }
        })
    }

    /// Derive the Lemma [`Address`] from the classical (Ed25519) component.
    ///
    /// Returns `None` if the classical bytes are not exactly 32 bytes.
    #[must_use]
    pub fn to_address(&self) -> Option<Address> {
        let bytes: &[u8; 32] = self.classical.as_slice().try_into().ok()?;
        Some(Address::from_public_key(bytes))
    }
}

// ─── HybridSignature ─────────────────────────────────────────────────────────

/// A detached hybrid signature: Ed25519 (64 bytes) + ML-DSA-65 (3309 bytes).
///
/// **Both** halves must verify for [`verify`] to succeed. Convert to
/// [`lemma_core::Signature::Hybrid`] for embedding in a transaction via
/// [`HybridSignature::to_lemma_signature`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Ed25519 detached signature — 64 bytes.
    pub classical: Vec<u8>,
    /// ML-DSA-65 detached signature — 3309 bytes.
    pub quantum: Vec<u8>,
}

impl HybridSignature {
    /// Convert to [`lemma_core::Signature::Hybrid`] for embedding in a
    /// [`lemma_core::Transaction`] or [`lemma_core::BlockHeader`].
    #[must_use]
    pub fn to_lemma_signature(&self) -> Signature {
        Signature::Hybrid {
            classical: self.classical.clone(),
            quantum:   self.quantum.clone(),
        }
    }
}

// ─── KeyPair ─────────────────────────────────────────────────────────────────

/// A Lemma hybrid keypair: Ed25519 (classical) + ML-DSA-65 (post-quantum).
///
/// Stores **both halves** of the ML-DSA-65 keypair at generation time because
/// pqcrypto 0.1.x does not support re-deriving the public key from the secret
/// key after the fact.
///
/// # Examples
///
/// ```no_run
/// use lemma_crypto::{KeyPair, verify};
///
/// let kp  = KeyPair::generate().unwrap();
/// let pk  = kp.public_key();
/// let sig = kp.sign(b"hello lemma");
/// assert!(verify(&pk, b"hello lemma", &sig).is_ok());
/// ```
///
/// # Security
///
/// `KeyPair` is **not `Clone`** — accidental copies of the signing key are
/// a security risk. Persist the key to an encrypted keystore; reconstruct
/// by deserializing the secret key bytes.
pub struct KeyPair {
    /// Ed25519 signing key (contains both the private scalar and verifying key).
    classical: ed25519_dalek::SigningKey,
    /// ML-DSA-65 secret key (4032 bytes). Stored by value; pass references.
    quantum_sk: mldsa65::SecretKey,
    /// ML-DSA-65 public key (1952 bytes). Stored at generation time because
    /// pqcrypto 0.1.x cannot derive pk from sk after the fact.
    quantum_pk: mldsa65::PublicKey,
    /// Derived address — `Blake3(Ed25519_pubkey)[0..20]`. Cached at generation.
    address: Address,
}

impl KeyPair {
    /// Generate a fresh hybrid keypair using OS entropy.
    ///
    /// - Ed25519: uses [`rand::rngs::OsRng`].
    /// - ML-DSA-65: uses pqcrypto's internal C entropy (independent of the
    ///   Rust RNG).
    ///
    /// Both the ML-DSA-65 public key **and** secret key are stored at
    /// generation time — the public key cannot be re-derived later
    /// (pqcrypto 0.1.x limitation).
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGenerationFailed`] if the OS RNG is unavailable
    /// (extremely rare; indicates a broken OS environment).
    pub fn generate() -> Result<Self, CryptoError> {
        let classical  = ed25519_dalek::SigningKey::generate(&mut OsRng);
        // pqcrypto uses its own internal C entropy — no RNG argument needed.
        let (quantum_pk, quantum_sk) = mldsa65::keypair();
        let address = Address::from_public_key(classical.verifying_key().as_bytes());
        Ok(Self { classical, quantum_sk, quantum_pk, address })
    }

    /// Derive the [`PublicKey`] (Ed25519 + ML-DSA-65 verifying keys as bytes).
    ///
    /// The returned `PublicKey` is `Serialize + Deserialize + PartialEq + Hash`
    /// and is the type stored in `Validator.consensus_pubkey` (spec 13 §1).
    /// This is an O(1) read — both public keys are cached at generation.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            classical: self.classical.verifying_key().as_bytes().to_vec(),
            quantum:   self.quantum_pk.as_bytes().to_vec(),
        }
    }

    /// Return a reference to the derived [`Address`] for this keypair.
    ///
    /// Derived from the Ed25519 public key at generation and cached —
    /// this is a zero-cost view.
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Sign `message` with both the Ed25519 and ML-DSA-65 keys.
    ///
    /// Returns a [`HybridSignature`] where **both** halves must verify.
    /// The result is deterministic for the same `(key, message)` pair.
    ///
    /// # Infallibility
    ///
    /// This function cannot fail — Ed25519 signing is infallible for any
    /// message, and ML-DSA-65 signing is infallible for any message given a
    /// valid secret key (guaranteed post-generation).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let classical_sig = self.classical.sign(message);
        let quantum_sig   = mldsa65::detached_sign(message, &self.quantum_sk);
        HybridSignature {
            classical: classical_sig.to_bytes().to_vec(),
            quantum:   quantum_sig.as_bytes().to_vec(),
        }
    }

    /// Sign `message` and return a [`lemma_core::Signature::Hybrid`] ready
    /// for embedding in a [`lemma_core::Transaction`].
    #[must_use]
    pub fn sign_to_lemma(&self, message: &[u8]) -> Signature {
        self.sign(message).to_lemma_signature()
    }
}

// ─── verify ──────────────────────────────────────────────────────────────────

/// Verify a [`HybridSignature`] against a [`PublicKey`] and message.
///
/// **Both** the Ed25519 classical signature **and** the ML-DSA-65 post-quantum
/// signature must independently verify — passing either alone is rejected.
///
/// Classical verification delegates to `ed25519-dalek`, which uses
/// `subtle::ConstantTimeEq` throughout its scalar arithmetic, satisfying the
/// constant-time requirement (AGENTS.md §7.3).
///
/// # Errors
///
/// | Error | Cause |
/// |---|---|
/// | [`CryptoError::InvalidPublicKeyBytes`] | Classical key is not a valid Ed25519 point |
/// | [`CryptoError::InvalidQuantumPublicKeyBytes`] | Quantum key bytes are invalid |
/// | [`CryptoError::InvalidClassicalSignatureLength`] | Classical sig ≠ 64 bytes |
/// | [`CryptoError::InvalidQuantumSignatureLength`] | Quantum sig wrong length |
/// | [`CryptoError::ClassicalVerificationFailed`] | Ed25519 signature invalid |
/// | [`CryptoError::QuantumVerificationFailed`] | ML-DSA-65 signature invalid |
///
/// # Examples
///
/// ```no_run
/// use lemma_crypto::{KeyPair, verify};
///
/// let kp  = KeyPair::generate().unwrap();
/// let pk  = kp.public_key();
/// let sig = kp.sign(b"hello lemma");
///
/// assert!(verify(&pk, b"hello lemma", &sig).is_ok());
/// assert!(verify(&pk, b"tampered!", &sig).is_err());
/// ```
pub fn verify(
    pubkey:  &PublicKey,
    message: &[u8],
    sig:     &HybridSignature,
) -> Result<(), CryptoError> {
    // ── Classical (Ed25519) ──────────────────────────────────────────────────
    let vk = pubkey.classical_verifying_key()?;

    let classical_bytes: [u8; 64] =
        sig.classical.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidClassicalSignatureLength { got: sig.classical.len() }
        })?;
    let classical_sig = ed25519_dalek::Signature::from_bytes(&classical_bytes);

    vk.verify(message, &classical_sig)
        .map_err(|_| CryptoError::ClassicalVerificationFailed)?;

    // ── Post-quantum (ML-DSA-65) ─────────────────────────────────────────────
    let pq_pub = pubkey.quantum_public_key()?;

    // mldsa65::DetachedSignature::from_bytes takes &[u8] via the trait method.
    let pq_sig = mldsa65::DetachedSignature::from_bytes(&sig.quantum).map_err(|_| {
        CryptoError::InvalidQuantumSignatureLength {
            expected: mldsa65::signature_bytes(),
            got:      sig.quantum.len(),
        }
    })?;

    // Note: verify_detached_signature arg order is (sig, message, pk) —
    // NOT (pk, message, sig). See docs/external-context/keypair/pqcrypto-mldsa.md.
    mldsa65::verify_detached_signature(&pq_sig, message, &pq_pub)
        .map_err(|_| CryptoError::QuantumVerificationFailed)?;

    Ok(())
}

// ─── Conversions ─────────────────────────────────────────────────────────────

/// Convert a `lemma_crypto::PublicKey` into a `lemma_core::ConsensusKey`.
///
/// This is the canonical bridge between the crypto-operations type (`PublicKey`,
/// which can reconstruct `ed25519_dalek::VerifyingKey` / `mldsa65::PublicKey`)
/// and the storage type (`ConsensusKey`, which is raw bytes in `lemma-core`).
///
/// The dependency direction is correct: `lemma-crypto` depends on `lemma-core`,
/// so this `From` impl lives here. `lemma-core` never imports `lemma-crypto`.
impl From<PublicKey> for lemma_core::ConsensusKey {
    fn from(pk: PublicKey) -> Self {
        lemma_core::ConsensusKey::from_bytes(pk.classical, pk.quantum)
    }
}

/// Convert a `lemma_core::ConsensusKey` into a `lemma_crypto::PublicKey`.
///
/// Allows reconstructing the crypto-operations type from stored raw bytes.
/// No cryptographic validation is performed — call
/// `PublicKey::classical_verifying_key()` / `quantum_public_key()` to validate.
impl From<lemma_core::ConsensusKey> for PublicKey {
    fn from(ck: lemma_core::ConsensusKey) -> Self {
        PublicKey {
            classical: ck.classical,
            quantum:   ck.quantum,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
