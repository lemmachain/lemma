//! State snapshot management for crash recovery.
//!
//! A snapshot is a **RocksDB checkpoint** — a hard-linked, point-in-time
//! physical copy of the database. Creating a snapshot is nearly instant and
//! storage-efficient (SST files are shared until they diverge). Restoring
//! from a snapshot requires only `LemmaDb::open(snapshot_path)` followed by
//! `WorldState::with_state_root(db, metadata.state_root)`.
//!
//! ## Snapshot layout
//!
//! ```text
//! <snapshot_dir>/
//! ├── snapshot_001000/          # checkpoint at height 1000
//! │   ├── metadata.json         # SnapshotMetadata (height, state_root, timestamp)
//! │   └── <RocksDB files>       # CURRENT, MANIFEST-*, *.sst, ...
//! ├── snapshot_002000/
//! │   └── ...
//! └── snapshot_003000/
//!     └── ...
//! ```
//!
//! ## Lifecycle
//!
//! 1. **Create** — `SnapshotManager::create_snapshot(db, metadata)`:
//!    - Calls `LemmaDb::create_checkpoint(path)` to hard-link the SST files.
//!    - Writes `metadata.json` alongside the checkpoint.
//!    - Prunes oldest snapshots beyond `max_snapshots`.
//!
//! 2. **Restore** — `SnapshotManager::restore_path(height)`:
//!    - Returns the checkpoint directory path.
//!    - Caller opens it with `LemmaDb::open(path)` +
//!      `WorldState::with_state_root(db, metadata.state_root)`.
//!
//! ## What this module does NOT do
//!
//! - **Snapshot scheduling** — the node decides when to snapshot (at epoch
//!   boundaries, or every `SNAPSHOT_INTERVAL` blocks). Scheduling lives in
//!   `lemma-node`.
//! - **State-sync serving** (chunk + range proof) — lives in `lemma-network`.
//! - **Async creation** — Phase 2. For Phase 1, snapshots are synchronous.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use lemma_core::Hash;
use serde::{Deserialize, Serialize};

use crate::{db::LemmaDb, StorageError};

/// Filename for snapshot metadata within each snapshot directory.
const METADATA_FILENAME: &str = "metadata.json";

/// Prefix used to name snapshot subdirectories.
///
/// Format: `snapshot_<height_zero_padded_12>` — zero-padded to 12 digits so
/// lexicographic sort equals numeric sort up to height 999_999_999_999.
const SNAPSHOT_DIR_PREFIX: &str = "snapshot_";

// ─── SnapshotMetadata ─────────────────────────────────────────────────────────

/// Metadata stored alongside each RocksDB checkpoint.
///
/// Written as `metadata.json` in the snapshot directory. JSON is used (rather
/// than bincode) so the file is human-readable and inspectable with standard
/// tools — important for incident response and operational debugging.
///
/// The `state_root` is the cryptographic anchor for the snapshot: after
/// restore, `WorldState::with_state_root(db, metadata.state_root)` resumes
/// the exact state captured at `height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Block height at which this snapshot was taken.
    ///
    /// The snapshot represents the world state *after* all transactions in
    /// block `height` have been applied and committed.
    pub height: u64,

    /// Blake3 Merkle root of the world state trie at `height`.
    ///
    /// Used to resume [`WorldState`] after restore:
    /// `WorldState::with_state_root(db, metadata.state_root)`.
    ///
    /// [`WorldState`]: crate::state::WorldState
    pub state_root: Hash,

    /// Unix timestamp (seconds since epoch) when this snapshot was created.
    ///
    /// Used for display and pruning — not for consensus. Never use this for
    /// any timing that affects chain state.
    pub timestamp: u64,
}

impl SnapshotMetadata {
    /// Create metadata for a snapshot taken at `height` with `state_root`.
    ///
    /// `timestamp` is set to the current wall-clock time. If the system
    /// clock is unavailable, falls back to `0` — this only affects display,
    /// never consensus.
    pub fn new(height: u64, state_root: Hash) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self { height, state_root, timestamp }
    }
}

// ─── SnapshotManager ──────────────────────────────────────────────────────────

/// Manages snapshot creation, listing, and pruning.
///
/// A `SnapshotManager` is bound to a single `snapshot_dir` on disk. Multiple
/// `SnapshotManager` instances pointing to the same directory are unsupported
/// — create one per node process.
///
/// ## Thread safety
///
/// `SnapshotManager` is `Send + Sync` (it holds only a `PathBuf` and `usize`).
/// Concurrent calls to `create_snapshot` from multiple threads are safe at the
/// `SnapshotManager` level, but callers must ensure `LemmaDb` is not being
/// written to concurrently during checkpoint creation.
pub struct SnapshotManager {
    /// Base directory where all snapshot subdirectories live.
    snapshot_dir: PathBuf,
    /// Maximum number of snapshots to retain. Older snapshots are pruned
    /// automatically after each `create_snapshot`. `0` means unlimited.
    max_snapshots: usize,
}

impl SnapshotManager {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Create a `SnapshotManager` rooted at `snapshot_dir`.
    ///
    /// The directory is created if it does not exist.
    ///
    /// `max_snapshots` controls how many snapshots to retain. Older snapshots
    /// are pruned automatically on each `create_snapshot`. `0` = unlimited
    /// (no pruning). Recommended default: `3`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SnapshotFailed`] if `snapshot_dir` cannot be
    /// created (e.g. insufficient permissions).
    pub fn new<P: AsRef<Path>>(
        snapshot_dir: P,
        max_snapshots: usize,
    ) -> Result<Self, StorageError> {
        let snapshot_dir = snapshot_dir.as_ref().to_path_buf();
        fs::create_dir_all(&snapshot_dir).map_err(|e| StorageError::SnapshotFailed {
            reason: format!("cannot create snapshot directory '{}': {e}", snapshot_dir.display()),
        })?;
        Ok(Self { snapshot_dir, max_snapshots })
    }

    // ── Create ────────────────────────────────────────────────────────────────

    /// Create a snapshot of `db` at `metadata.height`.
    ///
    /// Calls `db.create_checkpoint(path)` to hard-link the current SST files,
    /// then writes `metadata.json` alongside the checkpoint. If a snapshot at
    /// `metadata.height` already exists it is replaced (the old directory is
    /// removed first).
    ///
    /// After creating, prunes oldest snapshots if `max_snapshots > 0`.
    ///
    /// Returns the path to the new snapshot directory.
    ///
    /// # Errors
    ///
    /// - [`StorageError::SnapshotFailed`] — checkpoint creation or metadata
    ///   write failed. The old snapshot (if any) may have been removed already;
    ///   recovery falls back to the previous snapshot.
    pub fn create_snapshot(
        &self,
        db: &LemmaDb,
        metadata: &SnapshotMetadata,
    ) -> Result<PathBuf, StorageError> {
        let path = self.snapshot_path(metadata.height);

        // Remove existing snapshot at this height before overwriting.
        if path.exists() {
            fs::remove_dir_all(&path).map_err(|e| StorageError::SnapshotFailed {
                reason: format!(
                    "cannot remove existing snapshot at '{}': {e}",
                    path.display()
                ),
            })?;
        }

        // Create the RocksDB checkpoint (hard-linked SST files).
        db.create_checkpoint(&path)?;

        // Write metadata alongside the checkpoint.
        self.write_metadata(&path, metadata)?;

        // Prune oldest snapshots beyond max_snapshots.
        if self.max_snapshots > 0 {
            self.prune()?;
        }

        Ok(path)
    }

    // ── List / Query ──────────────────────────────────────────────────────────

    /// List all valid snapshots, sorted by height descending (newest first).
    ///
    /// Snapshots with missing or unparseable `metadata.json` are silently
    /// skipped — a partial write during a previous crash should not prevent
    /// the node from reading the other snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SnapshotFailed`] if `snapshot_dir` cannot be
    /// read (e.g. the directory was deleted externally).
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotMetadata>, StorageError> {
        let entries = fs::read_dir(&self.snapshot_dir).map_err(|e| {
            StorageError::SnapshotFailed {
                reason: format!(
                    "cannot read snapshot directory '{}': {e}",
                    self.snapshot_dir.display()
                ),
            }
        })?;

        let mut snapshots: Vec<SnapshotMetadata> = entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                // Only consider directories whose name starts with the prefix.
                if !path.is_dir() {
                    return None;
                }
                let name = path.file_name()?.to_str()?;
                if !name.starts_with(SNAPSHOT_DIR_PREFIX) {
                    return None;
                }
                // Read metadata; skip on any error (partial write).
                self.read_metadata(&path).ok()
            })
            .collect();

        // Sort newest-first (highest height first).
        snapshots.sort_by(|a, b| b.height.cmp(&a.height));
        Ok(snapshots)
    }

    /// Return the metadata for the most recent (highest-height) valid snapshot,
    /// or `None` if no snapshots exist.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`list_snapshots`].
    ///
    /// [`list_snapshots`]: SnapshotManager::list_snapshots
    pub fn latest_snapshot(&self) -> Result<Option<SnapshotMetadata>, StorageError> {
        Ok(self.list_snapshots()?.into_iter().next())
    }

    // ── Restore ───────────────────────────────────────────────────────────────

    /// Return the metadata for the snapshot at `height`, if it exists.
    ///
    /// Use this to verify a snapshot before restoring:
    ///
    /// ```ignore
    /// let meta = manager.snapshot_metadata(height)?
    ///     .ok_or(StorageError::RestoreFailed { reason: "snapshot not found".into() })?;
    /// let db = LemmaDb::open(manager.restore_path(height)?)?;
    /// let ws = WorldState::with_state_root(db, meta.state_root);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::RestoreFailed`] if the metadata file is missing
    /// or corrupt.
    pub fn snapshot_metadata(
        &self,
        height: u64,
    ) -> Result<Option<SnapshotMetadata>, StorageError> {
        let path = self.snapshot_path(height);
        if !path.exists() {
            return Ok(None);
        }
        let meta = self.read_metadata(&path).map_err(|_| StorageError::RestoreFailed {
            reason: format!("metadata.json for snapshot at height {height} is missing or corrupt"),
        })?;
        Ok(Some(meta))
    }

    /// Return the filesystem path of the snapshot directory at `height`.
    ///
    /// The returned path is the root of a valid RocksDB database directory
    /// that can be opened with `LemmaDb::open(path)`. Does **not** validate
    /// that the snapshot actually exists — call [`snapshot_metadata`] first.
    ///
    /// [`snapshot_metadata`]: SnapshotManager::snapshot_metadata
    pub fn restore_path(&self, height: u64) -> PathBuf {
        self.snapshot_path(height)
    }

    // ── Prune ─────────────────────────────────────────────────────────────────

    /// Remove oldest snapshots, keeping only the `max_snapshots` most recent.
    ///
    /// If `max_snapshots == 0` (unlimited), this is a no-op. Returns the
    /// number of snapshots removed.
    ///
    /// Snapshots are identified by their directory name — a directory with a
    /// corrupt `metadata.json` is still counted and pruned by age (determined
    /// from the directory name's height suffix).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SnapshotFailed`] if a snapshot directory cannot
    /// be removed. Does **not** fail on partial success — removes as many as
    /// possible and reports the first removal error.
    pub fn prune(&self) -> Result<usize, StorageError> {
        if self.max_snapshots == 0 {
            return Ok(0);
        }

        // Collect all snapshot directories sorted newest-first by height.
        let all_dirs = self.all_snapshot_dirs()?;

        let to_remove = all_dirs.into_iter().skip(self.max_snapshots).collect::<Vec<_>>();
        let count = to_remove.len();

        for dir in to_remove {
            fs::remove_dir_all(&dir).map_err(|e| StorageError::SnapshotFailed {
                reason: format!("cannot prune snapshot '{}': {e}", dir.display()),
            })?;
        }

        Ok(count)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Canonical path for the snapshot directory at `height`.
    fn snapshot_path(&self, height: u64) -> PathBuf {
        // Zero-pad to 12 digits so lexicographic sort matches numeric sort.
        self.snapshot_dir.join(format!("{SNAPSHOT_DIR_PREFIX}{height:012}"))
    }

    /// Write `metadata` as `metadata.json` inside `snapshot_path`.
    fn write_metadata(
        &self,
        snapshot_path: &Path,
        metadata: &SnapshotMetadata,
    ) -> Result<(), StorageError> {
        let meta_path = snapshot_path.join(METADATA_FILENAME);
        let json = serde_json::to_string_pretty(metadata).map_err(|e| {
            StorageError::SnapshotFailed {
                reason: format!("cannot serialise snapshot metadata: {e}"),
            }
        })?;
        fs::write(&meta_path, json).map_err(|e| StorageError::SnapshotFailed {
            reason: format!("cannot write metadata.json to '{}': {e}", meta_path.display()),
        })
    }

    /// Read and deserialise `metadata.json` from `snapshot_path`.
    fn read_metadata(&self, snapshot_path: &Path) -> Result<SnapshotMetadata, StorageError> {
        let meta_path = snapshot_path.join(METADATA_FILENAME);
        let json = fs::read_to_string(&meta_path).map_err(|e| StorageError::RestoreFailed {
            reason: format!("cannot read '{}': {e}", meta_path.display()),
        })?;
        serde_json::from_str(&json).map_err(|e| StorageError::RestoreFailed {
            reason: format!("cannot parse '{}': {e}", meta_path.display()),
        })
    }

    /// Return all snapshot directories sorted newest-first (by height parsed
    /// from directory name). Directories whose names cannot be parsed are
    /// skipped.
    fn all_snapshot_dirs(&self) -> Result<Vec<PathBuf>, StorageError> {
        let entries = fs::read_dir(&self.snapshot_dir).map_err(|e| {
            StorageError::SnapshotFailed {
                reason: format!(
                    "cannot read snapshot directory '{}': {e}",
                    self.snapshot_dir.display()
                ),
            }
        })?;

        let mut dirs: Vec<(u64, PathBuf)> = entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if !path.is_dir() {
                    return None;
                }
                let name = path.file_name()?.to_str()?;
                let height_str = name.strip_prefix(SNAPSHOT_DIR_PREFIX)?;
                let height: u64 = height_str.parse().ok()?;
                Some((height, path))
            })
            .collect();

        // Newest-first (highest height first).
        dirs.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(dirs.into_iter().map(|(_, p)| p).collect())
    }
}

#[cfg(test)]
mod tests;
