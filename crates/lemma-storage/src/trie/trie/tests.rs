//! Tests for `lemma_storage::trie::trie`.
//!
//! Covers empty trie, single insert, updates, diverging paths,
//! prefix relationships, branch/extension creation, root determinism,
//! and persistence across trie reopening.

use tempfile::tempdir;

use super::*;
use crate::db::LemmaDb;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir must succeed");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed");
    (db, dir)
}

fn trie(db: &LemmaDb) -> MerklePatriciaTrie<'_> {
    MerklePatriciaTrie::new(db)
}

// ── Empty trie ────────────────────────────────────────────────────────────────

#[test]
fn empty_trie_root_is_none() {
    let (db, _dir) = open_temp_db();
    assert!(trie(&db).root().is_none());
}

#[test]
fn empty_trie_get_returns_none() {
    let (db, _dir) = open_temp_db();
    assert_eq!(trie(&db).get(b"key").unwrap(), None);
}

// ── Single insert ─────────────────────────────────────────────────────────────

#[test]
fn insert_sets_non_none_root() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key", b"val".to_vec()).unwrap();
    assert!(t.root().is_some());
}

#[test]
fn insert_then_get_returns_value() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"hello", b"world".to_vec()).unwrap();
    assert_eq!(t.get(b"hello").unwrap(), Some(b"world".to_vec()));
}

#[test]
fn get_on_uninserted_key_returns_none() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key_a", b"val_a".to_vec()).unwrap();
    assert_eq!(t.get(b"key_b").unwrap(), None);
}

// ── Update existing key ───────────────────────────────────────────────────────

#[test]
fn insert_same_key_twice_returns_new_value() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key", b"value_1".to_vec()).unwrap();
    t.insert(b"key", b"value_2".to_vec()).unwrap();
    assert_eq!(t.get(b"key").unwrap(), Some(b"value_2".to_vec()));
}

#[test]
fn root_changes_on_first_insert() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    let root_before = t.root();
    t.insert(b"k", b"v".to_vec()).unwrap();
    assert_ne!(t.root(), root_before);
}

#[test]
fn root_changes_on_value_update() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"k", b"v1".to_vec()).unwrap();
    let root_after_first = t.root();
    t.insert(b"k", b"v2".to_vec()).unwrap();
    assert_ne!(t.root(), root_after_first);
}

#[test]
fn root_is_stable_when_same_key_same_value_reinserted() {
    // Reinserting the identical key-value pair must produce the same root.
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"k", b"v".to_vec()).unwrap();
    let root_first = t.root();
    t.insert(b"k", b"v".to_vec()).unwrap();
    assert_eq!(t.root(), root_first);
}

// ── Two diverging keys (Branch creation) ─────────────────────────────────────

#[test]
fn two_keys_diverging_at_first_nibble_both_retrievable() {
    // Keys "a" (0x61) and "b" (0x62) share no nibbles at position 0.
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"a", b"val_a".to_vec()).unwrap();
    t.insert(b"b", b"val_b".to_vec()).unwrap();
    assert_eq!(t.get(b"a").unwrap(), Some(b"val_a".to_vec()));
    assert_eq!(t.get(b"b").unwrap(), Some(b"val_b".to_vec()));
}

#[test]
fn two_keys_with_long_common_prefix_both_retrievable() {
    // Keys "abcdefgh" and "abcdefgx" share 7 bytes = 14 nibbles.
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"abcdefgh", b"val1".to_vec()).unwrap();
    t.insert(b"abcdefgx", b"val2".to_vec()).unwrap();
    assert_eq!(t.get(b"abcdefgh").unwrap(), Some(b"val1".to_vec()));
    assert_eq!(t.get(b"abcdefgx").unwrap(), Some(b"val2".to_vec()));
}

// ── Prefix key relationships ───────────────────────────────────────────────────

#[test]
fn key_is_prefix_of_other_key_both_retrievable() {
    // "ab" is a prefix of "abc".
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"ab", b"short".to_vec()).unwrap();
    t.insert(b"abc", b"long".to_vec()).unwrap();
    assert_eq!(t.get(b"ab").unwrap(), Some(b"short".to_vec()));
    assert_eq!(t.get(b"abc").unwrap(), Some(b"long".to_vec()));
}

#[test]
fn longer_key_inserted_first_then_prefix_key_both_retrievable() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"abc", b"long".to_vec()).unwrap();
    t.insert(b"ab", b"short".to_vec()).unwrap();
    assert_eq!(t.get(b"abc").unwrap(), Some(b"long".to_vec()));
    assert_eq!(t.get(b"ab").unwrap(), Some(b"short".to_vec()));
}

// ── Three or more keys ────────────────────────────────────────────────────────

#[test]
fn three_distinct_keys_all_retrievable() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    t.insert(b"key2", b"val2".to_vec()).unwrap();
    t.insert(b"key3", b"val3".to_vec()).unwrap();
    assert_eq!(t.get(b"key1").unwrap(), Some(b"val1".to_vec()));
    assert_eq!(t.get(b"key2").unwrap(), Some(b"val2".to_vec()));
    assert_eq!(t.get(b"key3").unwrap(), Some(b"val3".to_vec()));
}

#[test]
fn many_keys_all_retrievable() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    let pairs: Vec<(&[u8], &[u8])> = vec![
        (b"account_lem1a", b"acc1"),
        (b"account_lem1b", b"acc2"),
        (b"account_lem1c", b"acc3"),
        (b"contract_lem1c", b"code"),
        (b"metadata", b"meta"),
    ];
    for (k, v) in &pairs {
        t.insert(k, v.to_vec()).unwrap();
    }
    for (k, v) in &pairs {
        assert_eq!(t.get(k).unwrap(), Some(v.to_vec()), "failed for key {:?}", k);
    }
}

// ── Empty key edge case ───────────────────────────────────────────────────────

#[test]
fn insert_and_get_empty_key() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"", b"empty_key_value".to_vec()).unwrap();
    assert_eq!(t.get(b"").unwrap(), Some(b"empty_key_value".to_vec()));
}

#[test]
fn empty_key_and_nonempty_key_both_retrievable() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"", b"root_value".to_vec()).unwrap();
    t.insert(b"a", b"a_value".to_vec()).unwrap();
    assert_eq!(t.get(b"").unwrap(), Some(b"root_value".to_vec()));
    assert_eq!(t.get(b"a").unwrap(), Some(b"a_value".to_vec()));
}

// ── 32-byte keys (full account address length) ────────────────────────────────

#[test]
fn insert_and_get_32_byte_key() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    let key = [0xABu8; 32];
    t.insert(&key, b"account_bytes".to_vec()).unwrap();
    assert_eq!(t.get(&key).unwrap(), Some(b"account_bytes".to_vec()));
}

#[test]
fn two_32_byte_keys_differing_at_last_byte_both_retrievable() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    let mut key_a = [0xABu8; 32];
    let mut key_b = [0xABu8; 32];
    key_b[31] = 0xCD;
    t.insert(&key_a, b"val_a".to_vec()).unwrap();
    t.insert(&key_b, b"val_b".to_vec()).unwrap();
    assert_eq!(t.get(&key_a).unwrap(), Some(b"val_a".to_vec()));
    assert_eq!(t.get(&key_b).unwrap(), Some(b"val_b".to_vec()));
}

// ── Root determinism ──────────────────────────────────────────────────────────

#[test]
fn same_insertions_in_same_order_produce_same_root() {
    let (db1, _dir1) = open_temp_db();
    let mut t1 = trie(&db1);
    t1.insert(b"key1", b"val1".to_vec()).unwrap();
    t1.insert(b"key2", b"val2".to_vec()).unwrap();

    let (db2, _dir2) = open_temp_db();
    let mut t2 = trie(&db2);
    t2.insert(b"key1", b"val1".to_vec()).unwrap();
    t2.insert(b"key2", b"val2".to_vec()).unwrap();

    assert_eq!(t1.root(), t2.root());
}

#[test]
fn different_insertions_produce_different_roots() {
    let (db1, _dir1) = open_temp_db();
    let mut t1 = trie(&db1);
    t1.insert(b"key1", b"val_a".to_vec()).unwrap();

    let (db2, _dir2) = open_temp_db();
    let mut t2 = trie(&db2);
    t2.insert(b"key1", b"val_b".to_vec()).unwrap();

    assert_ne!(t1.root(), t2.root());
}

// ── Persistence: with_root restores state ────────────────────────────────────

#[test]
fn with_root_restores_get_access_to_all_nodes() {
    let (db, _dir) = open_temp_db();

    let saved_root = {
        let mut t = MerklePatriciaTrie::new(&db);
        t.insert(b"key_x", b"val_x".to_vec()).unwrap();
        t.insert(b"key_y", b"val_y".to_vec()).unwrap();
        t.root().expect("root must be Some after inserts")
    };

    // Recreate trie from the saved root — same DB, same nodes in storage.
    let t2 = MerklePatriciaTrie::with_root(&db, saved_root);
    assert_eq!(t2.get(b"key_x").unwrap(), Some(b"val_x".to_vec()));
    assert_eq!(t2.get(b"key_y").unwrap(), Some(b"val_y".to_vec()));
}

#[test]
fn with_root_root_matches_saved() {
    let (db, _dir) = open_temp_db();
    let mut t = MerklePatriciaTrie::new(&db);
    t.insert(b"k", b"v".to_vec()).unwrap();
    let saved = t.root().unwrap();

    let t2 = MerklePatriciaTrie::with_root(&db, saved);
    assert_eq!(t2.root(), Some(saved));
}

// ── Large value ───────────────────────────────────────────────────────────────

#[test]
fn insert_and_get_large_value() {
    // Values in the trie are arbitrary bytes (e.g. bincode-encoded Account).
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    let large_value = vec![0xABu8; 1024]; // 1 KB
    t.insert(b"large_key", large_value.clone()).unwrap();
    assert_eq!(t.get(b"large_key").unwrap(), Some(large_value));
}
