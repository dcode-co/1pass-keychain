//! Unit tests for the store, against the in-memory backend. All values are obviously fake.

use std::fs;
use std::path::Path;
use std::thread;

use super::*;
use crate::ErrorKind;
use crate::encoding::{
    Head, account_of, chunk_payload, encode_chunk, encode_inline, peek, sha256_hex,
};
use crate::testing::MemoryBackend;

const NS: &str = "dev.1pass.kc.unit";

/// A store with the smallest blob limit (chunks of 159 bytes), so small fake values chunk.
fn open(dir: &Path, memory: &MemoryBackend) -> Store {
    open_with(dir, memory, crate::MIN_MAX_BLOB_LEN)
}

fn open_with(dir: &Path, memory: &MemoryBackend, max_blob_len: usize) -> Store {
    let cfg = StoreConfig::new(NS, dir).with_max_blob_len(max_blob_len);
    Store::open_with_memory_backend(cfg, memory).unwrap()
}

/// Deterministic, obviously fake bytes.
fn fake(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn set(store: &Store, name: &str, value: &[u8]) -> Change {
    store
        .set(name, value, ItemKind::Text, Origin::Local)
        .unwrap()
        .change
}

fn get(store: &Store, name: &str) -> Option<Vec<u8>> {
    store.get(name).unwrap().map(|v| v.as_bytes().to_vec())
}

fn accounts(memory: &MemoryBackend) -> Vec<String> {
    memory.accounts(NS)
}

fn names(items: &[ItemInfo]) -> Vec<&str> {
    items.iter().map(|item| item.name.as_str()).collect()
}

/// The generation the manifest at `head` points at (generations are random).
fn generation_of(memory: &MemoryBackend, head: &str) -> u64 {
    let blob = memory.raw(NS, head).expect("head exists");
    peek(&blob).manifest().expect("a manifest head").generation
}

fn chunk(base: &str, generation: u64, index: u32) -> String {
    format!("{base}#{generation}.{index}")
}

/// Chunk accounts of `base` that belong to `generation`.
fn chunks_of(memory: &MemoryBackend, base: &str, generation: u64) -> usize {
    let prefix = format!("{base}#{generation}.");
    accounts(memory)
        .iter()
        .filter(|account| account.starts_with(&prefix))
        .count()
}

#[test]
fn set_then_get_through_a_separate_store_instance() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let first = open(dir.path(), &memory);
    assert_eq!(
        set(&first, "openai-api-key", b"fake-sk-123"),
        Change::Created
    );
    drop(first);
    let second = open(dir.path(), &memory);
    assert_eq!(
        get(&second, "openai-api-key").as_deref(),
        Some(&b"fake-sk-123"[..])
    );
    assert_eq!(get(&second, "missing"), None);
    let raw = memory.raw(NS, "item:openai-api-key").unwrap();
    assert_eq!(account_of(&raw).as_deref(), Some("item:openai-api-key"));
    assert!(matches!(peek(&raw), Head::Inline(b"fake-sk-123")));
    assert!(second.exists("openai-api-key").unwrap());
    assert!(!second.exists("missing").unwrap());
}

#[test]
fn large_values_are_chunked_under_a_generation_and_verified() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let value = fake(1000, 7);
    set(&store, "big", &value);

    // Several chunks of one generation, then the manifest. The exact count depends on the blob
    // limit and the account frame, so it is derived rather than hard-coded.
    let generation = generation_of(&memory, "item:big");
    let n = chunks_of(&memory, "item:big", generation);
    assert!(
        n > 1,
        "a 1000-byte value should chunk under the smallest limit"
    );
    let mut expected: Vec<String> = (0..n as u32)
        .map(|i| chunk("item:big", generation, i))
        .collect();
    expected.push("item:big".into());
    expected.sort();
    assert_eq!(accounts(&memory), expected);
    for account in accounts(&memory) {
        let blob = memory.raw(NS, &account).unwrap();
        assert!(
            blob.len() <= crate::MIN_MAX_BLOB_LEN,
            "{account} is {} bytes",
            blob.len()
        );
        assert_eq!(account_of(&blob).as_deref(), Some(account.as_str()));
        if account == "item:big" {
            assert!(matches!(peek(&blob), Head::Manifest(_)), "{account}");
        } else {
            assert!(chunk_payload(&account, &blob).is_ok(), "{account}");
        }
    }
    let head = memory.raw(NS, "item:big").unwrap();
    let manifest = peek(&head).manifest().cloned().unwrap();
    assert_eq!(manifest.generation, generation);
    assert_eq!(manifest.n as usize, n);
    assert_eq!(manifest.len, 1000);
    assert_eq!(manifest.sha256, sha256_hex(&value));

    assert_eq!(get(&open(dir.path(), &memory), "big"), Some(value));
}

#[test]
fn values_are_inline_up_to_the_blob_limit() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    // The largest value that still fits inline is the limit minus the frame (format byte, u16
    // length, the account) and the one-byte tag — sized against the longest account the head may
    // be copied to (`#prev`/`#swap`), so the inline value still fits once reframed.
    let fits = crate::MIN_MAX_BLOB_LEN - (1 + 2 + "item:fits#prev".len() + 1);
    set(&store, "fits", &fake(fits, 1));
    set(&store, "spills", &fake(fits + 1, 2));
    assert!(
        matches!(peek(&memory.raw(NS, "item:fits").unwrap()), Head::Inline(_)),
        "a value at the limit is inline"
    );
    assert!(
        peek(&memory.raw(NS, "item:spills").unwrap())
            .manifest()
            .is_some(),
        "one byte over the limit chunks"
    );
    let generation = generation_of(&memory, "item:spills");
    assert!(chunks_of(&memory, "item:spills", generation) >= 1);
    assert_eq!(get(&store, "fits"), Some(fake(fits, 1)));
    assert_eq!(get(&store, "spills"), Some(fake(fits + 1, 2)));
}

#[test]
fn the_default_blob_limit_fits_windows_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open_with(dir.path(), &memory, crate::DEFAULT_MAX_BLOB_LEN);
    set(&store, "env-file", &fake(10_000, 3));
    for account in accounts(&memory) {
        let len = memory.raw(NS, &account).unwrap().len();
        assert!(len <= 2048, "{account}: {len}");
        assert!(len <= crate::WINDOWS_MAX_BLOB_LEN);
    }
    assert_eq!(get(&store, "env-file"), Some(fake(10_000, 3)));
}

#[test]
fn overwrite_keeps_one_previous_value_and_drops_older_generations() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let (v1, v2, v3) = (fake(1000, 1), fake(350, 2), fake(10, 3));

    assert_eq!(set(&store, "k", &v1), Change::Created);
    let g1 = generation_of(&memory, "item:k");
    let g1_chunks = chunks_of(&memory, "item:k", g1);
    assert!(g1_chunks > 1, "v1 should span several chunks");
    assert_eq!(set(&store, "k", &v2), Change::Updated);
    let g2 = generation_of(&memory, "item:k");
    let g2_chunks = chunks_of(&memory, "item:k", g2);
    assert!(g2_chunks >= 1);
    assert_ne!(g1, g2);
    assert_eq!(chunks_of(&memory, "item:k", g1), g1_chunks); // v1 kept as #prev
    assert!(accounts(&memory).contains(&"item:k#prev".to_owned()));

    // Shrinking to an inline value: v2 becomes the previous value (its generation stays) and
    // v1's generation, which nothing points at any more, is deleted.
    assert_eq!(set(&store, "k", &v3), Change::Updated);
    let mut expected: Vec<String> = (0..g2_chunks as u32)
        .map(|i| chunk("item:k", g2, i))
        .collect();
    expected.extend(["item:k".to_owned(), "item:k#prev".to_owned()]);
    expected.sort();
    assert_eq!(accounts(&memory), expected);
    assert_eq!(get(&store, "k"), Some(v3));
}

#[test]
fn restore_swaps_the_current_and_previous_values() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let (v1, v2) = (fake(500, 1), fake(300, 2));
    store.set("k", &v1, ItemKind::Text, Origin::Local).unwrap();
    let g1 = generation_of(&memory, "item:k");
    let g1_chunks = chunks_of(&memory, "item:k", g1);
    assert!(g1_chunks > 1, "v1 should span several chunks");
    let received = Origin::Received {
        from_device: "macbook".into(),
    };
    store
        .set("k", &v2, ItemKind::File, received.clone())
        .unwrap();
    let g2 = generation_of(&memory, "item:k");
    let g2_chunks = chunks_of(&memory, "item:k", g2);
    assert!(g2_chunks >= 1);

    let info = store.restore("k").unwrap();
    assert_eq!(get(&store, "k"), Some(v1.clone()));
    assert_eq!((info.kind, info.origin), (ItemKind::Text, Origin::Local));

    let info = store.restore("k").unwrap();
    assert_eq!(get(&store, "k"), Some(v2.clone()));
    assert_eq!((info.kind, &info.origin), (ItemKind::File, &received));

    // Both generations were still referenced throughout; nothing was rewritten as chunks.
    assert_eq!(chunks_of(&memory, "item:k", g1), g1_chunks);
    assert_eq!(chunks_of(&memory, "item:k", g2), g2_chunks);
}

#[test]
fn restore_needs_a_readable_previous_value() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    set(&store, "k", &fake(500, 1));
    let g1 = generation_of(&memory, "item:k");
    let err = store.restore("k").unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)), "{err}");
    assert_eq!(err.exit_code(), 3);

    set(&store, "k", &fake(10, 2));
    // Damage the first chunk of the (now previous) value; every chunked value has chunk 0.
    assert!(memory.remove(NS, &chunk("item:k", g1, 0)));
    let err = store.restore("k").unwrap_err();
    assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");
    // Nothing changed.
    assert_eq!(get(&store, "k"), Some(fake(10, 2)));
}

#[test]
fn writing_the_same_value_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    set(&store, "small", b"fake-value");
    set(&store, "big", &fake(500, 5));
    let before = store.list().unwrap();
    let writes = memory.writes();

    assert_eq!(set(&store, "small", b"fake-value"), Change::Unchanged);
    let outcome = store
        .set("big", &fake(500, 5), ItemKind::File, Origin::Unknown)
        .unwrap();
    assert_eq!(outcome.change, Change::Unchanged);
    // Metadata is untouched by a no-op write.
    assert_eq!(outcome.info.kind, ItemKind::Text);
    assert_eq!(outcome.info.origin, Origin::Local);

    assert_eq!(memory.writes(), writes);
    assert!(!accounts(&memory).iter().any(|a| a.ends_with("#prev")));
    assert_eq!(store.list().unwrap(), before);
}

#[test]
fn rewriting_a_damaged_value_repairs_it() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let value = fake(1000, 5);
    set(&store, "big", &value);
    let damaged = chunk("item:big", generation_of(&memory, "item:big"), 0);
    let mut blob = memory.raw(NS, &damaged).unwrap().to_vec();
    // The last byte is always in the chunk's payload (the frame and tag come first).
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    memory.insert(NS, &damaged, &blob);
    assert!(matches!(
        store.get("big").unwrap_err(),
        StoreError::Corrupt { .. }
    ));

    // Same bytes as before, but the stored copy is damaged, so this is a real write.
    assert_eq!(set(&store, "big", &value), Change::Updated);
    assert_eq!(get(&store, "big"), Some(value));
}

#[test]
fn damaged_values_are_reported_not_returned() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let value = fake(1000, 9);
    let check = |label: &str| {
        let err = store.get("big").unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }), "{label}: {err}");
        assert_eq!(err.kind(), ErrorKind::Other, "{label}");
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("fake"), "{label}: {shown}");
    };

    set(&store, "big", &value);
    let damaged = chunk("item:big", generation_of(&memory, "item:big"), 1);
    let mut blob = memory.raw(NS, &damaged).unwrap().to_vec();
    // The last byte is always in the chunk's payload.
    let last = blob.len() - 1;
    blob[last] ^= 1;
    memory.insert(NS, &damaged, &blob);
    check("flipped bit");

    set(&store, "big", &fake(1000, 10));
    let missing = chunk("item:big", generation_of(&memory, "item:big"), 0);
    assert!(memory.remove(NS, &missing));
    check("missing chunk");

    memory.insert(NS, "item:big", &[0x7f, 1, 2, 3]);
    check("unknown tag");

    memory.insert(NS, "item:big", b"\x02{\"gen\":1}");
    check("bad manifest");

    set(&store, "big", &fake(1000, 11));
    let wrong = chunk("item:big", generation_of(&memory, "item:big"), 0);
    memory.insert(NS, &wrong, &encode_inline(&wrong, b"not a chunk"));
    check("wrong chunk tag");
}

#[test]
fn an_interrupted_write_leaves_the_old_value_readable() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let v1 = fake(500, 1);
    set(&store, "k", &v1);
    let g1 = generation_of(&memory, "item:k");
    let v1_chunks = chunks_of(&memory, "item:k", g1);
    assert!(v1_chunks >= 1);
    let info = store.info("k").unwrap().unwrap();

    // Five chunks of a new, larger generation get written, then the sixth write fails.
    memory.fail_writes_after(5);
    let err = store
        .set("k", &fake(4000, 2), ItemKind::Text, Origin::Local)
        .unwrap_err();
    assert!(matches!(err, StoreError::Backend { .. }), "{err}");
    memory.allow_writes();

    // The manifest still points at v1's generation, and the index didn't move.
    assert_eq!(get(&store, "k"), Some(v1.clone()));
    assert_eq!(store.info("k").unwrap().unwrap(), info);
    assert_eq!(accounts(&memory).len(), 1 + v1_chunks + 5);

    // A retry writes yet another generation; reindex clears the failed attempt's five chunks.
    let v2 = fake(600, 3); // large enough to chunk under the smallest blob limit
    assert_eq!(set(&store, "k", &v2), Change::Updated);
    let g2 = generation_of(&memory, "item:k");
    let v2_chunks = chunks_of(&memory, "item:k", g2);
    assert_eq!(store.reindex().unwrap().orphans_removed, 5);
    let mut expected: Vec<String> = (0..v1_chunks as u32)
        .map(|i| chunk("item:k", g1, i))
        .collect();
    expected.extend((0..v2_chunks as u32).map(|i| chunk("item:k", g2, i)));
    expected.extend(["item:k".to_owned(), "item:k#prev".to_owned()]);
    expected.sort();
    assert_eq!(accounts(&memory), expected);
    assert_eq!(get(&store, "k"), Some(v2));
}

#[test]
fn the_index_changes_only_after_the_keychain_write() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    memory.fail_writes_after(0);
    let err = store
        .set("k", b"fake", ItemKind::Text, Origin::Local)
        .unwrap_err();
    assert!(matches!(err, StoreError::Backend { .. }), "{err}");
    assert_eq!(store.info("k").unwrap(), None);
    assert!(!dir.path().join("index.json").exists());

    memory.allow_writes();
    let outcome = store
        .set("k", b"fake", ItemKind::Text, Origin::Local)
        .unwrap();
    assert_eq!(outcome.change, Change::Created);
    assert_eq!(outcome.info.created_at, outcome.info.updated_at);
    assert!(outcome.info.created_at.is_some());
    assert_eq!(store.info("k").unwrap(), Some(outcome.info));
}

#[test]
fn updates_keep_the_creation_time() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let created = store
        .set("k", b"fake-1", ItemKind::Text, Origin::Local)
        .unwrap()
        .info;
    let updated = store
        .set("k", b"fake-2", ItemKind::Text, Origin::Local)
        .unwrap()
        .info;
    assert_eq!(updated.created_at, created.created_at);
    assert!(updated.updated_at >= created.updated_at);
}

#[test]
fn delete_removes_value_previous_value_and_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    set(&store, "k", &fake(500, 1));
    set(&store, "k", &fake(400, 2)); // k now has a current value, a #prev and two generations
    // Neighbours that share a prefix must survive.
    for name in ["k2", "k/x", "kk"] {
        set(&store, name, b"fake-neighbour");
    }

    assert!(store.delete("k").unwrap());
    // k's value, its previous value and every live chunk of both are gone; neighbours survive.
    // (A chunk of a generation no head points at — debris of an interrupted write — isn't
    // enumerated on delete; reindex removes it, see verify_reports_drift_and_reindex_repairs_it.)
    assert_eq!(accounts(&memory), ["item:k/x", "item:k2", "item:kk"]);
    assert_eq!(store.info("k").unwrap(), None);
    assert_eq!(get(&store, "k"), None);
    assert!(!store.delete("k").unwrap());
}

#[test]
fn list_is_driven_by_the_index_and_checks_existence() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    set(&store, "a", b"fake-a");
    store
        .set(
            "b/c",
            b"fake-bc",
            ItemKind::File,
            Origin::Received {
                from_device: "mac-mini".into(),
            },
        )
        .unwrap();
    set(&store, "big", &fake(300, 1));
    set(&store, "big", &fake(301, 1)); // has #prev and two generations
    store.set_internal("device-key", b"fake-key").unwrap();
    // Written outside kc (not in the index): not listed until reindex picks it up.
    memory.insert(
        NS,
        "item:written-elsewhere",
        &encode_inline("item:written-elsewhere", b"fake"),
    );
    memory.insert(NS, "unrelated-account", b"fake");

    let items = store.list().unwrap();
    assert_eq!(names(&items), ["a", "b/c", "big"]);
    assert_eq!(items[1].kind, ItemKind::File);
    assert_eq!(
        items[1].origin,
        Origin::Received {
            from_device: "mac-mini".into()
        }
    );
    // Internal slots are never listed.
    assert!(!names(&items).contains(&"device-key"));

    // An indexed item deleted behind kc's back drops out of the list (existence is checked).
    assert!(memory.remove(NS, "item:a"));
    assert_eq!(names(&store.list().unwrap()), ["b/c", "big"]);

    // Without the index, nothing is listed until reindex rebuilds it from the keychain.
    fs::remove_file(dir.path().join("index.json")).unwrap();
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn verify_reports_drift_and_reindex_repairs_it() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    set(&store, "kept", b"fake-kept");
    set(&store, "gone", b"fake-gone");
    set(&store, "big", &fake(300, 1));
    // Changes behind kc's back.
    memory.remove(NS, "item:gone");
    memory.insert(NS, "item:new", &encode_inline("item:new", b"fake-new"));
    // Orphans: a chunk of a generation nothing points at, and a #prev whose item is gone.
    // (Generation 0 is never used.)
    memory.insert(NS, "item:big#0.0", &encode_chunk("item:big#0.0", b"orphan"));
    memory.insert(
        NS,
        "item:ghost#prev",
        &encode_inline("item:ghost#prev", b"orphan"),
    );
    memory.insert(
        NS,
        "item:ghost#3.0",
        &encode_chunk("item:ghost#3.0", b"orphan"),
    );

    let drift = store.verify().unwrap();
    assert_eq!(names(&drift.stale), ["gone"]);
    assert_eq!(drift.unindexed, ["new"]);
    assert!(!drift.is_clean());

    let report = store.reindex().unwrap();
    assert_eq!(report.added, ["new"]);
    assert_eq!(report.removed, ["gone"]);
    assert_eq!(report.orphans_removed, 3);
    assert!(!report.replaced_corrupt_index);

    assert!(store.verify().unwrap().is_clean());
    let all = accounts(&memory);
    assert!(
        !all.iter()
            .any(|a| a.contains("ghost") || a == "item:big#0.0")
    );
    assert_eq!(get(&store, "big"), Some(fake(300, 1)));
    assert_eq!(store.info("kept").unwrap().unwrap().origin, Origin::Local);
    assert_eq!(store.info("new").unwrap().unwrap().origin, Origin::Unknown);
}

#[test]
fn reindex_leaves_chunks_of_unreadable_heads_alone() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    // A head in a format this kc doesn't know (a newer kc?) with chunks it can't interpret.
    memory.insert(NS, "item:future", &[0x09, 1, 2, 3]);
    memory.insert(
        NS,
        "item:future#5.0",
        &encode_chunk("item:future#5.0", b"future"),
    );
    let report = store.reindex().unwrap();
    assert_eq!(report.orphans_removed, 0);
    assert!(memory.raw(NS, "item:future#5.0").is_some());
}

#[test]
fn a_damaged_index_blocks_writes_until_reindex() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    set(&store, "a", b"fake-a");
    fs::write(dir.path().join("index.json"), b"{ broken").unwrap();

    let err = store
        .set("b", b"fake-b", ItemKind::Text, Origin::Local)
        .unwrap_err();
    assert!(matches!(err, StoreError::IndexCorrupt { .. }), "{err}");
    assert!(err.to_string().contains("kc reindex"));
    assert_eq!(err.exit_code(), 1);
    assert!(!accounts(&memory).contains(&"item:b".to_owned()));

    let report = store.reindex().unwrap();
    assert!(report.replaced_corrupt_index);
    assert_eq!(report.added, ["a"]);
    assert!(dir.path().join("index.json.corrupt").exists());
    assert_eq!(set(&store, "b", b"fake-b"), Change::Created);
}

#[test]
fn internal_slots_are_separate_unlisted_and_keep_no_previous_value() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    assert_eq!(
        store.set_internal("device-key", &fake(32, 9)).unwrap(),
        Change::Created
    );
    set(&store, "device-key", b"fake-user-item-with-the-same-name");
    store.set_internal("inbox-token", &fake(300, 4)).unwrap();
    let g1 = generation_of(&memory, "sys:inbox-token");
    assert_eq!(chunks_of(&memory, "sys:inbox-token", g1), 2);

    let other = open(dir.path(), &memory);
    assert_eq!(
        other
            .get_internal("device-key")
            .unwrap()
            .unwrap()
            .as_bytes(),
        fake(32, 9)
    );
    assert_eq!(names(&other.list().unwrap()), ["device-key"]);
    assert_eq!(
        get(&other, "device-key").as_deref(),
        Some(&b"fake-user-item-with-the-same-name"[..])
    );

    // Overwriting an internal value drops the old generation at once.
    assert_eq!(
        store.set_internal("inbox-token", &fake(200, 5)).unwrap(),
        Change::Updated
    );
    let all = accounts(&memory);
    assert_eq!(chunks_of(&memory, "sys:inbox-token", g1), 0);
    assert!(
        !all.iter()
            .any(|a| a.starts_with("sys:") && a.ends_with("#prev"))
    );
    assert_eq!(
        store.set_internal("inbox-token", &fake(200, 5)).unwrap(),
        Change::Unchanged
    );

    assert!(store.delete_internal("inbox-token").unwrap());
    assert!(store.get_internal("inbox-token").unwrap().is_none());
    assert!(!accounts(&memory).iter().any(|a| a.contains("inbox-token")));
    assert!(!store.delete_internal("inbox-token").unwrap());
    assert!(matches!(
        store.set_internal("bad key", b"x").unwrap_err(),
        StoreError::InvalidName { .. }
    ));
}

#[test]
fn adopt_copies_a_foreign_entry() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    memory.insert("zai-api-key", "me", b"fake-zai-key");

    let outcome = store.adopt("zai-api-key", Some("me"), "zai").unwrap();
    assert_eq!(outcome.change, Change::Created);
    assert_eq!(outcome.info.kind, ItemKind::Text);
    assert_eq!(
        outcome.info.origin,
        Origin::Adopted {
            service: "zai-api-key".into(),
            account: Some("me".into()),
        }
    );
    assert_eq!(get(&store, "zai").as_deref(), Some(&b"fake-zai-key"[..]));
    assert!(
        memory.raw("zai-api-key", "me").is_some(),
        "the original stays"
    );

    // Without an account the single entry is used.
    store.adopt("zai-api-key", None, "zai-2").unwrap();
    memory.insert("zai-api-key", "you", b"fake-other");
    let err = store.adopt("zai-api-key", None, "zai-3").unwrap_err();
    assert!(matches!(err, StoreError::Ambiguous { .. }), "{err}");
    assert_eq!(err.exit_code(), 2);
    let message = err.to_string();
    assert!(
        message.contains("account=me") && message.contains("account=you"),
        "{message}"
    );

    let err = store.adopt("no-such-service", None, "x").unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)), "{err}");
    assert_eq!(err.exit_code(), 3);

    memory.insert("binary-thing", "a", &[0xff, 0x00, 0xfe]);
    let outcome = store.adopt("binary-thing", Some("a"), "bin").unwrap();
    assert_eq!(outcome.info.kind, ItemKind::File);

    assert!(matches!(
        store.adopt("", None, "x").unwrap_err(),
        StoreError::InvalidName { .. }
    ));
    assert!(matches!(
        store
            .adopt("zai-api-key", Some("me"), "bad name")
            .unwrap_err(),
        StoreError::InvalidName { .. }
    ));
}

#[test]
fn rejects_bad_names_and_values_before_touching_the_keychain() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    for (result, what) in [
        (
            store
                .set("bad name", b"x", ItemKind::Text, Origin::Local)
                .map(|_| ()),
            "space",
        ),
        (store.get("a/../b").map(|_| ()), "dot-dot"),
        (store.delete("/abs").map(|_| ()), "leading slash"),
        (store.restore("trailing/").map(|_| ()), "trailing slash"),
    ] {
        let err = result.unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidName { .. }),
            "{what}: {err}"
        );
        assert_eq!(err.exit_code(), 2);
    }
    let empty = store
        .set("k", b"", ItemKind::Text, Origin::Local)
        .unwrap_err();
    assert!(matches!(empty, StoreError::InvalidValue(_)), "{empty}");
    let huge = store
        .set(
            "k",
            &vec![0u8; MAX_VALUE_LEN + 1],
            ItemKind::File,
            Origin::Local,
        )
        .unwrap_err();
    assert!(matches!(huge, StoreError::InvalidValue(_)), "{huge}");
    assert_eq!(memory.writes(), 0);
}

#[test]
fn the_largest_value_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open_with(dir.path(), &memory, crate::DEFAULT_MAX_BLOB_LEN);
    let value = fake(MAX_VALUE_LEN, 1);
    set(&store, "max", &value);
    assert_eq!(get(&store, "max"), Some(value));
}

#[test]
fn concurrent_writers_from_separate_store_instances_lose_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let threads: Vec<_> = (0..8u8)
        .map(|t| {
            let dir = dir.path().to_path_buf();
            let memory = memory.clone();
            thread::spawn(move || {
                let store = open(&dir, &memory);
                for i in 0..10u8 {
                    set(
                        &store,
                        &format!("t{t}/i{i}"),
                        &fake(300 + usize::from(i), t),
                    );
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let store = open(dir.path(), &memory);
    let items = store.list().unwrap();
    assert_eq!(items.len(), 80);
    assert!(items.iter().all(|item| item.origin == Origin::Local));
    assert!(store.verify().unwrap().is_clean());
    for t in 0..8u8 {
        for i in 0..10u8 {
            assert_eq!(
                get(&store, &format!("t{t}/i{i}")),
                Some(fake(300 + usize::from(i), t))
            );
        }
    }
}

#[test]
fn namespaces_share_a_config_dir_without_mixing() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let a = Store::open_with_memory_backend(
        StoreConfig::new("dev.1pass.kc.unit-a", dir.path()),
        &memory,
    )
    .unwrap();
    let b = Store::open_with_memory_backend(
        StoreConfig::new("dev.1pass.kc.unit-b", dir.path()),
        &memory,
    )
    .unwrap();
    set(&a, "x", b"fake-x");
    set(&b, "y", b"fake-y");
    assert_eq!(names(&a.list().unwrap()), ["x"]);
    assert_eq!(names(&b.list().unwrap()), ["y"]);
    assert_eq!(get(&a, "y"), None);
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("index.json")).unwrap()).unwrap();
    assert!(index["namespaces"]["dev.1pass.kc.unit-a"]["x"].is_object());
    assert!(index["namespaces"]["dev.1pass.kc.unit-b"]["y"].is_object());
}

#[test]
fn purge_clears_a_test_namespace_and_refuses_the_default_one() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let real = Store::open_with_memory_backend(
        StoreConfig::new(crate::DEFAULT_NAMESPACE, dir.path()),
        &memory,
    )
    .unwrap();
    set(&real, "keep-me", b"fake");
    assert!(matches!(
        real.purge_namespace().unwrap_err(),
        StoreError::InvalidConfig(_)
    ));

    let store = open(dir.path(), &memory);
    set(&store, "a", &fake(300, 1));
    set(&store, "a", &fake(10, 2));
    store.set_internal("device-key", b"fake").unwrap();
    assert!(store.purge_namespace().unwrap() > 3);
    assert!(accounts(&memory).is_empty());
    assert!(store.list().unwrap().is_empty());
    assert_eq!(names(&real.list().unwrap()), ["keep-me"]);
}

#[test]
fn store_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Store>();
}

#[test]
fn a_write_interrupted_after_the_prev_copy_keeps_the_previous_value() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let (v1, v2, v3) = (fake(500, 1), fake(10, 2), fake(20, 3));
    set(&store, "k", &v1); // generation 1

    // v2 is inline: the write copies v1 to #prev (1 write) and then fails on the head.
    memory.fail_writes_after(1);
    assert!(store.set("k", &v2, ItemKind::Text, Origin::Local).is_err());
    memory.allow_writes();
    // Both heads now point at generation 1.
    assert_eq!(get(&store, "k"), Some(v1.clone()));

    // The retry must not treat generation 1 as garbage: #prev still needs it.
    assert_eq!(set(&store, "k", &v3), Change::Updated);
    store.restore("k").unwrap();
    assert_eq!(get(&store, "k"), Some(v1));
}

#[test]
fn an_interrupted_restore_loses_nothing() {
    // Restore writes #swap, then the head, then #prev. Cut it after each step, for an inline
    // and for a chunked current value.
    for current_len in [10, 500] {
        for writes_before_failure in [0, 1, 2] {
            let dir = tempfile::tempdir().unwrap();
            let memory = MemoryBackend::new();
            let store = open(dir.path(), &memory);
            let previous = fake(400, 1);
            let current = fake(current_len, 2);
            set(&store, "k", &previous);
            set(&store, "k", &current);

            memory.fail_writes_after(writes_before_failure);
            assert!(store.restore("k").is_err());
            memory.allow_writes();

            // Whatever happened, a reindex (or any later write) settles the item, and both
            // values are still there: one current, one previous.
            store.reindex().unwrap();
            assert!(!accounts(&memory).iter().any(|a| a.ends_with("#swap")));
            let now = get(&store, "k").unwrap();
            store.restore("k").unwrap();
            let other = get(&store, "k").unwrap();
            let mut seen = [now, other];
            seen.sort();
            let mut expected = [previous.clone(), current.clone()];
            expected.sort();
            assert_eq!(
                seen, expected,
                "current {current_len} bytes, failure after {writes_before_failure} writes"
            );
        }
    }
}

#[test]
fn a_set_finishes_an_interrupted_restore_first() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let (previous, current, next) = (fake(300, 1), fake(200, 2), fake(30, 3));
    set(&store, "k", &previous);
    set(&store, "k", &current);
    // The head now holds `previous`, but `current` only lives in #swap.
    memory.fail_writes_after(2);
    assert!(store.restore("k").is_err());
    memory.allow_writes();
    assert_eq!(get(&store, "k"), Some(previous.clone()));

    // The next write completes the restore before replacing the value, so `previous`
    // becomes #prev and `current` (from #swap) is not silently dropped before that.
    assert_eq!(set(&store, "k", &next), Change::Updated);
    assert!(!accounts(&memory).iter().any(|a| a.ends_with("#swap")));
    store.restore("k").unwrap();
    assert_eq!(get(&store, "k"), Some(previous));
}

#[test]
fn an_empty_swap_left_by_a_cut_off_creation_is_not_a_value() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let (previous, current) = (fake(300, 1), fake(20, 2));
    set(&store, "k", &previous);
    set(&store, "k", &current);
    // The Secret Service creates an item empty and fills it in a second call; a restore cut
    // off in between leaves an empty #swap. It must not replace #prev.
    memory.insert(NS, "item:k#swap", b"");
    let report = store.reindex().unwrap();
    assert!(report.orphans_removed >= 1);
    assert!(memory.raw(NS, "item:k#swap").is_none());
    assert_eq!(get(&store, "k"), Some(current));
    store.restore("k").unwrap();
    assert_eq!(get(&store, "k"), Some(previous));

    // The same through a write instead of reindex.
    memory.insert(NS, "item:k#swap", b"");
    set(&store, "k", &fake(30, 3));
    assert!(memory.raw(NS, "item:k#swap").is_none());
}

#[test]
fn an_empty_head_is_an_unfinished_creation() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    // A creation cut off after the chunks and an empty head.
    memory.insert(
        NS,
        "item:new#1.0",
        &encode_chunk("item:new#1.0", b"fake-part"),
    );
    memory.insert(NS, "item:new", b"");
    assert_eq!(get(&store, "new"), None);
    let report = store.reindex().unwrap();
    assert_eq!(report.orphans_removed, 2);
    assert!(accounts(&memory).is_empty());
    // A later write simply creates the item.
    assert_eq!(set(&store, "new", b"fake-value"), Change::Created);
    assert_eq!(get(&store, "new").as_deref(), Some(&b"fake-value"[..]));
}

#[test]
fn reindex_keeps_chunks_either_head_needs() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let value = fake(600, 1);
    set(&store, "k", &value);
    let generation = generation_of(&memory, "item:k");
    let n = chunks_of(&memory, "item:k", generation);
    assert!(n >= 2, "the value should span several chunks");
    // An interrupted write left #prev pointing at the same generation, and this copy claims
    // fewer chunks (damaged but well-formed).
    let short = crate::encoding::Manifest {
        generation,
        n: (n - 1) as u32,
        len: 100,
        sha256: "0".repeat(64),
    };
    memory.insert(
        NS,
        "item:k#prev",
        &crate::encoding::encode_manifest("item:k#prev", &short),
    );
    store.reindex().unwrap();
    // The chunks the real head needs survive (the max of the two heads' counts).
    assert_eq!(chunks_of(&memory, "item:k", generation), n);
    assert_eq!(get(&store, "k"), Some(value));
}

#[test]
fn reindex_removes_stray_chunks_inside_a_live_generation() {
    let dir = tempfile::tempdir().unwrap();
    let memory = MemoryBackend::new();
    let store = open(dir.path(), &memory);
    let value = fake(300, 1); // generation 1, chunks 0 and 1
    set(&store, "k", &value);
    // A sparse tail an interrupted cleanup could leave: .3 without .2.
    let stray = chunk("item:k", generation_of(&memory, "item:k"), 3);
    memory.insert(NS, &stray, &encode_chunk(&stray, b"stray"));
    let report = store.reindex().unwrap();
    assert_eq!(report.orphans_removed, 1);
    assert!(memory.raw(NS, &stray).is_none());
    assert_eq!(get(&store, "k"), Some(value));
}

/// A backend that, like the Secret Service, recovers each entry's account from the stored blob,
/// so a head in a format kc can't frame-decode is absent from `accounts()`. The in-memory
/// backend enumerates native account names and so can't exercise this path.
struct FrameAwareBackend {
    entries: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl Backend for FrameAwareBackend {
    fn describe(&self) -> String {
        "frame-aware test backend".into()
    }
    fn may_leave_empty_entries(&self) -> bool {
        true
    }
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(account)
            .map(|blob| Zeroizing::new(blob.clone())))
    }
    fn set(&self, account: &str, blob: &[u8]) -> Result<()> {
        self.entries
            .lock()
            .unwrap()
            .insert(account.to_owned(), blob.to_vec());
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<bool> {
        Ok(self.entries.lock().unwrap().remove(account).is_some())
    }
    fn exists(&self, account: &str) -> Result<bool> {
        Ok(self.entries.lock().unwrap().contains_key(account))
    }
    fn accounts(&self) -> Result<Vec<String>> {
        // The account comes from the blob frame, so an unframed head is absent (like Linux).
        Ok(self
            .entries
            .lock()
            .unwrap()
            .values()
            .filter_map(|blob| account_of(blob))
            .collect())
    }
    fn purge(&self) -> Result<usize> {
        let mut entries = self.entries.lock().unwrap();
        let removed = entries.len();
        entries.clear();
        Ok(removed)
    }
    fn read_foreign(
        &self,
        _service: &str,
        _account: Option<&str>,
    ) -> Result<crate::backend::ForeignItem> {
        unreachable!("read_foreign is not exercised by this test")
    }
}

#[test]
fn reindex_keeps_an_unreadable_head_and_its_companions() {
    // The Secret Service recovers accounts from the blob, so a head another program wrote (not in
    // kc's framed format) is absent from accounts(). reindex must not then delete that head's
    // previous value and chunks as if the head were gone.
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FrameAwareBackend {
        entries: Mutex::new(BTreeMap::new()),
    });
    backend
        .set("item:k", &encode_inline("item:k", b"fake-current"))
        .unwrap();
    backend
        .set(
            "item:k#prev",
            &encode_inline("item:k#prev", b"fake-previous"),
        )
        .unwrap();
    backend
        .set("item:k#7.0", &encode_chunk("item:k#7.0", b"fake-chunk"))
        .unwrap();
    // Another program clobbers the head with its own, unframed value.
    backend.set("item:k", b"foreign-unframed-value").unwrap();
    assert!(
        !backend.accounts().unwrap().contains(&"item:k".to_owned()),
        "the unframed head is absent from accounts()"
    );

    let store = Store::with_backend(StoreConfig::new(NS, dir.path()), backend.clone()).unwrap();
    let report = store.reindex().unwrap();
    assert_eq!(report.orphans_removed, 0, "nothing of k should be deleted");
    assert!(backend.exists("item:k").unwrap());
    assert!(
        backend.exists("item:k#prev").unwrap(),
        "previous value kept"
    );
    assert!(backend.exists("item:k#7.0").unwrap(), "chunk kept");
}
