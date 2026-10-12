//! `index.json`: a metadata cache (kind, origin, timestamps). It never holds secrets.
//!
//! The keychain is the source of truth for which items exist; listing uses the keychain's own
//! search. The index only adds metadata the keychain can't hold, and
//! [`Store::reindex`](crate::Store::reindex) rebuilds it. Writes go to a temp file that is
//! fsynced and renamed over `index.json`, always after the keychain write succeeded and while
//! `kc.lock` is held.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Result, StoreError};

const INDEX_FILE: &str = "index.json";
const INDEX_VERSION: u32 = 1;

/// What kind of value an item holds. Presentation only; values are bytes either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// A short text secret such as an API key.
    #[default]
    Text,
    /// The whole contents of a file (for example a `.env` file).
    File,
}

/// Where an item's current value came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Origin {
    /// Set on this device (`kc set`).
    Local,
    /// Copied from an existing OS keychain entry (`kc adopt`).
    Adopted {
        service: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
    },
    /// Received from another device (`kc receive` / `kc inbox`).
    Received { from_device: String },
    /// Found in the keychain without index metadata (index lost or written elsewhere).
    Unknown,
}

/// Metadata about one item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemInfo {
    pub name: String,
    pub kind: ItemKind,
    pub origin: Origin,
    /// When the item was first stored, if known.
    #[serde(default, with = "opt_rfc3339")]
    pub created_at: Option<SystemTime>,
    /// When the current value was stored, if known.
    #[serde(default, with = "opt_rfc3339")]
    pub updated_at: Option<SystemTime>,
}

/// On-disk metadata of one item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    pub kind: ItemKind,
    pub origin: Origin,
    #[serde(default, with = "opt_rfc3339")]
    pub created_at: Option<SystemTime>,
    #[serde(default, with = "opt_rfc3339")]
    pub updated_at: Option<SystemTime>,
    /// Metadata of the value kept at `item:<name>#prev`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<PrevRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PrevRecord {
    pub kind: ItemKind,
    pub origin: Origin,
    #[serde(default, with = "opt_rfc3339")]
    pub updated_at: Option<SystemTime>,
}

impl Record {
    pub(crate) fn unknown() -> Self {
        Record {
            kind: ItemKind::Text,
            origin: Origin::Unknown,
            created_at: None,
            updated_at: None,
            prev: None,
        }
    }

    pub(crate) fn info(&self, name: &str) -> ItemInfo {
        ItemInfo {
            name: name.to_owned(),
            kind: self.kind,
            origin: self.origin.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IndexFile {
    #[serde(default = "index_version")]
    pub version: u32,
    /// Namespace → item name → metadata. One config directory can serve several namespaces.
    #[serde(default)]
    pub namespaces: BTreeMap<String, BTreeMap<String, Record>>,
}

fn index_version() -> u32 {
    INDEX_VERSION
}

impl IndexFile {
    pub(crate) fn empty() -> Self {
        IndexFile {
            version: INDEX_VERSION,
            namespaces: BTreeMap::new(),
        }
    }

    pub(crate) fn items(&self, namespace: &str) -> Option<&BTreeMap<String, Record>> {
        self.namespaces.get(namespace)
    }

    pub(crate) fn record(&self, namespace: &str, name: &str) -> Option<&Record> {
        self.items(namespace)?.get(name)
    }

    pub(crate) fn items_mut(&mut self, namespace: &str) -> &mut BTreeMap<String, Record> {
        self.namespaces.entry(namespace.to_owned()).or_default()
    }

    /// Removes a record; returns whether it existed.
    pub(crate) fn remove(&mut self, namespace: &str, name: &str) -> bool {
        let Some(items) = self.namespaces.get_mut(namespace) else {
            return false;
        };
        let existed = items.remove(name).is_some();
        if items.is_empty() {
            self.namespaces.remove(namespace);
        }
        existed
    }

    /// Drops empty namespace sections.
    pub(crate) fn prune(&mut self) {
        self.namespaces.retain(|_, items| !items.is_empty());
    }
}

pub(crate) struct Index {
    path: PathBuf,
    dir: PathBuf,
}

impl Index {
    pub(crate) fn new(config_dir: &Path) -> Self {
        Index {
            path: config_dir.join(INDEX_FILE),
            dir: config_dir.to_path_buf(),
        }
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the index. A missing file is an empty index.
    pub(crate) fn load(&self) -> Result<IndexFile> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(IndexFile::empty()),
            Err(err) => return Err(StoreError::io(&self.path, err)),
        };
        let file: IndexFile =
            serde_json::from_slice(&bytes).map_err(|err| StoreError::IndexCorrupt {
                path: self.path.clone(),
                detail: format!("not valid kc index JSON ({err})"),
            })?;
        if file.version > INDEX_VERSION {
            return Err(StoreError::IndexCorrupt {
                path: self.path.clone(),
                detail: format!(
                    "written by a newer kc (index version {}, this kc understands {INDEX_VERSION})",
                    file.version
                ),
            });
        }
        Ok(file)
    }

    /// Moves a damaged index aside (`index.json.corrupt`) so it can be rebuilt.
    pub(crate) fn quarantine(&self) -> Result<()> {
        let aside = self.path.with_extension("json.corrupt");
        match fs::rename(&self.path, &aside) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(StoreError::io(&self.path, err)),
        }
    }

    /// Writes the index atomically: temp file in the same directory, fsync, rename, fsync dir.
    pub(crate) fn save(&self, file: &IndexFile) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(file).map_err(|err| StoreError::IndexCorrupt {
            path: self.path.clone(),
            detail: format!("cannot serialize the index ({err})"),
        })?;
        json.push(b'\n');
        let tmp = self.dir.join(format!(
            ".{INDEX_FILE}.{}.{}.tmp",
            std::process::id(),
            unique_suffix()
        ));
        let result = write_synced(&tmp, &json).and_then(|()| fs::rename(&tmp, &self.path));
        if let Err(err) = result {
            let _ = fs::remove_file(&tmp);
            return Err(StoreError::io(&self.path, err));
        }
        sync_dir(&self.dir).map_err(|err| StoreError::io(&self.dir, err))
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    // Windows can't open a directory as a file without extra flags; the rename itself is
    // atomic (MoveFileExW with MOVEFILE_REPLACE_EXISTING).
    Ok(())
}

fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (u64::from(nanos) << 20) ^ COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The current time, truncated to whole seconds (what the index can store).
pub(crate) fn now() -> SystemTime {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Optional RFC 3339 timestamps (`2026-10-12T01:30:00Z`).
mod opt_rfc3339 {
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(crate) fn serialize<S: Serializer>(
        time: &Option<SystemTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match time {
            // humantime panics before the epoch; clamp instead.
            Some(time) => {
                serializer.collect_str(&humantime::format_rfc3339_seconds((*time).max(UNIX_EPOCH)))
            }
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SystemTime>, D::Error> {
        let text = Option::<String>::deserialize(deserializer)?;
        text.map(|text| humantime::parse_rfc3339_weak(&text).map_err(D::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> Record {
        Record {
            kind: ItemKind::File,
            origin: Origin::Adopted {
                service: "zai-api-key".into(),
                account: Some("me".into()),
            },
            created_at: Some(UNIX_EPOCH + Duration::from_secs(1_760_000_000)),
            updated_at: Some(UNIX_EPOCH + Duration::from_secs(1_760_000_100)),
            prev: Some(PrevRecord {
                kind: ItemKind::Text,
                origin: Origin::Received {
                    from_device: "macbook".into(),
                },
                updated_at: None,
            }),
        }
    }

    #[test]
    fn roundtrips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::new(dir.path());
        assert_eq!(index.load().unwrap(), IndexFile::empty());
        let mut file = IndexFile::empty();
        file.items_mut("ns").insert("a/b".into(), sample_record());
        file.items_mut("ns")
            .insert("plain".into(), Record::unknown());
        index.save(&file).unwrap();
        assert_eq!(index.load().unwrap(), file);
        let text = fs::read_to_string(index.path()).unwrap();
        assert!(text.contains("\"2025-10-09T08:53:20Z\""), "{text}");
        assert!(text.contains("\"type\": \"adopted\""), "{text}");
        assert!(text.contains("\"type\": \"unknown\""), "{text}");
    }

    #[test]
    fn save_leaves_no_temp_files_and_replaces_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::new(dir.path());
        for i in 0..5 {
            let mut file = IndexFile::empty();
            file.items_mut("ns")
                .insert(format!("n{i}"), Record::unknown());
            index.save(&file).unwrap();
        }
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec![INDEX_FILE.to_owned()]);
        assert_eq!(index.load().unwrap().items("ns").unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn index_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let index = Index::new(dir.path());
        index.save(&IndexFile::empty()).unwrap();
        let mode = fs::metadata(index.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_and_future_files_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::new(dir.path());
        fs::write(index.path(), b"{ not json").unwrap();
        assert!(matches!(
            index.load().unwrap_err(),
            StoreError::IndexCorrupt { .. }
        ));
        fs::write(index.path(), br#"{"version": 99, "namespaces": {}}"#).unwrap();
        assert!(matches!(
            index.load().unwrap_err(),
            StoreError::IndexCorrupt { .. }
        ));
        index.quarantine().unwrap();
        assert!(!index.path().exists());
        assert!(dir.path().join("index.json.corrupt").exists());
        assert_eq!(index.load().unwrap(), IndexFile::empty());
    }

    #[test]
    fn remove_prunes_empty_namespaces() {
        let mut file = IndexFile::empty();
        file.items_mut("ns").insert("a".into(), Record::unknown());
        assert!(file.remove("ns", "a"));
        assert!(!file.remove("ns", "a"));
        assert!(file.namespaces.is_empty());
    }
}
