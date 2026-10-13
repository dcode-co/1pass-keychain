//! Device state next to `config.toml`: remembered devices (`peers.json`), the inbox replay
//! set (`seen.json`), and `state.lock`, which serialises changes to them between kc
//! processes. None of these files holds a secret; writer tokens and keys live in the OS
//! keychain (see `commands::pairing`).

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kc_proto::inbox::MessageId;
use kc_proto::payload::InboxId;
use kc_proto::{DevicePublicKey, Fingerprint, ItemResult, Label};
use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};
use crate::i18n::tr;

pub const PEERS_FILE: &str = "peers.json";
pub const SEEN_FILE: &str = "seen.json";
pub const LOCK_FILE: &str = "state.lock";
pub const ITEMS_LOCK_PREFIX: &str = "items-";
pub const PAIRING_LOCK_FILE: &str = "pairing.lock";
const LOCK_WAIT: Duration = Duration::from_secs(15);
const LOCK_POLL: Duration = Duration::from_millis(25);
const FORMAT_VERSION: u32 = 1;

/// A device this one is paired with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    /// Chosen on this device (from the peer's suggestion), unique here.
    pub label: Label,
    /// `SHA-256(device_pk)`.
    pub fingerprint: Fingerprint,
    pub device_pk: DevicePublicKey,
    /// The peer's inbox, where `kc send --to` posts.
    pub inbox_id: InboxId,
    /// The writer registration this device made on its own inbox for the peer, so
    /// `kc peers rm` can revoke it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_id: Option<String>,
    /// The keychain internal slot holding the token for posting to the peer's inbox. Each
    /// pairing writes a new slot and then switches to it here, so the token and this entry
    /// always change together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_key: Option<String>,
    /// Unix seconds.
    pub paired_at: i64,
}

impl Peer {
    /// The keychain slot of the token for posting to this peer.
    pub fn token_key(&self) -> String {
        self.token_key
            .clone()
            .unwrap_or_else(|| format!("{WRITER_KEY_PREFIX}{}", self.fingerprint.to_hex()))
    }
}

/// Keychain slots holding writer tokens for peers start with this.
pub const WRITER_KEY_PREFIX: &str = "writer/";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peers {
    #[serde(default = "format_version")]
    pub v: u32,
    #[serde(default)]
    pub peers: Vec<Peer>,
    /// Writer registrations on this device's inbox that no peer entry accounts for: those
    /// of a pairing still under way (recorded before the relay is asked), and replaced or
    /// unrevoked ones. A pairing that was interrupted (Ctrl-C, a crash) leaves its entry
    /// here, and a later pairing revokes it, so the inbox's 16 writer slots don't leak.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_writers: Vec<PendingWriter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWriter {
    /// The relay's id for the registration, once known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_id: Option<String>,
    /// What registering sent (`writer_token_sha256`). Registering the same hash again gives
    /// back the same id, so a registration whose answer was lost can still be found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_sha256: Option<String>,
    /// Unix seconds.
    pub since: i64,
    /// Marked under `state.lock` before it is revoked as stale: a pairing still holding it
    /// can no longer be committed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revoking: bool,
    /// The peer a retired registration belonged to, so `kc peers rm` revokes it too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<Fingerprint>,
}

fn format_version() -> u32 {
    FORMAT_VERSION
}

impl Peers {
    /// Labels are matched without regard to ASCII case, and unique that way too.
    pub fn find(&self, label: &str) -> Option<&Peer> {
        self.peers
            .iter()
            .find(|p| p.label.as_str().eq_ignore_ascii_case(label))
    }

    pub fn position(&self, label: &str) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.label.as_str().eq_ignore_ascii_case(label))
    }

    pub fn by_fingerprint(&self, fp: &Fingerprint) -> Option<&Peer> {
        self.peers.iter().find(|p| p.fingerprint == *fp)
    }

    pub fn label_taken(&self, label: &str) -> bool {
        self.find(label).is_some()
    }

    fn validate(&self) -> std::result::Result<(), String> {
        let mut labels = Vec::new();
        for p in &self.peers {
            if p.device_pk.fingerprint() != p.fingerprint {
                return Err(tr!(
                    "{label}: the fingerprint doesn't match the key",
                    label = p.label
                ));
            }
            if p.writer_id.as_deref().is_some_and(|w| !is_url_token(w)) {
                return Err(tr!("{label}: invalid writer id", label = p.label));
            }
            let valid_key = |k: &str| {
                k.strip_prefix(WRITER_KEY_PREFIX).is_some_and(|rest| {
                    rest.split('/').all(is_url_token) && rest.split('/').count() <= 2
                })
            };
            if p.token_key.as_deref().is_some_and(|k| !valid_key(k)) {
                return Err(tr!("{label}: invalid token slot", label = p.label));
            }
            let lower = p.label.as_str().to_ascii_lowercase();
            if labels.contains(&lower) {
                return Err(tr!("the label {label} appears twice", label = p.label));
            }
            labels.push(lower);
        }
        let valid = |w: &PendingWriter| {
            (w.writer_id.is_some() || w.token_sha256.is_some())
                && w.writer_id.as_deref().is_none_or(is_url_token)
                && w.token_sha256.as_deref().is_none_or(is_url_token)
        };
        if !self.pending_writers.iter().all(valid) {
            return Err(tr!("invalid pending writer entry"));
        }
        Ok(())
    }
}

/// Inbox messages already imported, by end-to-end message id, kept until they would have
/// expired anyway (PROTOCOL §4), plus a journal of messages being imported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    #[serde(default = "format_version")]
    pub v: u32,
    /// Message id (hex) → keep until (Unix seconds). A message listed here is a replay.
    #[serde(default)]
    pub seen: BTreeMap<String, i64>,
    /// Messages whose import started but didn't finish (a crash, or a keychain failure),
    /// with the items already settled. The next `kc inbox` skips those items, so a retry
    /// never applies an item twice.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pending: BTreeMap<String, Pending>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// Keep until (Unix seconds).
    pub until: i64,
    /// Items already settled, with what happened to them.
    #[serde(default)]
    pub done: Vec<ItemResult>,
    /// The item being written when the record was saved: if a run stops there, whether
    /// the write happened is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writing: Option<String>,
}

impl Seen {
    pub fn contains(&self, id: &MessageId) -> bool {
        self.seen.contains_key(&id.to_hex())
    }

    /// Marks the import of `id` finished.
    pub fn insert(&mut self, id: &MessageId, keep_until: i64) {
        let key = id.to_hex();
        self.pending.remove(&key);
        let entry = self.seen.entry(key).or_insert(keep_until);
        *entry = (*entry).max(keep_until);
    }

    /// The journal entry of a message being imported, created if needed.
    pub fn pending(&mut self, id: &MessageId, keep_until: i64) -> &mut Pending {
        let entry = self.pending.entry(id.to_hex()).or_default();
        entry.until = entry.until.max(keep_until);
        entry
    }

    pub fn prune(&mut self, now: i64) {
        self.seen.retain(|_, until| *until >= now);
        self.pending.retain(|_, p| p.until >= now);
    }
}

/// Holds a lock file (`state.lock` or `items.lock`). Dropping it closes the file, which
/// releases the lock.
#[derive(Debug)]
pub struct StateLock {
    _held: fd_lock::RwLock<File>,
}

/// The config directory, seen as the home of kc-cli's own files.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    pub fn new(root: impl Into<PathBuf>) -> StateDir {
        StateDir { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Takes `state.lock` exclusively (pairing state, inbox processing, config changes),
    /// waiting up to 15 s for another kc process. Don't take it twice in one process: a
    /// second handle blocks too.
    pub fn lock(&self) -> Result<StateLock> {
        self.lock_file(LOCK_FILE, || {
            tr!("another kc process is changing this device's pairing state; try again")
        })
    }

    /// `state.lock` if it is free right now. For housekeeping that can wait.
    pub fn try_lock(&self) -> Option<StateLock> {
        self.try_lock_file(LOCK_FILE)
    }

    /// `pairing.lock`, held for a whole pairing, if no other pairing on this device holds
    /// it: two pairings at once between the same devices could each keep credentials the
    /// other one revoked.
    pub fn try_lock_pairing(&self) -> Option<StateLock> {
        self.try_lock_file(PAIRING_LOCK_FILE)
    }

    fn try_lock_file(&self, name: &str) -> Option<StateLock> {
        let mut lock = fd_lock::RwLock::new(self.open_lock(name).ok()?);
        // The guard is forgotten: the lock lasts until the file is closed.
        lock.try_write().map(std::mem::forget).ok()?;
        Some(StateLock { _held: lock })
    }

    /// Takes `items-<namespace>.lock` exclusively around one item's check and write, so a
    /// conflict check and the write it decides on can't interleave with another kc process
    /// writing to the same keychain namespace. The keychain is shared by every config
    /// directory of the user, so the lock file lives in a per-user directory (the runtime
    /// or cache directory), not in the config directory. Taken before `state.lock` when
    /// both are needed; seen.json is written after sync state.
    pub fn lock_items(&self, namespace: &str) -> Result<StateLock> {
        let file = format!("{ITEMS_LOCK_PREFIX}{namespace}.lock");
        let busy = || tr!("another kc process is writing items; try again");
        match user_lock_dir() {
            Some(dir) => StateDir::new(dir).lock_file(&file, busy),
            None => self.lock_file(&file, busy),
        }
    }

    #[cfg(test)]
    fn open_lock_at_user_dir(&self, namespace: &str) -> Result<File> {
        let file = format!("{ITEMS_LOCK_PREFIX}{namespace}.lock");
        match user_lock_dir() {
            Some(dir) => StateDir::new(dir).open_lock(&file),
            None => self.open_lock(&file),
        }
    }

    fn open_lock(&self, name: &str) -> Result<File> {
        create_private_dir(&self.root)?;
        let path = self.root.join(name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path).map_err(|e| {
            CliError::failure(tr!("can't open {path}: {e}", path = path.display(), e = e))
        })
    }

    fn lock_file(&self, name: &str, busy: impl Fn() -> String) -> Result<StateLock> {
        let mut lock = fd_lock::RwLock::new(self.open_lock(name)?);
        let start = Instant::now();
        loop {
            // The guard is forgotten: the lock lasts until the file is closed.
            match lock.try_write().map(std::mem::forget) {
                Ok(()) => return Ok(StateLock { _held: lock }),
                Err(e) if is_contended(&e) && start.elapsed() < LOCK_WAIT => {
                    std::thread::sleep(LOCK_POLL);
                }
                Err(e) if is_contended(&e) => {
                    return Err(CliError::failure(busy()));
                }
                Err(e) => {
                    return Err(CliError::failure(tr!(
                        "can't lock {path}: {e}",
                        path = self.root.join(name).display(),
                        e = e
                    )));
                }
            }
        }
    }

    pub fn load_peers(&self) -> Result<Peers> {
        let path = self.root.join(PEERS_FILE);
        let peers: Peers = load_json(&path)?.unwrap_or_default();
        peers.validate().map_err(|why| {
            CliError::failure(tr!(
                "{path} is damaged: {why}",
                path = path.display(),
                why = why
            ))
            .with_hint(tr!("fix or delete the entry, then pair that device again"))
        })?;
        Ok(peers)
    }

    pub fn save_peers(&self, peers: &Peers) -> Result<()> {
        save_json(&self.root.join(PEERS_FILE), peers)
    }

    /// The seen-set, without entries that expired before `now`.
    pub fn load_seen(&self, now: i64) -> Result<Seen> {
        let mut seen: Seen = load_json(&self.root.join(SEEN_FILE))?.unwrap_or_default();
        seen.prune(now);
        Ok(seen)
    }

    pub fn save_seen(&self, seen: &Seen) -> Result<()> {
        save_json(&self.root.join(SEEN_FILE), seen)
    }
}

/// Where locks shared by all of the user's config directories live. On Linux and the BSDs
/// that is `/run/user/<uid>` when it exists, found from the user id rather than from
/// `XDG_RUNTIME_DIR`, so processes with different environments (a desktop session, cron,
/// SSH) agree; kc-store keeps its own user-wide lock there too. Otherwise the platform's
/// cache directory.
fn user_lock_dir() -> Option<PathBuf> {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::fs::MetadataExt as _;
        let uid = crate::harden::effective_uid();
        let run = PathBuf::from(format!("/run/user/{uid}"));
        if fs::metadata(&run).is_ok_and(|m| m.is_dir() && m.uid() == uid) {
            return Some(run.join("dev.1pass.kc"));
        }
    }
    let dirs = directories::BaseDirs::new()?;
    Some(dirs.cache_dir().join("dev.1pass.kc"))
}

fn is_contended(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(CliError::failure(tr!(
                "can't read {path}: {e}",
                path = path.display(),
                e = e
            )));
        }
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|e| {
        CliError::failure(tr!(
            "{path} is damaged: {why}",
            path = path.display(),
            why = e
        ))
    })
}

fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| {
        CliError::failure(tr!(
            "can't encode {path}: {e}",
            path = path.display(),
            e = e
        ))
    })?;
    bytes.push(b'\n');
    write_private_atomic(path, &bytes).map_err(|e| {
        CliError::failure(tr!("can't write {path}: {e}", path = path.display(), e = e))
    })
}

/// `[A-Za-z0-9_-]{1,64}`: what base64url ids look like, so they're safe in a URL path.
pub fn is_url_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| {
        CliError::failure(tr!("can't create {path}: {e}", path = dir.display(), e = e))
    })
}

/// Writes `bytes` to `path` atomically: a new file readable only by the user (mode 600 on
/// Unix) in the same directory, synced, then renamed over `path`. A symlink at `path` is
/// replaced, not followed. For kc's own files in its config directory; a secret value
/// written anywhere else goes through [`write_secret_file`].
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, |_| Ok(()))
}

/// [`write_private_atomic`] for a secret value at a place the user chose (`kc get
/// --to-file`). On Windows a new file takes its folder's permissions, which may let others
/// read it, so before anything is written the file's inherited entries are replaced by a
/// single one for its owner; if that can't be done, nothing is written.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, restrict_to_owner)
}

#[cfg(windows)]
fn restrict_to_owner(file: &Path) -> io::Result<()> {
    // icacls from the system directory; `*S-1-3-4` is OWNER RIGHTS, i.e. whoever owns the
    // file: the user creating it.
    let icacls = std::env::var_os("SystemRoot").map_or_else(
        || PathBuf::from("icacls"),
        |root| PathBuf::from(root).join("System32").join("icacls.exe"),
    );
    let status = std::process::Command::new(icacls)
        .arg(file)
        .args(["/inheritance:r", "/grant:r", "*S-1-3-4:F", "/q"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(tr!(
            "couldn't restrict the file to its owner (icacls failed)"
        )))
    }
}

/// Unix: the file is created with mode 600 already.
#[cfg(not(windows))]
fn restrict_to_owner(_file: &Path) -> io::Result<()> {
    Ok(())
}

/// Creates the temporary file empty, lets `prepare` adjust it, then writes, syncs and
/// renames it over `path`. The handle that created the file is the one written through, so
/// nobody can swap the file in between: on Unix it was created exclusively with mode 600;
/// on Windows it is held without any sharing, so until it is closed no other process can
/// open it for reading or writing, or rename it away while `prepare` restricts it.
/// (Opening it only to change its permissions, as icacls does, isn't subject to sharing.)
fn write_atomic(
    path: &Path,
    bytes: &[u8],
    prepare: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, tr!("not a file path")))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp = dir.join(format!(
        ".{}.kc-{}-{}-{nanos}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let mut file = options.open(&tmp)?;
    let written = prepare(&tmp).and_then(|()| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    drop(file);
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kc_proto::DeviceKeyPair;

    fn peer(label: &str) -> Peer {
        let pk = *DeviceKeyPair::generate().public();
        Peer {
            label: Label::new(label).unwrap(),
            fingerprint: pk.fingerprint(),
            device_pk: pk,
            inbox_id: InboxId([7; 16]),
            writer_id: Some("d3JpdGVy".into()),
            token_key: None,
            paired_at: 1_760_000_000,
        }
    }

    #[test]
    fn peers_round_trip_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        assert!(state.load_peers().unwrap().peers.is_empty());
        let peers = Peers {
            v: 1,
            peers: vec![peer("Mac"), peer("laptop")],
            ..Peers::default()
        };
        state.save_peers(&peers).unwrap();
        let loaded = state.load_peers().unwrap();
        assert_eq!(loaded, peers);
        assert!(loaded.find("mac").is_some());
        assert!(loaded.label_taken("LAPTOP"));
        assert_eq!(loaded.position("laptop"), Some(1));
        let fp = peers.peers[0].fingerprint;
        assert_eq!(loaded.by_fingerprint(&fp).unwrap().label.as_str(), "Mac");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(PEERS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn damaged_peers_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        let mut bad = peer("mac");
        bad.fingerprint = peer("other").fingerprint;
        state
            .save_peers(&Peers {
                v: 1,
                peers: vec![bad],
                ..Peers::default()
            })
            .unwrap();
        assert!(state.load_peers().is_err());
        state
            .save_peers(&Peers {
                v: 1,
                peers: vec![peer("mac"), peer("MAC")],
                ..Peers::default()
            })
            .unwrap();
        assert!(state.load_peers().is_err());
        fs::write(dir.path().join(PEERS_FILE), b"{not json").unwrap();
        assert!(state.load_peers().is_err());
    }

    #[test]
    fn seen_prunes_expired_ids() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        let mut seen = Seen::default();
        let (old, new) = (MessageId([1; 16]), MessageId([2; 16]));
        seen.insert(&old, 100);
        seen.insert(&new, 1_000);
        seen.insert(&new, 500); // keeps the later expiry
        state.save_seen(&seen).unwrap();
        let loaded = state.load_seen(200).unwrap();
        assert!(!loaded.contains(&old));
        assert!(loaded.contains(&new));
        assert_eq!(loaded.seen[&new.to_hex()], 1_000);
    }

    #[test]
    fn the_import_journal_survives_a_restart_and_clears_when_done() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        let id = MessageId([3; 16]);
        let mut seen = Seen::default();
        let settled = ItemResult {
            name: kc_proto::ItemName::new("A").unwrap(),
            status: kc_proto::ItemStatus::SkippedConflict,
        };
        seen.pending(&id, 500).done.push(settled.clone());
        state.save_seen(&seen).unwrap();
        let mut loaded = state.load_seen(100).unwrap();
        assert!(!loaded.contains(&id), "pending isn't seen");
        assert_eq!(loaded.pending(&id, 400).done, [settled]);
        loaded.insert(&id, 500);
        assert!(loaded.contains(&id));
        assert!(loaded.pending.is_empty());
        // Expired journal entries go too.
        let mut seen = Seen::default();
        seen.pending(&id, 50);
        seen.prune(100);
        assert!(seen.pending.is_empty());
    }

    #[test]
    fn token_slots_are_checked() {
        let mut p = peer("mac");
        assert_eq!(p.token_key(), format!("writer/{}", p.fingerprint.to_hex()));
        p.token_key = Some(format!("writer/{}/0a1b2c3d", p.fingerprint.to_hex()));
        assert!(
            Peers {
                v: 1,
                peers: vec![p.clone()],
                ..Peers::default()
            }
            .validate()
            .is_ok()
        );
        p.token_key = Some("device-key".into());
        assert!(
            Peers {
                v: 1,
                peers: vec![p.clone()],
                ..Peers::default()
            }
            .validate()
            .is_err()
        );
        p.token_key = Some("writer/../device-key".into());
        assert!(
            Peers {
                v: 1,
                peers: vec![p],
                ..Peers::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn lock_is_exclusive_between_handles() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        let held = state.lock().unwrap();
        assert!(state.try_lock().is_none());
        drop(held);
        assert!(state.try_lock().is_some());
        // The items lock is a separate file, so it nests inside state.lock; it is per user
        // and per namespace, so another config directory contends for it too.
        let held = state.lock().unwrap();
        let ns = format!("dev.1pass.kc.test-lock-{}", std::process::id());
        let items = state.lock_items(&ns).unwrap();
        let other = tempfile::tempdir().unwrap();
        let elsewhere = StateDir::new(other.path());
        let mut contended = fd_lock::RwLock::new(elsewhere.open_lock_at_user_dir(&ns).unwrap());
        assert!(contended.try_write().is_err());
        drop((items, held));
        assert!(contended.try_write().is_ok());
        assert!(state.try_lock().is_some());
    }

    #[test]
    fn atomic_write_replaces_files_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out");
        write_private_atomic(&path, b"one").unwrap();
        write_private_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        #[cfg(unix)]
        {
            let target = dir.path().join("target");
            fs::write(&target, b"keep").unwrap();
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            write_private_atomic(&link, b"new").unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"keep");
            assert!(
                !fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
        let leftovers = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        assert!(is_url_token("abc-_09"));
        assert!(!is_url_token("../x"));
        assert!(!is_url_token(""));
    }
}
