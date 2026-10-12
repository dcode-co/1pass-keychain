//! Remembered-device inboxes in SQLite.
//!
//! The database holds only `SHA-256(inbox_id)`, `SHA-256(owner_token)` and the
//! writer token hashes the owner registered. Message bodies are opaque HPKE
//! ciphertexts. `secure_delete` overwrites deleted rows, `auto_vacuum =
//! INCREMENTAL` returns freed pages, and `max_page_count` caps the file.
//!
//! One connection behind a mutex, used from `spawn_blocking`: the relay's
//! inbox traffic is small, and a single writer keeps the quota checks simple.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::futures::OwnedNotified;
use tokio::sync::{Notify, Semaphore};

use crate::config::{DbLocation, InboxConfig};
use crate::util::{Hash, Id, Token, ct_eq, duration_ms, random, sha256};

#[derive(Debug)]
pub enum InboxError {
    /// Unknown inbox, wrong token, or a writer that isn't registered.
    Unauthorized,
    /// Unknown writer or message in an inbox the caller owns.
    NotFound,
    /// Message, byte, writer or per-writer quota reached.
    Full,
    /// Relay-wide caps: inbox count or database size.
    Capacity,
    Internal(String),
}

impl From<rusqlite::Error> for InboxError {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DiskFull) => InboxError::Capacity,
            _ => InboxError::Internal(e.to_string()),
        }
    }
}

const SCHEMA_VERSION: i64 = 1;

const SCHEMA_V1: &str = "
CREATE TABLE inboxes (
    id_hash      BLOB PRIMARY KEY NOT NULL,
    owner_hash   BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    last_read_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX inboxes_by_last_read ON inboxes(last_read_at);

CREATE TABLE writers (
    writer_id  BLOB PRIMARY KEY NOT NULL,
    inbox      BLOB NOT NULL REFERENCES inboxes(id_hash) ON DELETE CASCADE,
    token_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (inbox, token_hash)
) WITHOUT ROWID;

CREATE TABLE messages (
    msg_id      BLOB NOT NULL UNIQUE,
    inbox       BLOB NOT NULL REFERENCES inboxes(id_hash) ON DELETE CASCADE,
    writer_id   BLOB NOT NULL REFERENCES writers(writer_id) ON DELETE CASCADE,
    received_at INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    body        BLOB NOT NULL
);
CREATE INDEX messages_by_inbox ON messages(inbox, received_at);
CREATE INDEX messages_by_writer ON messages(writer_id);
CREATE INDEX messages_by_expiry ON messages(expires_at);
";

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    /// Database jobs admitted at once (queued or running). The permit moves
    /// into the blocking job, so a request that disconnects can't leave work
    /// queued beyond this bound.
    admission: Arc<Semaphore>,
}

/// Default for `Db::open`'s job bound.
pub const DB_JOBS: usize = 32;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Db {
    pub fn open(location: &DbLocation, max_db_bytes: u64, max_jobs: usize) -> anyhow::Result<Db> {
        let conn = match location {
            DbLocation::File(path) => {
                if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                }
                Connection::open(path).with_context(|| format!("opening {}", path.display()))?
            }
            DbLocation::Memory => Connection::open_in_memory()?,
        };
        configure(&conn, matches!(location, DbLocation::File(_)), max_db_bytes)?;
        migrate(&conn)?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
            admission: Arc::new(Semaphore::new(max_jobs.max(1))),
        })
    }

    /// Run `f` on the connection in the blocking pool. Waiting for admission
    /// is cancellable; once admitted, the job holds its permit to the end.
    pub async fn call<F, R>(&self, f: F) -> Result<R, InboxError>
    where
        F: FnOnce(&mut Connection) -> Result<R, InboxError> + Send + 'static,
        R: Send + 'static,
    {
        let permit = Arc::clone(&self.admission)
            .acquire_owned()
            .await
            .map_err(|_| InboxError::Internal("database closed".into()))?;
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f(&mut lock(&conn))
        })
        .await
        .map_err(|_| InboxError::Internal("database task failed".into()))?
    }

    /// Synchronous access, for tests and diagnostics.
    pub fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> R) -> R {
        f(&lock(&self.conn))
    }
}

fn configure(conn: &Connection, file: bool, max_db_bytes: u64) -> anyhow::Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    // Only takes effect before the first table exists, i.e. on a new database.
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    if file {
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        anyhow::ensure!(
            mode.eq_ignore_ascii_case("wal"),
            "SQLite refused WAL mode (got {mode})"
        );
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "journal_size_limit", 8 * 1024 * 1024)?;
    }
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    let page_size: i64 = conn.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let pages = (max_db_bytes / u64::try_from(page_size).unwrap_or(4096).max(512)).max(32);
    conn.pragma_update(
        None,
        "max_page_count",
        i64::try_from(pages).unwrap_or(i64::MAX),
    )?;
    Ok(())
}

fn migrate(conn: &Connection) -> anyhow::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    anyhow::ensure!(
        version <= SCHEMA_VERSION,
        "database schema v{version} is newer than this relay (v{SCHEMA_VERSION})"
    );
    if version < 1 {
        conn.execute_batch(&format!(
            "BEGIN; {SCHEMA_V1} PRAGMA user_version = 1; COMMIT;"
        ))?;
    }
    Ok(())
}

pub struct StoredMessage {
    pub msg_id: Id,
    pub writer_id: Id,
    pub received_at_ms: i64,
    pub body: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PurgeStats {
    pub expired_messages: usize,
    pub idle_inboxes: usize,
}

type Waiters = Arc<Mutex<HashMap<Hash, Arc<Notify>>>>;

pub struct InboxStore {
    db: Db,
    cfg: InboxConfig,
    waiters: Waiters,
}

/// A registration for "wake me when this inbox gets a message". Dropping it
/// removes the entry once nobody else waits on the same inbox.
pub struct InboxWaiter {
    waiters: Waiters,
    key: Hash,
    notify: Arc<Notify>,
}

impl InboxWaiter {
    pub fn notified(&self) -> OwnedNotified {
        Arc::clone(&self.notify).notified_owned()
    }
}

impl Drop for InboxWaiter {
    fn drop(&mut self) {
        let mut map = lock(&self.waiters);
        // One reference in the map and one here means we were the last waiter.
        if Arc::strong_count(&self.notify) <= 2
            && map
                .get(&self.key)
                .is_some_and(|n| Arc::ptr_eq(n, &self.notify))
        {
            map.remove(&self.key);
        }
    }
}

fn blob<const N: usize>(v: Vec<u8>) -> Result<[u8; N], InboxError> {
    v.try_into()
        .map_err(|_| InboxError::Internal("corrupt row".into()))
}

/// The owner check. An unknown inbox and a wrong token look the same.
fn check_owner(c: &Connection, id_hash: &Hash, owner_hash: &Hash) -> Result<(), InboxError> {
    let stored: Option<Vec<u8>> = c
        .query_row(
            "SELECT owner_hash FROM inboxes WHERE id_hash = ?1",
            [&id_hash[..]],
            |r| r.get(0),
        )
        .optional()?;
    let (known, stored) = match stored {
        Some(v) => (true, blob::<32>(v)?),
        None => (false, [0u8; 32]),
    };
    // Compare even when unknown so both paths take the same time.
    let matches = ct_eq(&stored, owner_hash);
    if known && matches {
        Ok(())
    } else {
        Err(InboxError::Unauthorized)
    }
}

/// The writer that `token_hash` belongs to in this inbox. Every registered
/// hash is compared in constant time.
fn find_writer(c: &Connection, id_hash: &Hash, token_hash: &Hash) -> Result<Id, InboxError> {
    let mut stmt =
        c.prepare_cached("SELECT writer_id, token_hash FROM writers WHERE inbox = ?1")?;
    let rows = stmt.query_map([&id_hash[..]], |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    let mut found = None;
    for row in rows {
        let (writer_id, stored) = row?;
        let stored: Hash = blob(stored)?;
        if ct_eq(&stored, token_hash) && found.is_none() {
            found = Some(blob::<16>(writer_id)?);
        }
    }
    found.ok_or(InboxError::Unauthorized)
}

impl InboxStore {
    pub fn new(db: Db, cfg: InboxConfig) -> Self {
        InboxStore {
            db,
            cfg,
            waiters: Arc::default(),
        }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub async fn create(&self, now_ms: i64) -> Result<(Id, Token), InboxError> {
        let id: Id = random();
        let token: Token = random();
        let (id_hash, owner_hash) = (sha256(&id), sha256(&token));
        let max = self.cfg.max_inboxes;
        self.db
            .call(move |c| {
                let n: i64 = c.query_row("SELECT COUNT(*) FROM inboxes", [], |r| r.get(0))?;
                if usize::try_from(n).unwrap_or(usize::MAX) >= max {
                    return Err(InboxError::Capacity);
                }
                c.execute(
                    "INSERT INTO inboxes (id_hash, owner_hash, created_at, last_read_at) VALUES (?1, ?2, ?3, ?3)",
                    params![&id_hash[..], &owner_hash[..], now_ms],
                )?;
                Ok(())
            })
            .await?;
        Ok((id, token))
    }

    /// The owner check on its own, for requests that must not read a body
    /// before the caller is known.
    pub async fn authorize_owner(&self, id_hash: Hash, owner_hash: Hash) -> Result<(), InboxError> {
        self.db
            .call(move |c| check_owner(c, &id_hash, &owner_hash))
            .await
    }

    /// Register a writer token hash. Registering the same hash again returns
    /// the existing writer id.
    pub async fn add_writer(
        &self,
        id_hash: Hash,
        owner_hash: Hash,
        token_hash: Hash,
        now_ms: i64,
    ) -> Result<Id, InboxError> {
        let max = self.cfg.max_writers;
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                check_owner(&tx, &id_hash, &owner_hash)?;
                let existing: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT writer_id FROM writers WHERE inbox = ?1 AND token_hash = ?2",
                        params![&id_hash[..], &token_hash[..]],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(writer_id) = existing {
                    return blob(writer_id);
                }
                let n: i64 = tx.query_row("SELECT COUNT(*) FROM writers WHERE inbox = ?1", [&id_hash[..]], |r| r.get(0))?;
                if usize::try_from(n).unwrap_or(usize::MAX) >= max {
                    return Err(InboxError::Full);
                }
                let writer_id: Id = random();
                tx.execute(
                    "INSERT INTO writers (writer_id, inbox, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
                    params![&writer_id[..], &id_hash[..], &token_hash[..], now_ms],
                )?;
                tx.commit()?;
                Ok(writer_id)
            })
            .await
    }

    /// Revoke a writer. Its undelivered messages go with it.
    pub async fn remove_writer(
        &self,
        id_hash: Hash,
        owner_hash: Hash,
        writer_id: Option<Id>,
    ) -> Result<(), InboxError> {
        self.db
            .call(move |c| {
                check_owner(c, &id_hash, &owner_hash)?;
                let writer_id = writer_id.ok_or(InboxError::NotFound)?;
                let n = c.execute(
                    "DELETE FROM writers WHERE writer_id = ?1 AND inbox = ?2",
                    params![&writer_id[..], &id_hash[..]],
                )?;
                if n == 0 {
                    Err(InboxError::NotFound)
                } else {
                    Ok(())
                }
            })
            .await
    }

    pub async fn writer_for(&self, id_hash: Hash, token_hash: Hash) -> Result<Id, InboxError> {
        self.db
            .call(move |c| find_writer(c, &id_hash, &token_hash))
            .await
    }

    pub async fn post(
        &self,
        id_hash: Hash,
        token_hash: Hash,
        body: Bytes,
        now_ms: i64,
    ) -> Result<Id, InboxError> {
        let cfg = self.cfg.clone();
        let msg_id = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let writer_id = find_writer(&tx, &id_hash, &token_hash)?;
                tx.execute(
                    "DELETE FROM messages WHERE inbox = ?1 AND expires_at <= ?2",
                    params![&id_hash[..], now_ms],
                )?;
                let size = i64::try_from(body.len()).unwrap_or(i64::MAX);
                let (count, bytes): (i64, i64) = tx.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages WHERE inbox = ?1",
                    [&id_hash[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if over(count, 1, cfg.max_messages) || over(bytes, size, cfg.max_bytes) {
                    return Err(InboxError::Full);
                }
                let (w_count, w_bytes): (i64, i64) = tx.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages WHERE writer_id = ?1",
                    [&writer_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if over(w_count, 1, cfg.writer_max_messages) || over(w_bytes, size, cfg.writer_max_bytes) {
                    return Err(InboxError::Full);
                }
                let msg_id: Id = random();
                tx.execute(
                    "INSERT INTO messages (msg_id, inbox, writer_id, received_at, expires_at, size, body)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        &msg_id[..],
                        &id_hash[..],
                        &writer_id[..],
                        now_ms,
                        now_ms.saturating_add(duration_ms(cfg.message_ttl)),
                        size,
                        &body[..]
                    ],
                )?;
                tx.commit()?;
                Ok(msg_id)
            })
            .await?;
        self.wake(&id_hash);
        Ok(msg_id)
    }

    /// Unexpired messages, oldest first. Counts as a read for idle deletion.
    pub async fn list(
        &self,
        id_hash: Hash,
        owner_hash: Hash,
        now_ms: i64,
    ) -> Result<Vec<StoredMessage>, InboxError> {
        self.db
            .call(move |c| {
                check_owner(c, &id_hash, &owner_hash)?;
                // Best effort: a full database must not stop the owner from
                // reading (and then deleting) what is there.
                let _ = c.execute(
                    "UPDATE inboxes SET last_read_at = ?2 WHERE id_hash = ?1",
                    params![&id_hash[..], now_ms],
                );
                let mut stmt = c.prepare_cached(
                    "SELECT msg_id, writer_id, received_at, body FROM messages
                     WHERE inbox = ?1 AND expires_at > ?2 ORDER BY received_at, rowid",
                )?;
                let rows = stmt.query_map(params![&id_hash[..], now_ms], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                })?;
                let mut out = Vec::new();
                for row in rows {
                    let (msg_id, writer_id, received_at_ms, body) = row?;
                    out.push(StoredMessage {
                        msg_id: blob(msg_id)?,
                        writer_id: blob(writer_id)?,
                        received_at_ms,
                        body,
                    });
                }
                Ok(out)
            })
            .await
    }

    pub async fn delete_message(
        &self,
        id_hash: Hash,
        owner_hash: Hash,
        msg_id: Option<Id>,
    ) -> Result<(), InboxError> {
        self.db
            .call(move |c| {
                check_owner(c, &id_hash, &owner_hash)?;
                let msg_id = msg_id.ok_or(InboxError::NotFound)?;
                let n = c.execute(
                    "DELETE FROM messages WHERE msg_id = ?1 AND inbox = ?2",
                    params![&msg_id[..], &id_hash[..]],
                )?;
                if n == 0 {
                    Err(InboxError::NotFound)
                } else {
                    Ok(())
                }
            })
            .await
    }

    pub async fn delete_inbox(&self, id_hash: Hash, owner_hash: Hash) -> Result<(), InboxError> {
        self.db
            .call(move |c| {
                check_owner(c, &id_hash, &owner_hash)?;
                c.execute("DELETE FROM inboxes WHERE id_hash = ?1", [&id_hash[..]])?;
                Ok(())
            })
            .await?;
        self.wake(&id_hash);
        Ok(())
    }

    /// Delete expired messages and inboxes nobody has read for `idle_delete`,
    /// then give the freed pages back and truncate the WAL so deleted
    /// ciphertext doesn't linger there.
    ///
    /// Work is done in short batches, each its own database call, so requests
    /// keep flowing in between and `stop` (set at shutdown) takes effect
    /// within one batch.
    pub async fn purge(&self, now_ms: i64, stop: &AtomicBool) -> Result<PurgeStats, InboxError> {
        const MESSAGES_PER_BATCH: usize = 128;
        const INBOXES_PER_BATCH: usize = 16;
        const PAGES_PER_BATCH: i64 = 2048;
        let idle_cutoff = now_ms.saturating_sub(duration_ms(self.cfg.idle_delete));
        let mut stats = PurgeStats::default();
        loop {
            let n = self
                .db
                .call(move |c| {
                    Ok(c.execute(
                        "DELETE FROM messages WHERE rowid IN
                           (SELECT rowid FROM messages WHERE expires_at <= ?1 LIMIT ?2)",
                        params![now_ms, MESSAGES_PER_BATCH as i64],
                    )?)
                })
                .await?;
            stats.expired_messages += n;
            if n < MESSAGES_PER_BATCH || stop.load(Ordering::Relaxed) {
                break;
            }
        }
        while !stop.load(Ordering::Relaxed) {
            let n = self
                .db
                .call(move |c| {
                    Ok(c.execute(
                        "DELETE FROM inboxes WHERE id_hash IN
                           (SELECT id_hash FROM inboxes WHERE last_read_at <= ?1 LIMIT ?2)",
                        params![idle_cutoff, INBOXES_PER_BATCH as i64],
                    )?)
                })
                .await?;
            stats.idle_inboxes += n;
            if n < INBOXES_PER_BATCH {
                break;
            }
        }
        if stats.expired_messages + stats.idle_inboxes > 0 {
            while !stop.load(Ordering::Relaxed) {
                let freed = self
                    .db
                    .call(move |c| {
                        // Each step frees one page, so run the statement to its end.
                        let mut stmt =
                            c.prepare(&format!("PRAGMA incremental_vacuum({PAGES_PER_BATCH})"))?;
                        let mut rows = stmt.query([])?;
                        let mut freed = 0i64;
                        while rows.next()?.is_some() {
                            freed += 1;
                        }
                        Ok(freed)
                    })
                    .await?;
                if freed < PAGES_PER_BATCH {
                    break;
                }
            }
        }
        self.db
            .call(|c| Ok(c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?))
            .await?;
        Ok(stats)
    }

    pub fn waiter(&self, id_hash: Hash) -> InboxWaiter {
        let notify = Arc::clone(lock(&self.waiters).entry(id_hash).or_default());
        InboxWaiter {
            waiters: Arc::clone(&self.waiters),
            key: id_hash,
            notify,
        }
    }

    pub fn waiting_inboxes(&self) -> usize {
        lock(&self.waiters).len()
    }

    fn wake(&self, id_hash: &Hash) {
        if let Some(n) = lock(&self.waiters).get(id_hash) {
            n.notify_waiters();
        }
    }
}

fn over(current: i64, adding: i64, max: usize) -> bool {
    let max = i64::try_from(max).unwrap_or(i64::MAX);
    current.saturating_add(adding) > max
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(cfg: InboxConfig) -> InboxStore {
        InboxStore::new(
            Db::open(&DbLocation::Memory, cfg.max_db_bytes, DB_JOBS).unwrap(),
            cfg,
        )
    }

    #[tokio::test]
    async fn owner_and_writer_auth() {
        let s = store(InboxConfig::default());
        let (id, owner) = s.create(1_000).await.unwrap();
        let (ih, oh) = (sha256(&id), sha256(&owner));
        let wtok: Token = random();
        let wid = s.add_writer(ih, oh, sha256(&wtok), 1_000).await.unwrap();
        assert_eq!(
            s.add_writer(ih, oh, sha256(&wtok), 1_000).await.unwrap(),
            wid,
            "idempotent"
        );
        assert!(matches!(
            s.add_writer(ih, sha256(b"x"), sha256(&wtok), 1).await,
            Err(InboxError::Unauthorized)
        ));
        assert!(matches!(
            s.list(sha256(b"nope"), oh, 1).await,
            Err(InboxError::Unauthorized)
        ));
        assert_eq!(s.writer_for(ih, sha256(&wtok)).await.unwrap(), wid);
        assert!(matches!(
            s.writer_for(ih, sha256(&owner)).await,
            Err(InboxError::Unauthorized)
        ));
        let m = s
            .post(ih, sha256(&wtok), Bytes::from_static(b"ct"), 2_000)
            .await
            .unwrap();
        let got = s.list(ih, oh, 3_000).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].msg_id, got[0].writer_id, got[0].body.as_slice()),
            (m, wid, &b"ct"[..])
        );
        s.remove_writer(ih, oh, Some(wid)).await.unwrap();
        assert!(
            s.list(ih, oh, 3_000).await.unwrap().is_empty(),
            "revoking a writer drops its messages"
        );
        assert!(matches!(
            s.post(ih, sha256(&wtok), Bytes::from_static(b"x"), 4_000)
                .await,
            Err(InboxError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn quotas() {
        let cfg = InboxConfig {
            max_messages: 3,
            max_bytes: 100,
            writer_max_messages: 2,
            writer_max_bytes: 60,
            max_writers: 2,
            ..InboxConfig::default()
        };
        let s = store(cfg);
        let (id, owner) = s.create(0).await.unwrap();
        let (ih, oh) = (sha256(&id), sha256(&owner));
        let (w1, w2, w3): (Token, Token, Token) = (random(), random(), random());
        s.add_writer(ih, oh, sha256(&w1), 0).await.unwrap();
        s.add_writer(ih, oh, sha256(&w2), 0).await.unwrap();
        assert!(matches!(
            s.add_writer(ih, oh, sha256(&w3), 0).await,
            Err(InboxError::Full)
        ));
        let body = |n: usize| Bytes::from(vec![1u8; n]);
        s.post(ih, sha256(&w1), body(30), 1).await.unwrap();
        // Per-writer byte quota (60).
        assert!(matches!(
            s.post(ih, sha256(&w1), body(31), 1).await,
            Err(InboxError::Full)
        ));
        s.post(ih, sha256(&w1), body(30), 1).await.unwrap();
        // Per-writer message quota (2).
        assert!(matches!(
            s.post(ih, sha256(&w1), body(1), 1).await,
            Err(InboxError::Full)
        ));
        // Inbox byte quota (100): 60 used.
        assert!(matches!(
            s.post(ih, sha256(&w2), body(41), 1).await,
            Err(InboxError::Full)
        ));
        s.post(ih, sha256(&w2), body(40), 1).await.unwrap();
        // Inbox message quota (3).
        assert!(matches!(
            s.post(ih, sha256(&w2), body(1), 1).await,
            Err(InboxError::Full)
        ));
    }

    #[tokio::test]
    async fn purge_removes_expired_and_idle() {
        let cfg = InboxConfig {
            message_ttl: Duration::from_millis(100),
            idle_delete: Duration::from_millis(1_000),
            ..InboxConfig::default()
        };
        let s = store(cfg);
        let (id, owner) = s.create(0).await.unwrap();
        let (ih, oh) = (sha256(&id), sha256(&owner));
        let w: Token = random();
        s.add_writer(ih, oh, sha256(&w), 0).await.unwrap();
        s.post(ih, sha256(&w), Bytes::from_static(b"old"), 0)
            .await
            .unwrap();
        assert!(
            s.list(ih, oh, 150).await.unwrap().is_empty(),
            "expired messages are hidden before the purge"
        );
        assert_eq!(
            s.purge(150, &AtomicBool::new(false)).await.unwrap(),
            PurgeStats {
                expired_messages: 1,
                idle_inboxes: 0
            }
        );
        assert_eq!(
            s.purge(150 + 1_000, &AtomicBool::new(false)).await.unwrap(),
            PurgeStats {
                expired_messages: 0,
                idle_inboxes: 1
            }
        );
        assert!(matches!(
            s.list(ih, oh, 2_000).await,
            Err(InboxError::Unauthorized)
        ));
        let leftovers: i64 = s.db().with_conn(|c| {
            c.query_row("SELECT COUNT(*) FROM writers", [], |r| r.get(0))
                .unwrap()
        });
        assert_eq!(leftovers, 0, "idle inbox deletion cascades");
    }

    #[tokio::test]
    async fn inbox_count_cap() {
        let s = store(InboxConfig {
            max_inboxes: 1,
            ..InboxConfig::default()
        });
        s.create(0).await.unwrap();
        assert!(matches!(s.create(0).await, Err(InboxError::Capacity)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admission_outlives_cancelled_callers() {
        use std::sync::atomic::AtomicUsize;
        let db = Db::open(&DbLocation::Memory, 1 << 20, 1).unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        // A slow job whose caller gives up after 50 ms keeps its permit.
        let slow = db.call(|_| {
            std::thread::sleep(Duration::from_millis(400));
            Ok(())
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), slow)
                .await
                .is_err()
        );
        // A caller that gives up while still waiting never runs at all.
        let counter = Arc::clone(&ran);
        let waiting = db.call(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), waiting)
                .await
                .is_err()
        );
        // The next caller waits for the slow job to finish, then runs.
        let t0 = std::time::Instant::now();
        let counter = Arc::clone(&ran);
        db.call(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            t0.elapsed() >= Duration::from_millis(150),
            "{:?}",
            t0.elapsed()
        );
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn waiter_entries_are_cleaned_up() {
        let s = store(InboxConfig::default());
        let key = sha256(b"inbox");
        let a = s.waiter(key);
        let b = s.waiter(key);
        assert_eq!(s.waiting_inboxes(), 1);
        drop(a);
        assert_eq!(s.waiting_inboxes(), 1);
        drop(b);
        assert_eq!(s.waiting_inboxes(), 0);
    }
}
