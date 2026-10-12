//! One-shot channels, held in memory only.
//!
//! A channel has two roles. The receiver gets its side token when it
//! allocates; the sender gets the other one when it joins, and nobody else
//! can join after that. Only token hashes are kept. Each role writes each phase
//! at most once. When a channel is deleted or expires, all of its data is
//! dropped at once and a tombstone answers 410 until the tombstone expires;
//! then the number is free again and answers 404. The tombstone keeps the two
//! token hashes, so the relay can tell its participants from strangers probing
//! for channel numbers.
//!
//! Every method takes `now`, so the TTL logic is tested without sleeping.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use kc_wire::{Phase, Role};
use rand::Rng;
use tokio::sync::Notify;
use tokio::sync::futures::OwnedNotified;
use tokio::time::Instant;

use crate::config::ChannelConfig;
use crate::util::{Hash, Token, ct_eq, random, sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    NotFound,
    /// Closed or expired. `participant` says whether the caller's token was
    /// one of the channel's two.
    Gone {
        participant: bool,
    },
    Unauthorized,
    WrongRole,
    Crowded,
    AlreadyWritten,
    Capacity,
}

pub struct Allocated {
    pub channel: u16,
    pub token: Token,
    pub expires_at: SystemTime,
}

pub struct Joined {
    pub token: Token,
    pub expires_at: SystemTime,
}

pub enum Poll {
    Ready(Bytes),
    /// Not written yet. `notified` fires on any change to the channel; check
    /// again then, or at `expires` at the latest.
    Pending {
        notified: OwnedNotified,
        expires: Instant,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    Now,
    /// It was already a tombstone. `participant` as in `ChannelError::Gone`.
    Already {
        participant: bool,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub open: usize,
    pub tombstones: usize,
    pub ram: usize,
}

pub struct ChannelStore {
    cfg: ChannelConfig,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    map: HashMap<u16, Entry>,
    open: usize,
    ram: usize,
}

/// SHA-256 of each role's side token: `[receiver, sender]`.
type Tokens = [Option<Hash>; 2];

enum Entry {
    Open(Box<Channel>),
    Tombstone { until: Instant, tokens: Tokens },
}

struct Channel {
    expires: Instant,
    expires_wall: SystemTime,
    tokens: Tokens,
    /// `[role][phase]`, indexed by the writer's role.
    slots: [[Option<Bytes>; 4]; 2],
    ram: usize,
    notify: Arc<Notify>,
}

fn role_ix(role: Role) -> usize {
    match role {
        Role::Receiver => 0,
        Role::Sender => 1,
    }
}

fn phase_ix(phase: Phase) -> usize {
    match phase {
        Phase::Pake => 0,
        Phase::Confirm => 1,
        Phase::Payload => 2,
        Phase::Ack => 3,
    }
}

/// Which role `token_hash` belongs to. Both stored hashes are compared in
/// constant time.
fn role_of(tokens: &Tokens, token_hash: &Hash) -> Option<Role> {
    let r = tokens[0].as_ref().is_some_and(|h| ct_eq(h, token_hash));
    let s = tokens[1].as_ref().is_some_and(|h| ct_eq(h, token_hash));
    match (r, s) {
        (true, _) => Some(Role::Receiver),
        (false, true) => Some(Role::Sender),
        (false, false) => None,
    }
}

impl Channel {
    fn role_of(&self, token_hash: &Hash) -> Option<Role> {
        role_of(&self.tokens, token_hash)
    }
}

impl Inner {
    /// Apply the clock to one entry: an expired channel becomes a tombstone,
    /// and a tombstone past its time is forgotten.
    fn settle(&mut self, c: u16, now: Instant, tombstone: Duration) {
        enum Act {
            Expire(Instant),
            Forget,
            Keep,
        }
        let act = match self.map.get(&c) {
            Some(Entry::Open(ch)) if now >= ch.expires => Act::Expire(ch.expires + tombstone),
            Some(Entry::Tombstone { until, .. }) if now >= *until => Act::Forget,
            _ => Act::Keep,
        };
        match act {
            Act::Expire(until) => self.close(c, until, now),
            Act::Forget => {
                self.map.remove(&c);
            }
            Act::Keep => {}
        }
    }

    /// Drop an open channel's data and leave a tombstone until `until`.
    fn close(&mut self, c: u16, until: Instant, now: Instant) {
        let ch = match self.map.remove(&c) {
            Some(Entry::Open(ch)) => ch,
            Some(tombstone) => {
                self.map.insert(c, tombstone);
                return;
            }
            None => return,
        };
        self.open -= 1;
        self.ram -= ch.ram;
        ch.notify.notify_waiters();
        if until > now {
            self.map.insert(
                c,
                Entry::Tombstone {
                    until,
                    tokens: ch.tokens,
                },
            );
        }
    }

    /// The open channel `c` after applying the clock. `token_hash` only
    /// decides whether a tombstone's `Gone` names a participant.
    fn open_mut(
        &mut self,
        c: u16,
        now: Instant,
        tombstone: Duration,
        token_hash: Option<&Hash>,
    ) -> Result<&mut Channel, ChannelError> {
        self.settle(c, now, tombstone);
        match self.map.get_mut(&c) {
            None => Err(ChannelError::NotFound),
            Some(Entry::Tombstone { tokens, .. }) => Err(ChannelError::Gone {
                participant: token_hash.is_some_and(|t| role_of(tokens, t).is_some()),
            }),
            Some(Entry::Open(ch)) => Ok(ch),
        }
    }

    fn sweep(&mut self, now: Instant, tombstone: Duration) {
        let due: Vec<u16> = self
            .map
            .iter()
            .filter(|(_, e)| match e {
                Entry::Open(ch) => now >= ch.expires,
                Entry::Tombstone { until, .. } => now >= *until,
            })
            .map(|(c, _)| *c)
            .collect();
        for c in due {
            self.settle(c, now, tombstone);
        }
    }
}

fn pick_free(map: &HashMap<u16, Entry>, max: u16) -> Option<u16> {
    if max == 0 {
        return None;
    }
    let mut rng = rand::rng();
    for _ in 0..16 {
        let n = rng.random_range(1..=max);
        if !map.contains_key(&n) {
            return Some(n);
        }
    }
    let free: Vec<u16> = (1..=max).filter(|n| !map.contains_key(n)).collect();
    if free.is_empty() {
        None
    } else {
        Some(free[rng.random_range(0..free.len())])
    }
}

impl ChannelStore {
    pub fn new(cfg: ChannelConfig) -> Self {
        ChannelStore {
            cfg,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// New channel; the caller is the receiver.
    pub fn allocate(&self, now: Instant, wall: SystemTime) -> Result<Allocated, ChannelError> {
        let mut g = self.lock();
        if g.open >= self.cfg.max_open {
            g.sweep(now, self.cfg.tombstone);
            if g.open >= self.cfg.max_open {
                return Err(ChannelError::Capacity);
            }
        }
        let number = match pick_free(&g.map, self.cfg.number_max) {
            Some(n) => n,
            None => {
                g.sweep(now, self.cfg.tombstone);
                pick_free(&g.map, self.cfg.number_max).ok_or(ChannelError::Capacity)?
            }
        };
        let token: Token = random();
        let expires_wall = wall + self.cfg.ttl;
        g.map.insert(
            number,
            Entry::Open(Box::new(Channel {
                expires: now + self.cfg.ttl,
                expires_wall,
                tokens: [Some(sha256(&token)), None],
                slots: Default::default(),
                ram: 0,
                notify: Arc::new(Notify::new()),
            })),
        );
        g.open += 1;
        Ok(Allocated {
            channel: number,
            token,
            expires_at: expires_wall,
        })
    }

    /// The sender's side token. Only the first join succeeds; later ones get
    /// `Crowded` and leave the channel as it is.
    pub fn join(&self, c: u16, now: Instant) -> Result<Joined, ChannelError> {
        let mut g = self.lock();
        let ch = g.open_mut(c, now, self.cfg.tombstone, None)?;
        if ch.tokens[1].is_some() {
            return Err(ChannelError::Crowded);
        }
        let token: Token = random();
        ch.tokens[1] = Some(sha256(&token));
        Ok(Joined {
            token,
            expires_at: ch.expires_wall,
        })
    }

    /// Everything `write` checks except the RAM cap, so a request that will
    /// be refused is refused before its body is read.
    pub fn check_write(
        &self,
        c: u16,
        token_hash: &Hash,
        phase: Phase,
        now: Instant,
    ) -> Result<Role, ChannelError> {
        let mut g = self.lock();
        let ch = g.open_mut(c, now, self.cfg.tombstone, Some(token_hash))?;
        let role = ch.role_of(token_hash).ok_or(ChannelError::Unauthorized)?;
        if !phase.writable_by(role) {
            return Err(ChannelError::WrongRole);
        }
        if ch.slots[role_ix(role)][phase_ix(phase)].is_some() {
            return Err(ChannelError::AlreadyWritten);
        }
        Ok(role)
    }

    pub fn write(
        &self,
        c: u16,
        token_hash: &Hash,
        phase: Phase,
        body: Bytes,
        now: Instant,
    ) -> Result<(), ChannelError> {
        let mut g = self.lock();
        let max_ram = self.cfg.max_ram_bytes;
        let ram_used = g.ram;
        let ch = g.open_mut(c, now, self.cfg.tombstone, Some(token_hash))?;
        let role = ch.role_of(token_hash).ok_or(ChannelError::Unauthorized)?;
        if !phase.writable_by(role) {
            return Err(ChannelError::WrongRole);
        }
        let slot = &mut ch.slots[role_ix(role)][phase_ix(phase)];
        if slot.is_some() {
            return Err(ChannelError::AlreadyWritten);
        }
        let len = body.len();
        if ram_used.saturating_add(len) > max_ram {
            return Err(ChannelError::Capacity);
        }
        *slot = Some(body);
        ch.ram += len;
        ch.notify.notify_waiters();
        g.ram += len;
        Ok(())
    }

    /// The peer's bytes for `phase`, if written.
    pub fn poll(
        &self,
        c: u16,
        token_hash: &Hash,
        phase: Phase,
        now: Instant,
    ) -> Result<Poll, ChannelError> {
        let mut g = self.lock();
        let ch = g.open_mut(c, now, self.cfg.tombstone, Some(token_hash))?;
        let role = ch.role_of(token_hash).ok_or(ChannelError::Unauthorized)?;
        let peer = role.peer();
        if !phase.writable_by(peer) {
            // The peer can never write this phase; don't let the caller wait.
            return Err(ChannelError::WrongRole);
        }
        match &ch.slots[role_ix(peer)][phase_ix(phase)] {
            Some(bytes) => Ok(Poll::Ready(bytes.clone())),
            None => Ok(Poll::Pending {
                notified: Arc::clone(&ch.notify).notified_owned(),
                expires: ch.expires,
            }),
        }
    }

    /// Close an open channel (either role's token), or report that it is
    /// already closed. DELETE is idempotent, so a tombstone answers success to
    /// anyone; `participant` lets the caller charge strangers for the probe.
    pub fn delete(
        &self,
        c: u16,
        token_hash: Option<&Hash>,
        now: Instant,
    ) -> Result<Closed, ChannelError> {
        let mut g = self.lock();
        let tombstone = self.cfg.tombstone;
        match g.open_mut(c, now, tombstone, token_hash) {
            Ok(ch) => {
                if token_hash.and_then(|t| ch.role_of(t)).is_none() {
                    return Err(ChannelError::Unauthorized);
                }
            }
            Err(ChannelError::Gone { participant }) => return Ok(Closed::Already { participant }),
            Err(e) => return Err(e),
        }
        g.close(c, now + tombstone, now);
        Ok(Closed::Now)
    }

    /// Expire channels and forget old tombstones.
    pub fn sweep(&self, now: Instant) -> Stats {
        let mut g = self.lock();
        g.sweep(now, self.cfg.tombstone);
        Stats {
            open: g.open,
            tombstones: g.map.len() - g.open,
            ram: g.ram,
        }
    }

    pub fn stats(&self) -> Stats {
        let g = self.lock();
        Stats {
            open: g.open,
            tombstones: g.map.len() - g.open,
            ram: g.ram,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ChannelConfig {
        ChannelConfig {
            ttl: Duration::from_secs(600),
            tombstone: Duration::from_secs(600),
            max_open: 10,
            max_ram_bytes: 1000,
            number_max: 9999,
            ..ChannelConfig::default()
        }
    }

    fn h(t: &Token) -> Hash {
        sha256(t)
    }

    fn ready(p: Poll) -> Bytes {
        match p {
            Poll::Ready(b) => b,
            Poll::Pending { .. } => panic!("expected data"),
        }
    }

    #[test]
    fn roles_and_slots() {
        let s = ChannelStore::new(cfg());
        let t0 = Instant::now();
        let a = s.allocate(t0, SystemTime::now()).unwrap();
        assert!((1..=9999).contains(&a.channel));
        let j = s.join(a.channel, t0).unwrap();
        assert_eq!(s.join(a.channel, t0).err(), Some(ChannelError::Crowded));
        let (r, snd) = (h(&a.token), h(&j.token));

        assert!(matches!(
            s.poll(a.channel, &r, Phase::Pake, t0),
            Ok(Poll::Pending { .. })
        ));
        s.write(a.channel, &r, Phase::Pake, Bytes::from_static(b"msgA"), t0)
            .unwrap();
        s.write(
            a.channel,
            &snd,
            Phase::Pake,
            Bytes::from_static(b"msgB"),
            t0,
        )
        .unwrap();
        assert_eq!(
            ready(s.poll(a.channel, &r, Phase::Pake, t0).unwrap()),
            "msgB"
        );
        assert_eq!(
            ready(s.poll(a.channel, &snd, Phase::Pake, t0).unwrap()),
            "msgA"
        );
        assert_eq!(
            s.write(a.channel, &r, Phase::Pake, Bytes::from_static(b"again"), t0)
                .err(),
            Some(ChannelError::AlreadyWritten)
        );
        assert_eq!(
            s.check_write(a.channel, &r, Phase::Payload, t0).err(),
            Some(ChannelError::WrongRole)
        );
        assert_eq!(
            s.check_write(a.channel, &snd, Phase::Ack, t0).err(),
            Some(ChannelError::WrongRole)
        );
        assert!(matches!(
            s.poll(a.channel, &r, Phase::Ack, t0),
            Err(ChannelError::WrongRole)
        ));
        assert!(matches!(
            s.poll(a.channel, &snd, Phase::Payload, t0),
            Err(ChannelError::WrongRole)
        ));
        let stranger = sha256(b"nope");
        assert!(matches!(
            s.poll(a.channel, &stranger, Phase::Pake, t0),
            Err(ChannelError::Unauthorized)
        ));
        assert_eq!(s.stats().ram, 8);
    }

    #[test]
    fn expiry_tombstone_then_free() {
        let s = ChannelStore::new(ChannelConfig {
            number_max: 1,
            ..cfg()
        });
        let t0 = Instant::now();
        let a = s.allocate(t0, SystemTime::now()).unwrap();
        assert_eq!(a.channel, 1);
        let t1 = t0 + Duration::from_secs(600);
        assert_eq!(
            s.join(1, t1).err(),
            Some(ChannelError::Gone { participant: false })
        );
        assert!(matches!(
            s.poll(1, &h(&a.token), Phase::Pake, t1),
            Err(ChannelError::Gone { participant: true })
        ));
        assert!(matches!(
            s.poll(1, &sha256(b"x"), Phase::Pake, t1),
            Err(ChannelError::Gone { participant: false })
        ));
        // The number is still taken by the tombstone.
        assert_eq!(
            s.allocate(t1, SystemTime::now()).err(),
            Some(ChannelError::Capacity)
        );
        let t2 = t1 + Duration::from_secs(600);
        assert_eq!(s.join(1, t2).err(), Some(ChannelError::NotFound));
        assert_eq!(s.allocate(t2, SystemTime::now()).unwrap().channel, 1);
    }

    #[test]
    fn delete_frees_ram_and_is_idempotent() {
        let s = ChannelStore::new(cfg());
        let t0 = Instant::now();
        let a = s.allocate(t0, SystemTime::now()).unwrap();
        let r = h(&a.token);
        s.write(a.channel, &r, Phase::Pake, Bytes::from(vec![0u8; 40]), t0)
            .unwrap();
        assert_eq!(
            s.delete(a.channel, None, t0).err(),
            Some(ChannelError::Unauthorized)
        );
        assert_eq!(
            s.delete(a.channel, Some(&sha256(b"x")), t0).err(),
            Some(ChannelError::Unauthorized)
        );
        assert_eq!(s.delete(a.channel, Some(&r), t0), Ok(Closed::Now));
        assert_eq!(
            s.stats(),
            Stats {
                open: 0,
                tombstones: 1,
                ram: 0
            }
        );
        assert_eq!(
            s.delete(a.channel, Some(&r), t0),
            Ok(Closed::Already { participant: true })
        );
        assert_eq!(
            s.delete(a.channel, None, t0),
            Ok(Closed::Already { participant: false })
        );
        assert!(matches!(
            s.poll(a.channel, &r, Phase::Pake, t0),
            Err(ChannelError::Gone { participant: true })
        ));
        let later = t0 + Duration::from_secs(601);
        assert_eq!(
            s.delete(a.channel, Some(&r), later).err(),
            Some(ChannelError::NotFound)
        );
    }

    #[test]
    fn caps() {
        let s = ChannelStore::new(ChannelConfig {
            max_open: 2,
            max_ram_bytes: 100,
            ..cfg()
        });
        let t0 = Instant::now();
        let a = s.allocate(t0, SystemTime::now()).unwrap();
        let _b = s.allocate(t0, SystemTime::now()).unwrap();
        assert_eq!(
            s.allocate(t0, SystemTime::now()).err(),
            Some(ChannelError::Capacity)
        );
        let r = h(&a.token);
        s.write(a.channel, &r, Phase::Pake, Bytes::from(vec![0u8; 64]), t0)
            .unwrap();
        assert_eq!(
            s.write(
                a.channel,
                &r,
                Phase::Confirm,
                Bytes::from(vec![0u8; 64]),
                t0
            )
            .err(),
            Some(ChannelError::Capacity)
        );
        // Expired channels stop counting as soon as allocation needs room.
        let later = t0 + Duration::from_secs(600);
        assert!(s.allocate(later, SystemTime::now()).is_ok());
        assert_eq!(s.stats().ram, 0);
    }

    #[test]
    fn sweep_expires_and_forgets() {
        let s = ChannelStore::new(cfg());
        let t0 = Instant::now();
        for _ in 0..3 {
            s.allocate(t0, SystemTime::now()).unwrap();
        }
        assert_eq!(s.sweep(t0 + Duration::from_secs(599)).open, 3);
        assert_eq!(
            s.sweep(t0 + Duration::from_secs(600)),
            Stats {
                open: 0,
                tombstones: 3,
                ram: 0
            }
        );
        assert_eq!(s.sweep(t0 + Duration::from_secs(1200)), Stats::default());
        // A sweep that runs very late skips the tombstone stage entirely.
        s.allocate(t0, SystemTime::now()).unwrap();
        assert_eq!(s.sweep(t0 + Duration::from_secs(5000)), Stats::default());
    }

    #[test]
    fn numbers_are_unique_and_cover_the_range() {
        let s = ChannelStore::new(ChannelConfig {
            max_open: 50,
            number_max: 50,
            ..cfg()
        });
        let t0 = Instant::now();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            assert!(seen.insert(s.allocate(t0, SystemTime::now()).unwrap().channel));
        }
        assert_eq!(seen.len(), 50);
        assert!(seen.iter().all(|n| (1..=50).contains(n)));
    }

    #[tokio::test]
    async fn waiters_wake_on_write_and_on_close() {
        let s = ChannelStore::new(cfg());
        let t0 = Instant::now();
        let a = s.allocate(t0, SystemTime::now()).unwrap();
        let j = s.join(a.channel, t0).unwrap();
        let Poll::Pending { notified, .. } =
            s.poll(a.channel, &h(&a.token), Phase::Pake, t0).unwrap()
        else {
            panic!("nothing written yet")
        };
        s.write(
            a.channel,
            &h(&j.token),
            Phase::Pake,
            Bytes::from_static(b"m"),
            t0,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), notified)
            .await
            .expect("woken by write");

        let Poll::Pending { notified, .. } =
            s.poll(a.channel, &h(&j.token), Phase::Pake, t0).unwrap()
        else {
            panic!("receiver hasn't written")
        };
        s.delete(a.channel, Some(&h(&a.token)), t0).unwrap();
        tokio::time::timeout(Duration::from_secs(5), notified)
            .await
            .expect("woken by close");
    }
}
