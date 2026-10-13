//! Seeded in-memory transport and persistence adapter; production policy comes from kc-sync.
use kc_sync::*;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::BTreeMap;

fn peer(n: usize) -> PeerId {
    PeerId(format!("device-{n}"))
}
fn id(i: &Incoming) -> ChangeId {
    ChangeId {
        name: "key".into(),
        generation: i.generation,
        new_vid: i.new_vid,
    }
}
fn fp(n: u64) -> Fp {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    Fp(bytes)
}
fn slot(v: Vid) -> String {
    format!("{v:?}")
}

struct Device {
    state: ItemState,
    value: Option<Fp>,
    checkpoint: Checkpoint,
    slots: SlotBudget,
    held: BTreeMap<Vid, Incoming>,
    receipts: BTreeMap<(usize, Vid), AckResult>,
    outbox: Outbox,
    sent: BTreeMap<Vid, Incoming>,
    generations: Generations,
}
impl Device {
    fn new() -> Self {
        Self {
            state: ItemState::new(0, Vid([0; 16]), fp(0), vec![]),
            value: Some(fp(0)),
            checkpoint: Checkpoint::default(),
            slots: SlotBudget::new(1024),
            held: BTreeMap::new(),
            receipts: BTreeMap::new(),
            outbox: Outbox::default(),
            sent: BTreeMap::new(),
            generations: Generations::default(),
        }
    }

    // This adapter only executes Transition intents; it contains no independent sync decisions.
    fn commit(&mut self, incoming: &Incoming, decision: Decision) {
        let before = self.value;
        let checkpoint_before = self.checkpoint.fingerprint();
        match decision.transition {
            Transition::Unchanged => {}
            Transition::Hold { .. } => {
                assert!(matches!(
                    self.slots.reserve(&slot(incoming.new_vid), SlotKind::Held),
                    Reservation::Reserved { .. }
                ));
                self.held.insert(incoming.new_vid, incoming.clone());
            }
            Transition::Conflict { candidates } => {
                for vid in candidates.candidates.keys() {
                    // A previously held slot is promoted by releasing its reservation first.
                    if self.slots.kind(&slot(*vid)) == Some(SlotKind::Held) {
                        self.slots.release(&slot(*vid));
                    }
                    assert!(matches!(
                        self.slots.reserve(&slot(*vid), SlotKind::ConflictCandidate),
                        Reservation::Reserved { .. }
                    ));
                }
                self.state.conflict = Some(candidates);
            }
            Transition::Advance {
                head,
                lineage,
                write_value,
                clear_conflict,
            } => {
                if write_value {
                    assert!(matches!(
                        self.slots.prepare_overwrite("checkpoint", "held-fallback"),
                        OverwriteCapacity::Ready { .. }
                    ));
                    self.checkpoint.before_remote_overwrite(self.value.unwrap());
                    self.value = incoming.value_fp;
                }
                self.state.head = head;
                self.state.lineage = lineage;
                assert!(self.state.remember(
                    incoming.new_vid,
                    VidRecord {
                        fp: incoming.value_fp.unwrap(),
                        parents: incoming.parents.clone()
                    }
                ));
                if clear_conflict {
                    self.state.conflict = None;
                }
            }
            Transition::Retire => {
                // §2.5 only changes registration metadata. There is deliberately no value deletion.
                self.state.generation += 1;
            }
        }
        assert!(
            before.is_some() && self.value.is_some(),
            "remote event deleted a value"
        );
        if checkpoint_before.is_some() {
            assert_eq!(
                self.checkpoint.fingerprint(),
                checkpoint_before,
                "remote event replaced a checkpoint"
            );
        }
    }

    fn receive(&mut self, from: usize, incoming: &Incoming) -> AckResult {
        if let Some(ack) = self.receipts.get(&(from, incoming.new_vid)) {
            return *ack;
        }
        let d = decide(
            &self.state,
            self.value.unwrap(),
            incoming,
            false,
            None,
            true,
        );
        let ack = d.ack;
        self.commit(incoming, d);
        if ack.is_final() {
            self.receipts.insert((from, incoming.new_vid), ack);
        }
        ack
    }

    fn review(&mut self, rng: &mut StdRng, stats: &mut Stats) {
        let Some(vid) = self
            .held
            .keys()
            .nth(rng.random_range(0..self.held.len().max(1)))
            .copied()
        else {
            return;
        };
        let incoming = self.held.remove(&vid).unwrap();
        self.slots.release(&slot(vid));
        let old_checkpoint = self.checkpoint.fingerprint();
        if rng.random_bool(0.5) {
            stats.accepted += 1;
            // The simulated human is the only caller providing the test approval marker.
            let approval = VerifiedApproval::for_tests();
            let d = decide(
                &self.state,
                self.value.unwrap(),
                &incoming,
                false,
                Some(&approval),
                true,
            );
            self.commit(&incoming, d);
        } else {
            stats.rejected += 1;
        }
        // Human review does not implicitly confirm a new checkpoint baseline.
        if old_checkpoint.is_some() {
            assert_eq!(old_checkpoint, self.checkpoint.fingerprint());
        }
    }
}

#[derive(Clone)]
enum Message {
    Change {
        from: usize,
        to: usize,
        incoming: Incoming,
    },
    Ack {
        from: usize,
        to: usize,
        change: ChangeId,
        result: AckResult,
    },
}
#[derive(Clone)]
struct Envelope {
    due: u64,
    message: Message,
}
#[derive(Default)]
struct Stats {
    dropped: usize,
    duplicated: usize,
    reordered: usize,
    delayed: usize,
    accepted: usize,
    rejected: usize,
    retired: usize,
}
struct Created {
    owner: usize,
    vid: Vid,
    fp: Fp,
    sequence: u64,
}

struct World {
    rng: StdRng,
    devices: Vec<Device>,
    queue: Vec<Envelope>,
    created: Vec<Created>,
    tick: u64,
    sequence: u64,
    stats: Stats,
}
impl World {
    fn new(seed: u64) -> Self {
        let count = 3 + (seed as usize % 2);
        let mut devices: Vec<_> = (0..count).map(|_| Device::new()).collect();
        for device in &mut devices {
            for target in 0..count {
                device.generations.received_accept(
                    peer(target),
                    Registration {
                        name: "key".into(),
                        generation: 0,
                    },
                );
            }
        }
        Self {
            rng: StdRng::seed_from_u64(seed),
            devices,
            queue: vec![],
            created: vec![],
            tick: 0,
            sequence: 0,
            stats: Stats::default(),
        }
    }
    fn schedule(&mut self, message: Message) {
        let delay = self.rng.random_range(1..=12);
        self.stats.delayed += usize::from(delay > 1);
        self.queue.push(Envelope {
            due: self.tick + delay,
            message,
        });
    }
    fn edit(&mut self, owner: usize) {
        self.sequence += 1;
        let vid = Vid(self.rng.random());
        let value = fp(self.sequence);
        assert!(!self.created.iter().any(|c| c.vid == vid));
        let targets = self.devices.len();
        let device = &mut self.devices[owner];
        let parents = vec![device.state.head];
        device.state.head = vid;
        device.state.lineage = device.state.lineage.clone().with_head(vid);
        device.state.remember(
            vid,
            VidRecord {
                fp: value,
                parents: parents.clone(),
            },
        );
        // Local edits cannot silently resolve existing conflicts: retain their new head as a candidate.
        if let Some(c) = &mut device.state.conflict {
            c.candidates.insert(
                vid,
                VidRecord {
                    fp: value,
                    parents: parents.clone(),
                },
            );
        }
        device.value = Some(value);
        let incoming = Incoming {
            generation: 0,
            new_vid: vid,
            parents,
            lineage: device.state.lineage.clone(),
            value_fp: Some(value),
            retire: false,
        };
        device.sent.insert(vid, incoming.clone());
        assert!(matches!(
            device
                .slots
                .reserve_snapshot(&format!("send-{}", slot(vid))),
            Reservation::Reserved { .. }
        ));
        let mut messages = vec![];
        for target in 0..targets {
            if target != owner {
                let mut outgoing = incoming.clone();
                outgoing.generation = device
                    .generations
                    .outgoing_generation(&peer(target), "key")
                    .unwrap();
                device.outbox.enqueue(peer(target), id(&outgoing));
                messages.push(Message::Change {
                    from: owner,
                    to: target,
                    incoming: outgoing,
                });
            }
        }
        self.created.push(Created {
            owner,
            vid,
            fp: value,
            sequence: self.sequence,
        });
        for message in messages {
            self.schedule(message);
        }
    }
    fn retry_pending(&mut self) {
        let mut retry = vec![];
        for (from, device) in self.devices.iter().enumerate() {
            for to in 0..self.devices.len() {
                for change in device.outbox.pending(&peer(to)) {
                    let mut incoming = device.sent[&change.new_vid].clone();
                    incoming.generation = change.generation;
                    retry.push(Message::Change { from, to, incoming });
                }
            }
        }
        for message in retry {
            self.schedule(message);
        }
    }
    fn deliver(&mut self, lossy: bool) -> bool {
        let eligible: Vec<_> = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, e)| e.due <= self.tick)
            .map(|(n, _)| n)
            .collect();
        if eligible.is_empty() {
            return false;
        }
        let index = eligible[self.rng.random_range(0..eligible.len())];
        self.stats.reordered += usize::from(index != 0);
        let envelope = self.queue.remove(index);
        if lossy && self.rng.random_bool(0.20) {
            self.stats.dropped += 1;
            return true;
        }
        if lossy && self.rng.random_bool(0.15) {
            self.stats.duplicated += 1;
            self.schedule(envelope.message.clone());
        }
        match envelope.message {
            Message::Change { from, to, incoming } => {
                let result = self.devices[to].receive(from, &incoming);
                self.schedule(Message::Ack {
                    from: to,
                    to: from,
                    change: id(&incoming),
                    result,
                });
            }
            Message::Ack {
                from,
                to,
                change,
                result,
            } => {
                let d = &mut self.devices[to];
                d.outbox.ack(&peer(from), &change, result);
                let release: Vec<_> = d
                    .sent
                    .keys()
                    .copied()
                    .filter(|vid| d.outbox.snapshot_releasable("key", *vid))
                    .collect();
                for vid in release {
                    assert!(d.outbox.release_snapshot("key", vid));
                    d.slots.release(&format!("send-{}", slot(vid)));
                }
            }
        }
        true
    }
    fn assert_preserved(&self, seed: u64) {
        for c in &self.created {
            let superseded_locally = self
                .created
                .iter()
                .any(|later| later.owner == c.owner && later.sequence > c.sequence);
            let preserved = self.devices.iter().any(|d| {
                d.value == Some(c.fp)
                    || d.held.values().any(|h| h.value_fp == Some(c.fp))
                    || d.state
                        .conflict
                        .as_ref()
                        .is_some_and(|set| set.candidates.values().any(|r| r.fp == c.fp))
            });
            assert!(
                superseded_locally || preserved,
                "seed {seed}: lost local value {:?} from {}",
                c.vid,
                c.owner
            );
        }
        for d in &self.devices {
            assert!(d.value.is_some());
        }
    }
    fn quiesce(&mut self) {
        self.retry_pending();
        for _ in 0..20000 {
            self.tick += 1;
            while self.deliver(false) {}
            for d in &mut self.devices {
                d.review(&mut self.rng, &mut self.stats);
            }
            if self.queue.is_empty() {
                let pending = self.devices.iter().any(|d| {
                    (0..self.devices.len()).any(|p| d.outbox.pending(&peer(p)).next().is_some())
                });
                if pending {
                    self.retry_pending();
                } else {
                    return;
                }
            }
        }
        panic!("transport did not quiesce");
    }
}

#[test]
fn seeded_lossy_multi_device_simulation_256_seeds() {
    let mut totals = Stats::default();
    for seed in 0..256 {
        let mut w = World::new(seed);
        // An initial causal edit exercises genuine Phase-1 holds and human accept/reject.
        w.edit(0);
        for _ in 0..30 {
            w.tick += 1;
            w.deliver(true);
            for d in &mut w.devices {
                d.review(&mut w.rng, &mut w.stats);
            }
            w.assert_preserved(seed);
        }
        w.quiesce();
        // Retire is delivered through the same decision path and changes registration, never value.
        let d = &mut w.devices[1];
        let before = d.value;
        let retire = Incoming {
            generation: 0,
            new_vid: Vid(w.rng.random()),
            parents: vec![d.state.head],
            lineage: d.state.lineage.clone(),
            value_fp: None,
            retire: true,
        };
        assert_eq!(d.receive(0, &retire), AckResult::Held);
        d.held.remove(&retire.new_vid);
        d.slots.release(&slot(retire.new_vid));
        let token = VerifiedApproval::for_tests();
        let decision = decide(
            &d.state,
            d.value.unwrap(),
            &retire,
            false,
            Some(&token),
            true,
        );
        assert_eq!(decision.transition, Transition::Retire);
        d.commit(&retire, decision);
        assert_eq!(before, d.value);
        w.stats.retired += 1;
        // A fresh human registration exchange reinstates the receiver-owned generation.
        let mut generations = Generations::default();
        generations.rm("key").unwrap();
        let accept = generations.accept("key", peer(0));
        assert_eq!(accept.generation, d.state.generation);
        // Every sender records the receiver's new Accept; generations never move backwards.
        for device in &mut w.devices {
            device.generations.received_accept(peer(1), accept.clone());
        }
        // Every device makes independent local edits before network delivery; then edits interleave
        // with transport. This creates true concurrent branches rather than serial overwrite tests.
        for owner in 0..w.devices.len() {
            for _ in 0..w.rng.random_range(1..=4) {
                w.edit(owner);
            }
        }
        for step in 0..120 {
            w.tick += 1;
            match w.rng.random_range(0..10) {
                0..=1 => {
                    let owner = w.rng.random_range(0..w.devices.len());
                    w.edit(owner);
                }
                2 => {
                    let owner = w.rng.random_range(0..w.devices.len());
                    w.devices[owner].review(&mut w.rng, &mut w.stats);
                }
                3 => {
                    let owner = w.rng.random_range(0..w.devices.len());
                    let d = &mut w.devices[owner];
                    d.checkpoint.human_confirm(d.value.unwrap());
                    assert_eq!(d.checkpoint.fingerprint(), d.value);
                }
                _ => {
                    w.deliver(true);
                }
            }
            if step % 23 == 0 {
                w.retry_pending();
            }
            w.assert_preserved(seed);
        }
        w.quiesce();
        w.assert_preserved(seed);
        for (a_index, a) in w.devices.iter().enumerate() {
            assert!(a.held.is_empty());
            for (b_index, b) in w.devices.iter().enumerate().skip(a_index + 1) {
                let equal = a.state.head == b.state.head && a.value == b.value;
                let conflict = a
                    .state
                    .conflict
                    .as_ref()
                    .is_some_and(|c| c.candidates.contains_key(&b.state.head))
                    || b.state
                        .conflict
                        .as_ref()
                        .is_some_and(|c| c.candidates.contains_key(&a.state.head));
                assert!(
                    equal || conflict,
                    "seed {seed}: devices {a_index}/{b_index} silently diverged"
                );
            }
            for p in 0..w.devices.len() {
                assert_eq!(a.outbox.pending(&peer(p)).count(), 0);
            }
        }
        assert!(w.queue.is_empty());
        totals.dropped += w.stats.dropped;
        totals.duplicated += w.stats.duplicated;
        totals.reordered += w.stats.reordered;
        totals.delayed += w.stats.delayed;
        totals.accepted += w.stats.accepted;
        totals.rejected += w.stats.rejected;
        totals.retired += w.stats.retired;
    }
    assert!(
        totals.dropped > 0 && totals.duplicated > 0 && totals.reordered > 0 && totals.delayed > 0
    );
    assert!(totals.accepted > 0 && totals.rejected > 0 && totals.retired == 256);
    // Keep actual coverage visible when this test is run with --nocapture.
    println!(
        "256 seeds: dropped={}, duplicated={}, reordered={}, delayed={}, accepted={}, rejected={}, retired={}",
        totals.dropped,
        totals.duplicated,
        totals.reordered,
        totals.delayed,
        totals.accepted,
        totals.rejected,
        totals.retired
    );
}
