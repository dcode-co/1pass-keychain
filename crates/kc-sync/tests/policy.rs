use kc_sync::*;
use std::collections::BTreeMap;

fn v(n: u16) -> Vid {
    let mut b = [0; 16];
    b[14..].copy_from_slice(&n.to_be_bytes());
    Vid(b)
}
fn f(n: u8) -> Fp {
    Fp([n; 32])
}
fn peer(n: &str) -> PeerId {
    PeerId(n.into())
}
fn state() -> ItemState {
    ItemState::new(7, v(1), f(1), vec![v(0)])
}
fn incoming() -> Incoming {
    Incoming {
        generation: 7,
        new_vid: v(2),
        parents: vec![v(1)],
        lineage: Lineage::new([v(1), v(2)]),
        value_fp: Some(f(2)),
        retire: false,
    }
}
fn run(s: &ItemState, i: &Incoming) -> Decision {
    decide(s, f(1), i, false, None, true)
}
fn held(d: &Decision, reason: HoldReason) {
    assert_eq!(d.ack, AckResult::Held);
    assert_eq!(d.transition, Transition::Hold { reason });
    assert!(!d.quarantine);
}
fn conflicted() -> ItemState {
    let mut s = state();
    s.conflict = Some(ConflictSet {
        candidates: BTreeMap::from([
            (
                v(1),
                VidRecord {
                    fp: f(1),
                    parents: vec![v(0)],
                },
            ),
            (
                v(3),
                VidRecord {
                    fp: f(3),
                    parents: vec![v(0)],
                },
            ),
            (
                v(4),
                VidRecord {
                    fp: f(4),
                    parents: vec![v(0)],
                },
            ),
        ]),
    });
    s
}

#[test]
fn row1_stale_beats_freeze_violation_conflict_approval_and_limits() {
    let mut i = incoming();
    i.generation = 6;
    i.new_vid = v(1);
    let d = decide(
        &conflicted(),
        f(1),
        &i,
        true,
        Some(&VerifiedApproval::for_tests()),
        false,
    );
    assert_eq!(d.ack, AckResult::StaleGeneration);
    assert_eq!(d.transition, Transition::Unchanged);
    assert!(!d.quarantine);
}
#[test]
fn row2_frozen_beats_fast_forward() {
    held(
        &decide(
            &state(),
            f(1),
            &incoming(),
            true,
            Some(&VerifiedApproval::for_tests()),
            true,
        ),
        HoldReason::Frozen,
    );
}
#[test]
fn row2_frozen_beats_violation() {
    let mut i = incoming();
    i.new_vid = v(1);
    held(
        &decide(&state(), f(1), &i, true, None, true),
        HoldReason::Frozen,
    );
}
#[test]
fn row3_same_vid_different_fp_is_quarantined() {
    let mut i = incoming();
    i.new_vid = v(1);
    i.parents = vec![v(0)];
    let d = run(&state(), &i);
    assert_eq!(d.ack, AckResult::Rejected);
    assert!(d.quarantine);
}
#[test]
fn row3_same_vid_different_parents_is_quarantined() {
    let mut i = incoming();
    i.new_vid = v(1);
    i.value_fp = Some(f(1));
    let d = run(&state(), &i);
    assert_eq!(d.ack, AckResult::Rejected);
    assert!(d.quarantine);
}
#[test]
fn row3_checks_non_head_known_and_conflict_records() {
    let mut s = state();
    s.remember(
        v(9),
        VidRecord {
            fp: f(9),
            parents: vec![v(0)],
        },
    );
    let mut i = incoming();
    i.new_vid = v(9);
    assert!(run(&s, &i).quarantine);
    i.new_vid = v(3);
    assert!(run(&conflicted(), &i).quarantine);
}
#[test]
fn row4_duplicate_head_applied_without_write() {
    let mut i = incoming();
    i.new_vid = v(1);
    i.value_fp = Some(f(1));
    i.parents = vec![v(0)];
    assert_eq!(
        run(&state(), &i),
        Decision {
            ack: AckResult::Applied,
            transition: Transition::Unchanged,
            quarantine: false
        }
    );
}
#[test]
fn row4_ancestor_beats_conflict_and_no_approval() {
    let mut s = conflicted();
    s.lineage = Lineage::new([v(1), v(2)]);
    assert_eq!(run(&s, &incoming()).transition, Transition::Unchanged);
}
#[test]
fn row5_adds_candidates_and_beats_same_value_and_fast_forward() {
    let mut i = incoming();
    i.value_fp = Some(f(1));
    let d = decide(
        &conflicted(),
        f(1),
        &i,
        false,
        Some(&VerifiedApproval::for_tests()),
        true,
    );
    let Transition::Conflict { candidates } = d.transition else {
        panic!("{d:?}");
    };
    assert_eq!(candidates.candidates.len(), 4);
    assert!(candidates.candidates.contains_key(&v(2)));
}
#[test]
fn row5_complete_resolve_without_approval_requires_review() {
    let mut i = incoming();
    i.parents = vec![v(1), v(3), v(4), v(99)];
    held(&run(&conflicted(), &i), HoldReason::Resolve);
}
#[test]
fn row5_complete_approved_resolve_clears_conflict_atomically() {
    let mut i = incoming();
    i.parents = vec![v(1), v(3), v(4), v(99)];
    let d = decide(
        &conflicted(),
        f(1),
        &i,
        false,
        Some(&VerifiedApproval::for_tests()),
        true,
    );
    assert!(
        matches!(d.transition, Transition::Advance { head, clear_conflict: true, write_value: true, .. } if head == v(2))
    );
}
#[test]
fn row5_missing_any_candidate_including_own_head_stays_conflict() {
    for missing in [v(1), v(3), v(4)] {
        let mut i = incoming();
        i.parents = [v(1), v(3), v(4)]
            .into_iter()
            .filter(|v| *v != missing)
            .collect();
        for approved in [false, true] {
            let token = VerifiedApproval::for_tests();
            let d = decide(
                &conflicted(),
                f(1),
                &i,
                false,
                approved.then_some(&token),
                true,
            );
            assert_eq!(d.ack, AckResult::Conflict);
        }
    }
}
#[test]
fn row5_resolve_obeys_limits() {
    let mut i = incoming();
    i.parents = vec![v(1), v(3), v(4)];
    held(
        &decide(
            &conflicted(),
            f(1),
            &i,
            false,
            Some(&VerifiedApproval::for_tests()),
            false,
        ),
        HoldReason::OverLimit,
    );
}
#[test]
fn row6_same_value_converges_before_approval_and_limits() {
    let mut i = incoming();
    i.value_fp = Some(f(1));
    i.parents = vec![v(55)];
    let d = decide(&state(), f(1), &i, false, None, false);
    assert!(
        matches!(d.transition, Transition::Advance { head, write_value: false, .. } if head == v(2))
    );
}
#[test]
fn convergence_is_symmetric_even_when_lineage_truncates() {
    let mut a = ItemState::new(7, v(5), f(1), vec![]);
    let mut b = ItemState::new(7, v(80), f(1), vec![]);
    a.lineage = Lineage::new((0..64).map(v)).with_head(a.head);
    b.lineage = Lineage::new((50..114).map(v)).with_head(b.head);
    let from = |s: &ItemState| Incoming {
        generation: 7,
        new_vid: s.head,
        parents: vec![],
        lineage: s.lineage.clone(),
        value_fp: Some(f(1)),
        retire: false,
    };
    let da = decide(&a, f(1), &from(&b), false, None, true);
    let db = decide(&b, f(1), &from(&a), false, None, true);
    for d in [da, db] {
        let Transition::Advance { head, lineage, .. } = d.transition else {
            panic!()
        };
        assert_eq!(head, v(80));
        assert_eq!(lineage.len(), 64);
        assert!(lineage.contains(&a.head));
        assert!(lineage.contains(&b.head));
    }
}
#[test]
fn row7_approved_direct_parent_fast_forwards() {
    let d = decide(
        &state(),
        f(1),
        &incoming(),
        false,
        Some(&VerifiedApproval::for_tests()),
        true,
    );
    assert!(
        matches!(d.transition, Transition::Advance { head, write_value: true, clear_conflict: false, .. } if head == v(2))
    );
}
#[test]
fn row8_phase1_direct_parent_is_held() {
    held(&run(&state(), &incoming()), HoldReason::NoApproval);
}
#[test]
fn row8_approved_over_limit_is_held() {
    held(
        &decide(
            &state(),
            f(1),
            &incoming(),
            false,
            Some(&VerifiedApproval::for_tests()),
            false,
        ),
        HoldReason::OverLimit,
    );
}
#[test]
fn row9_forged_lineage_cannot_replace_parent_binding() {
    let mut i = incoming();
    i.parents = vec![v(99)];
    assert!(i.lineage.contains(&state().head));
    for approved in [false, true] {
        let token = VerifiedApproval::for_tests();
        assert_eq!(
            decide(&state(), f(1), &i, false, approved.then_some(&token), true).ack,
            AckResult::Conflict
        );
    }
}
#[test]
fn retire_requires_approval_and_never_requests_value_deletion() {
    let mut i = incoming();
    i.retire = true;
    i.value_fp = None;
    held(&run(&state(), &i), HoldReason::NoApproval);
    assert_eq!(
        decide(
            &state(),
            f(1),
            &i,
            false,
            Some(&VerifiedApproval::for_tests()),
            true
        )
        .transition,
        Transition::Retire
    );
    held(
        &decide(
            &state(),
            f(1),
            &i,
            false,
            Some(&VerifiedApproval::for_tests()),
            false,
        ),
        HoldReason::OverLimit,
    );
    i.parents = vec![v(99)];
    held(&run(&conflicted(), &i), HoldReason::NoApproval);
    for s in [state(), conflicted()] {
        for parents in [vec![], vec![v(99)], vec![v(1), v(3), v(4)]] {
            i.parents = parents;
            held(
                &decide(
                    &s,
                    f(1),
                    &i,
                    false,
                    Some(&VerifiedApproval::for_tests()),
                    true,
                ),
                HoldReason::RetireMismatch,
            );
        }
    }
    i.parents = vec![v(1)];
    held(
        &decide(
            &conflicted(),
            f(1),
            &i,
            false,
            Some(&VerifiedApproval::for_tests()),
            true,
        ),
        HoldReason::Resolve,
    );
}
#[test]
fn malformed_put_or_retire_is_rejected() {
    let mut i = incoming();
    i.value_fp = None;
    assert_eq!(run(&state(), &i).ack, AckResult::Rejected);
    i.value_fp = Some(f(2));
    i.retire = true;
    assert_eq!(run(&state(), &i).ack, AckResult::Rejected);
}
#[test]
fn lineage_boundary_64_65_and_head_pinning() {
    let a = Lineage::new((0..64).map(v));
    assert_eq!(a.len(), 64);
    assert!(a.contains(&v(0)));
    let b = Lineage::merge(&a, &Lineage::new([v(64)]));
    assert_eq!(b.len(), 64);
    assert!(!b.contains(&v(0)));
    assert!(b.contains(&v(64)));
    assert_eq!(b, Lineage::merge(&Lineage::new([v(64)]), &a));
    let pinned = b.with_head(v(0));
    assert!(pinned.contains(&v(0)));
    assert!(!pinned.contains(&v(1)));
    assert_eq!(pinned.len(), 64);
}
#[test]
fn fast_forward_retains_small_random_head_at_capacity() {
    let mut s = state();
    s.lineage = Lineage::new((100..164).map(v)).with_head(v(1));
    let mut i = incoming();
    i.new_vid = v(0);
    i.lineage = Lineage::new((200..264).map(v));
    let d = decide(
        &s,
        f(1),
        &i,
        false,
        Some(&VerifiedApproval::for_tests()),
        true,
    );
    let Transition::Advance { head, lineage, .. } = d.transition else {
        panic!()
    };
    assert!(lineage.contains(&head));
    assert_eq!(head, v(0));
    assert_eq!(lineage.len(), 64);
}
#[test]
fn lineage_serde_rejects_oversized_sets() {
    let json = serde_json::to_string(&(0..65).map(v).collect::<Vec<_>>()).unwrap();
    assert!(serde_json::from_str::<Lineage>(&json).is_err());
    let a = Lineage::new((0..64).map(v));
    assert_eq!(
        a,
        serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
    );
}
#[test]
fn known_cache_is_bounded_and_immutable() {
    let mut s = state();
    for n in 2..400 {
        assert!(s.remember(
            v(n),
            VidRecord {
                fp: f(2),
                parents: vec![]
            }
        ));
    }
    assert_eq!(s.known.len(), MAX_KNOWN);
    assert!(s.known.contains_key(&s.head));
    assert!(!s.remember(
        v(1),
        VidRecord {
            fp: f(9),
            parents: vec![]
        }
    ));
}

fn id(n: u16) -> ChangeId {
    ChangeId {
        name: "key".into(),
        generation: 7,
        new_vid: v(n),
    }
}
#[test]
fn old_ack_never_deletes_newer_entry_even_with_lower_vid() {
    let mut o = Outbox::default();
    let p = peer("a");
    o.enqueue(p.clone(), id(99));
    o.enqueue(p.clone(), id(1));
    assert!(o.ack(&p, &id(99), AckResult::Applied));
    assert_eq!(o.pending(&p).cloned().collect::<Vec<_>>(), vec![id(1)]);
}
#[test]
fn newer_ack_supersedes_older_entries_for_only_that_peer_and_name() {
    let mut o = Outbox::default();
    let p = peer("a");
    let q = peer("b");
    for target in [&p, &q] {
        o.enqueue(target.clone(), id(99));
        o.enqueue(target.clone(), id(1));
    }
    let mut other = id(0);
    other.name = "other".into();
    o.enqueue(p.clone(), other.clone());
    o.ack(&p, &id(1), AckResult::Held);
    assert_eq!(o.pending(&p).cloned().collect::<Vec<_>>(), vec![other]);
    assert_eq!(o.pending(&q).count(), 2);
    assert!(!o.snapshot_releasable("key", v(99)));
    o.ack(&q, &id(1), AckResult::Conflict);
    assert!(o.snapshot_releasable("key", v(99)));
}
#[test]
fn deferred_and_unknown_ack_preserve_queue_and_snapshot() {
    let mut o = Outbox::default();
    let p = peer("a");
    o.enqueue(p.clone(), id(1));
    assert!(!o.ack(&p, &id(1), AckResult::DeferredCapacity));
    assert!(!o.ack(&p, &id(2), AckResult::Applied));
    let mut wrong = id(1);
    wrong.generation += 1;
    assert!(!o.ack(&p, &wrong, AckResult::Applied));
    assert_eq!(o.pending(&p).count(), 1);
    assert!(!o.snapshot_releasable("key", v(1)));
}
#[test]
fn stale_generation_marks_reoffer_and_accept_clears_it() {
    let mut o = Outbox::default();
    let p = peer("a");
    o.enqueue(p.clone(), id(1));
    o.ack(&p, &id(1), AckResult::StaleGeneration);
    assert_eq!(o.pending(&p).count(), 0);
    assert!(o.needs_reoffer(&p, "key"));
    o.accepted(&p, "key");
    assert!(!o.needs_reoffer(&p, "key"));
}
#[test]
fn snapshots_wait_for_all_targets_even_with_different_generations() {
    let mut o = Outbox::default();
    let p = peer("a");
    let q = peer("b");
    let mut other = id(1);
    other.generation = 22;
    o.enqueue(p.clone(), id(1));
    o.enqueue(q.clone(), other.clone());
    o.ack(&p, &id(1), AckResult::Rejected);
    assert!(!o.snapshot_releasable("key", v(1)));
    o.ack(&q, &other, AckResult::Applied);
    assert!(o.snapshot_releasable("key", v(1)));
    assert!(o.release_snapshot("key", v(1)));
    assert!(!o.snapshot_releasable("key", v(1)));
}
#[test]
fn ack_discriminant_order_and_finality() {
    for (n, result) in [
        AckResult::Applied,
        AckResult::Held,
        AckResult::Conflict,
        AckResult::StaleGeneration,
        AckResult::DeferredCapacity,
        AckResult::Rejected,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(result as usize, n);
        assert_eq!(result.is_final(), n != 4);
    }
}

fn journal() -> RemoteJournalRecord {
    RemoteJournalRecord {
        change_id: id(2),
        sender: peer("a"),
        prev_fp: f(1),
        new_fp: f(2),
        head: v(2),
        lineage: Lineage::new([v(1), v(2)]),
        approval_key: None,
        ack: AckResult::Applied,
        checkpoint_slot: Some("checkpoint".into()),
        candidate_slot: "candidate".into(),
    }
}
#[test]
fn remote_recovery_finish() {
    assert_eq!(
        recover_remote(&journal(), f(2)),
        RemoteRecovery::FinishFromStep4
    );
}
#[test]
fn remote_recovery_retry() {
    assert_eq!(recover_remote(&journal(), f(1)), RemoteRecovery::Retry);
}
#[test]
fn remote_recovery_conflict() {
    assert_eq!(recover_remote(&journal(), f(3)), RemoteRecovery::Conflict);
}
#[test]
fn local_row1_rebuild_snapshot() {
    assert_eq!(
        recover_local(f(1), f(2), f(2), false, false),
        LocalRecovery::RebuildSnapshotAndCommit
    );
}
#[test]
fn local_row2_commit_existing_snapshot() {
    assert_eq!(
        recover_local(f(1), f(2), f(2), false, true),
        LocalRecovery::Commit
    );
}
#[test]
fn local_row3_clean_committed_journal() {
    for snapshot in [false, true] {
        assert_eq!(
            recover_local(f(1), f(2), f(2), true, snapshot),
            LocalRecovery::CleanJournal
        );
    }
}
#[test]
fn local_row4_keep_queued_snapshot_and_scan() {
    for current in [f(1), f(3)] {
        for snapshot in [false, true] {
            assert_eq!(
                recover_local(f(1), f(2), current, true, snapshot),
                LocalRecovery::KeepSnapshotAndScan
            );
        }
    }
}
#[test]
fn local_row5_discard_uncommitted_snapshot() {
    for snapshot in [false, true] {
        assert_eq!(
            recover_local(f(1), f(2), f(1), false, snapshot),
            LocalRecovery::DiscardSnapshot
        );
    }
}
#[test]
fn local_row6_discard_and_scan_other_value() {
    for snapshot in [false, true] {
        assert_eq!(
            recover_local(f(1), f(2), f(3), false, snapshot),
            LocalRecovery::DiscardSnapshotAndScan
        );
    }
}
#[test]
fn journal_records_round_trip_and_equal_fps_prefer_finished_write() {
    let r = journal();
    assert_eq!(
        r,
        serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap()
    );
    let l = LocalJournalRecord {
        name: "key".into(),
        prev_fp: f(1),
        new_fp: f(2),
        new_vid: v(2),
        parents: vec![v(1)],
        snapshot_slot: "snapshot".into(),
        targets: vec![QueueTarget {
            peer: peer("a"),
            generation: 7,
        }],
    };
    assert_eq!(
        l,
        serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap()
    );
    let mut r = r;
    r.prev_fp = r.new_fp;
    assert_eq!(
        recover_remote(&r, r.new_fp),
        RemoteRecovery::FinishFromStep4
    );
}

#[test]
fn limiter_one_noninteractive_overwrite_per_item_per_24h_across_peers() {
    let mut l = Limiter::default();
    let p = peer("a");
    let q = peer("b");
    assert_eq!(
        l.check(&p, "key", RemoteOperation::Overwrite, 0, 100, false),
        LimitResult::Allowed
    );
    l.record(&p, "key", RemoteOperation::Overwrite, 0, false);
    assert_eq!(
        l.check(&q, "key", RemoteOperation::Overwrite, 86399, 100, false),
        LimitResult::ItemLimited
    );
    assert_eq!(
        l.check(&q, "key", RemoteOperation::Overwrite, 86399, 100, true),
        LimitResult::Allowed
    );
    assert_eq!(
        l.check(&q, "key", RemoteOperation::Overwrite, 86400, 100, false),
        LimitResult::Allowed
    );
}
#[test]
fn limiter_overwrite_and_retire_thresholds_are_strict_and_latched() {
    for (op, cap) in [
        (RemoteOperation::Overwrite, 5),
        (RemoteOperation::Retire, 3),
    ] {
        let mut l = Limiter::default();
        let p = peer("a");
        for n in 0..cap {
            let name = format!("key{n}");
            assert_eq!(l.check(&p, &name, op, 0, 100, false), LimitResult::Allowed);
            l.record(&p, &name, op, 0, false);
        }
        assert_eq!(
            l.check(&p, "extra", op, 0, 100, false),
            LimitResult::PeerTripped
        );
        assert_eq!(
            l.check(&p, "other", op, 200000, 100, true),
            LimitResult::PeerTripped
        );
        l.human_reset(&p);
        assert_eq!(
            l.check(&p, "extra", op, 200000, 100, false),
            LimitResult::Allowed
        );
    }
}
#[test]
fn limiter_percentage_only_at_eight_and_counts_distinct_affected_names() {
    for size in [7, 8, 9] {
        let mut l = Limiter::default();
        let p = peer("a");
        for name in ["a", "b"] {
            l.record(&p, name, RemoteOperation::Overwrite, 0, false);
        }
        assert_eq!(
            l.check(&p, "c", RemoteOperation::Retire, 0, size, false),
            if size < 8 {
                LimitResult::Allowed
            } else {
                LimitResult::PeerTripped
            }
        );
    }
    let mut l = Limiter::default();
    let p = peer("a");
    for _ in 0..3 {
        l.record(&p, "same", RemoteOperation::Overwrite, 0, true);
    }
    assert_eq!(
        l.check(&p, "same", RemoteOperation::Overwrite, 0, 8, true),
        LimitResult::Allowed
    );
}
#[test]
fn limiter_clock_rollback_expiry_and_serde() {
    let mut l = Limiter::default();
    let p = peer("a");
    l.record(&p, "key", RemoteOperation::Overwrite, i64::MAX, false);
    let mut l: Limiter = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
    assert_eq!(
        l.check(&p, "key", RemoteOperation::Overwrite, i64::MIN, 100, false),
        LimitResult::ItemLimited
    );
    let mut l = Limiter::default();
    l.record(&p, "key", RemoteOperation::Overwrite, 0, false);
    l.prune(WINDOW_SECS);
    assert_eq!(
        l.check(
            &p,
            "key",
            RemoteOperation::Overwrite,
            WINDOW_SECS,
            100,
            false
        ),
        LimitResult::Allowed
    );
}
#[test]
fn slot_capacity_floor_and_priority() {
    assert_eq!(SlotBudget::new(0).capacity(), 16);
    assert_eq!(SlotBudget::new(5).capacity(), 20);
    assert!(
        SlotKind::Checkpoint > SlotKind::ConflictCandidate
            && SlotKind::ConflictCandidate > SlotKind::Held
            && SlotKind::Held > SlotKind::Proposal
    );
    let mut b = SlotBudget::new(0);
    for n in 0..16 {
        assert!(matches!(
            b.reserve(&format!("p{n:02}"), SlotKind::Proposal),
            Reservation::Reserved { .. }
        ));
    }
    assert_eq!(b.reserve("p-new", SlotKind::Proposal), Reservation::Refused);
    assert_eq!(b.reserve("h-new", SlotKind::Held), Reservation::Refused);
    assert_eq!(
        b.reserve("candidate", SlotKind::ConflictCandidate),
        Reservation::Reserved {
            evicted: Some("p00".into())
        }
    );
    assert_eq!(
        b.reserve("checkpoint", SlotKind::Checkpoint),
        Reservation::Reserved {
            evicted: Some("p01".into())
        }
    );
    assert!(!b.release("checkpoint"));
    assert!(b.release("candidate"));
    assert_eq!(b.used(), 15);
}
#[test]
fn checkpoints_and_unacked_snapshots_are_never_evicted() {
    let mut b = SlotBudget::new(0);
    for n in 0..8 {
        b.reserve(&format!("c{n}"), SlotKind::Checkpoint);
        b.reserve_snapshot(&format!("s{n}"));
    }
    assert_eq!(b.reserve("new", SlotKind::Checkpoint), Reservation::Refused);
    assert!(matches!(
        b.prepare_overwrite("new", "held"),
        OverwriteCapacity::Deferred(Decision {
            ack: AckResult::DeferredCapacity,
            ..
        })
    ));
    assert!(matches!(
        b.prepare_overwrite("c0", "held"),
        OverwriteCapacity::Ready { .. }
    ));
}
#[test]
fn checkpoint_reservation_failure_holds_when_hold_can_be_retained() {
    let mut b = SlotBudget::new(0);
    b.reserve("occupied", SlotKind::Held);
    let OverwriteCapacity::Held(d) = b.prepare_overwrite("occupied", "held") else {
        panic!()
    };
    held(&d, HoldReason::OverLimit);
    assert_eq!(b.kind("held"), Some(SlotKind::Held));
}
#[test]
fn checkpoint_changes_only_on_first_capture_or_human_confirmation() {
    let mut cp = Checkpoint::default();
    assert_eq!(cp.before_remote_overwrite(f(1)), f(1));
    for n in 2..100 {
        assert_eq!(cp.before_remote_overwrite(f(n)), f(1));
    }
    cp.human_confirm(f(99));
    assert_eq!(cp.before_remote_overwrite(f(100)), f(99));
    let cp2: Checkpoint = serde_json::from_str(&serde_json::to_string(&cp).unwrap()).unwrap();
    assert_eq!(cp, cp2);
}
#[test]
fn generations_are_receiver_owned_scoped_and_bumped_on_rm() {
    let mut g = Generations::default();
    let a = peer("a");
    let b = peer("b");
    assert_eq!(g.outgoing_generation(&a, "key"), None);
    let accept = g.accept("key", a.clone());
    assert_eq!(accept.generation, 0);
    assert!(g.includes("key", &a));
    assert!(!g.includes("key", &b));
    let (leave, peers) = g.rm("key").unwrap();
    assert_eq!(leave.generation, 1);
    assert_eq!(peers.len(), 1);
    assert!(!g.includes("key", &a));
    let accept = g.accept("key", b.clone());
    assert_eq!(accept.generation, 1);
    assert!(g.includes("key", &b));
}
#[test]
fn accept_leave_ignore_older_generations_and_require_reacceptance() {
    let mut g = Generations::default();
    let p = peer("a");
    let msg = |generation| Registration {
        name: "key".into(),
        generation,
    };
    g.received_accept(p.clone(), msg(2));
    assert_eq!(g.outgoing_generation(&p, "key"), Some(2));
    g.received_leave(p.clone(), msg(3));
    assert_eq!(g.outgoing_generation(&p, "key"), None);
    assert!(!g.received_accept(p.clone(), msg(2)));
    assert_eq!(g.outgoing_generation(&p, "key"), None);
    g.received_accept(p.clone(), msg(3));
    assert_eq!(g.outgoing_generation(&p, "key"), Some(3));
    assert!(!g.received_leave(p.clone(), msg(2)));
    let g: Generations = serde_json::from_str(&serde_json::to_string(&g).unwrap()).unwrap();
    assert_eq!(g.outgoing_generation(&p, "key"), Some(3));
}

#[test]
fn item_state_and_outbox_round_trip_through_sync_json() {
    let s = conflicted();
    assert_eq!(
        s,
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
    );
    let mut o = Outbox::default();
    let p = peer("a");
    let q = peer("b");
    o.enqueue(p.clone(), id(1));
    o.enqueue(q.clone(), id(1));
    o.ack(&p, &id(1), AckResult::Held);
    let mut restored: Outbox = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
    assert_eq!(restored.pending(&p).count(), 0);
    assert_eq!(restored.pending(&q).count(), 1);
    assert!(!restored.snapshot_releasable("key", v(1)));
    restored.ack(&q, &id(1), AckResult::Applied);
    assert!(restored.snapshot_releasable("key", v(1)));
}
#[test]
fn known_cache_deserialization_rejects_unbounded_or_ambiguous_bindings() {
    let mut s = state();
    for n in 2..260 {
        s.known.insert(
            v(n),
            VidRecord {
                fp: f(2),
                parents: vec![],
            },
        );
    }
    assert!(serde_json::from_str::<ItemState>(&serde_json::to_string(&s).unwrap()).is_err());
    let mut json = serde_json::to_value(state()).unwrap();
    let known = json["known"].as_array_mut().unwrap();
    known.push(known[0].clone());
    assert!(serde_json::from_value::<ItemState>(json).is_err());
}
#[test]
fn slot_budget_round_trip_retains_snapshot_pins() {
    let mut b = SlotBudget::new(0);
    for n in 0..16 {
        b.reserve_snapshot(&format!("s{n}"));
    }
    let mut b: SlotBudget = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
    assert_eq!(
        b.reserve("checkpoint", SlotKind::Checkpoint),
        Reservation::Refused
    );
}

#[test]
fn convergence_cannot_inject_another_peers_future_vid() {
    let mut a = state();
    let mut from_b = incoming();
    from_b.value_fp = Some(f(1));
    from_b.lineage = Lineage::new([v(1), v(2), v(99)]);
    let Transition::Advance { head, lineage, .. } = run(&a, &from_b).transition else {
        panic!()
    };
    assert!(!lineage.contains(&v(99)));
    a.head = head;
    a.lineage = lineage;
    let mut from_c = incoming();
    from_c.new_vid = v(99);
    from_c.parents = vec![v(0)];
    from_c.value_fp = Some(f(3));
    let d = run(&a, &from_c);
    assert_eq!(d.ack, AckResult::Conflict);
    assert!(matches!(d.transition, Transition::Conflict { .. }));
}

#[test]
fn convergence_pins_both_heads_below_full_lineage() {
    let mut s = state();
    s.lineage = Lineage::new((100..164).map(v)).with_head(s.head);
    let mut i = incoming();
    i.value_fp = Some(f(1));
    for new_vid in [v(0), v(2)] {
        i.new_vid = new_vid;
        let Transition::Advance { head, lineage, .. } = run(&s, &i).transition else {
            panic!()
        };
        assert_eq!(head, s.head.max(new_vid));
        assert_eq!(lineage.len(), 64);
        assert!(lineage.contains(&s.head));
        assert!(lineage.contains(&new_vid));
    }
}

#[test]
fn approved_resolve_records_all_parents_and_late_candidates_are_stale() {
    let mut s = conflicted();
    let mut i = incoming();
    i.parents = vec![v(1), v(3), v(4), v(99)];
    i.lineage = Lineage::new([v(77)]);
    let d = decide(
        &s,
        f(1),
        &i,
        false,
        Some(&VerifiedApproval::for_tests()),
        true,
    );
    let Transition::Advance {
        head,
        lineage,
        clear_conflict: true,
        ..
    } = d.transition
    else {
        panic!()
    };
    assert!(lineage.contains(&v(77)));
    for parent in &i.parents {
        assert!(lineage.contains(parent));
    }
    s.head = head;
    s.lineage = lineage;
    s.conflict = None;
    for (vid, fp) in [(v(3), f(3)), (v(4), f(4)), (v(99), f(99))] {
        let late = Incoming {
            new_vid: vid,
            parents: vec![v(0)],
            value_fp: Some(fp),
            ..incoming()
        };
        let d = decide(&s, f(2), &late, false, None, true);
        assert_eq!(d.ack, AckResult::Applied);
        assert_eq!(d.transition, Transition::Unchanged);
    }
}

#[test]
fn approved_fast_forward_merges_sender_lineage() {
    let mut i = incoming();
    i.lineage = Lineage::new([v(99)]);
    let d = decide(
        &state(),
        f(1),
        &i,
        false,
        Some(&VerifiedApproval::for_tests()),
        true,
    );
    let Transition::Advance { lineage, .. } = d.transition else {
        panic!()
    };
    assert!(lineage.contains(&v(99)));
}

#[test]
fn slot_budget_shrink_preserves_slots_and_refuses_new_reservations() {
    let mut b = SlotBudget::new(5);
    for n in 0..20 {
        b.reserve(&format!("p{n}"), SlotKind::Proposal);
    }
    b.set_items(0);
    assert_eq!(b.capacity(), 16);
    assert_eq!(b.used(), 20);
    for n in 0..20 {
        assert_eq!(b.kind(&format!("p{n}")), Some(SlotKind::Proposal));
    }
    for kind in [
        SlotKind::Proposal,
        SlotKind::Held,
        SlotKind::ConflictCandidate,
        SlotKind::Checkpoint,
    ] {
        assert_eq!(b.reserve("new", kind), Reservation::Refused);
    }
    assert_eq!(
        b.reserve("p0", SlotKind::Proposal),
        Reservation::Reserved { evicted: None }
    );
    for n in 0..5 {
        assert!(b.release(&format!("p{n}")));
    }
    assert_eq!(
        b.reserve("held", SlotKind::Held),
        Reservation::Reserved { evicted: None }
    );
    b.set_items(6);
    assert_eq!(b.capacity(), 24);
    assert_eq!(
        b.reserve("new", SlotKind::Proposal),
        Reservation::Reserved { evicted: None }
    );
    b.set_items(usize::MAX);
    assert_eq!(b.capacity(), usize::MAX);
}

#[test]
fn prepare_hold_reserves_or_defers_without_eviction() {
    let mut b = SlotBudget::new(0);
    let OverwriteCapacity::Held(d) = b.prepare_hold("held", HoldReason::Frozen) else {
        panic!()
    };
    held(&d, HoldReason::Frozen);
    for n in 0..15 {
        b.reserve(&format!("p{n}"), SlotKind::Proposal);
    }
    let OverwriteCapacity::Deferred(d) = b.prepare_hold("new", HoldReason::NoApproval) else {
        panic!()
    };
    assert_eq!(d.ack, AckResult::DeferredCapacity);
    assert_eq!(d.transition, Transition::Unchanged);
    assert!(!d.ack.is_final());
    assert_eq!(b.used(), 16);
    assert_eq!(b.kind("new"), None);
    assert_eq!(b.kind("p0"), Some(SlotKind::Proposal));
    assert!(matches!(
        b.prepare_hold("held", HoldReason::NoApproval),
        OverwriteCapacity::Held(_)
    ));
}

#[test]
fn checkpoint_failure_reuses_existing_hold_at_capacity() {
    let mut b = SlotBudget::new(0);
    for n in 0..15 {
        b.reserve_snapshot(&format!("s{n}"));
    }
    b.reserve("held", SlotKind::Held);
    let OverwriteCapacity::Held(d) = b.prepare_overwrite("s0", "held") else {
        panic!()
    };
    held(&d, HoldReason::OverLimit);
    assert!(matches!(
        b.prepare_overwrite("s0", "new"),
        OverwriteCapacity::Deferred(_)
    ));
    assert_eq!(b.used(), 16);
}

#[test]
fn removing_one_scope_peer_preserves_generation_and_other_peers() {
    let mut g = Generations::default();
    g.rm("key").unwrap();
    g.accept("key", peer("a"));
    g.accept("key", peer("b"));
    g.accept("other", peer("a"));
    let (leave, target) = g.remove_peer("key", &peer("a")).unwrap();
    assert_eq!(target, peer("a"));
    assert_eq!(
        leave,
        Registration {
            name: "key".into(),
            generation: 1
        }
    );
    assert_eq!(g.generation("key"), 1);
    assert!(!g.includes("key", &peer("a")));
    assert!(g.includes("key", &peer("b")));
    assert!(g.includes("other", &peer("a")));
    assert_eq!(g.remove_peer("key", &peer("a")), None);
    assert_eq!(g.remove_peer("missing", &peer("a")), None);
    assert_eq!(g.accept("key", peer("a")).generation, 1);
}
