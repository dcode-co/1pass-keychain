use crate::{ConflictSet, Fp, Incoming, ItemState, Lineage, Vid, VidRecord};
use serde::{Deserialize, Serialize};

/// ACK discriminant order is the frozen sync contract (§12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckResult {
    /// Durable application, convergence, or already-seen version (§12.5).
    Applied,
    /// Durably retained for human review (§12.3).
    Held,
    /// Durably retained as a conflict (§2.4).
    Conflict,
    /// Receiver generation does not match (§12.2).
    StaleGeneration,
    /// Not retained; sender must retry and keep its snapshot (§12.3).
    DeferredCapacity,
    /// Rejected, including immutable-vid violations (§12.5).
    Rejected,
}

impl AckResult {
    /// Only capacity deferral is non-final (§12.3).
    pub fn is_final(self) -> bool {
        self != Self::DeferredCapacity
    }
}

/// Evidence supplied only by an external approval verifier; Phase 1 always uses `None` (§12.5).
#[derive(Debug)]
pub struct VerifiedApproval {
    _private: (),
}

impl VerifiedApproval {
    /// Test-only escape hatch; never call in production Phase 1 code (§12.5).
    #[doc(hidden)]
    pub fn for_tests() -> Self {
        Self { _private: () }
    }
}

/// Human-review reason in decision precedence order (§12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldReason {
    /// Receiver or peer is frozen (§4, §12.5).
    Frozen,
    /// No verified approval authorizes the operation (§12.5).
    NoApproval,
    /// Rate or checkpoint capacity prevents application (§4, §12.3).
    OverLimit,
    /// Complete Phase-1 resolve requires review (§2.4, §12.5).
    Resolve,
}

/// Side-effect-free state intent; persistence and slot allocation precede ACK (§12.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transition {
    /// Preserve state for stale, rejected, duplicate, or capacity-deferred messages (§12.5).
    Unchanged,
    /// Preserve the incoming value in a held slot (§12.3).
    Hold {
        /// Why human review is required (§12.5).
        reason: HoldReason,
    },
    /// Retain the complete unresolved candidate set without overwriting (§2.4).
    Conflict {
        /// Includes the receiver's current head and the incoming Put, if any (§2.4).
        candidates: ConflictSet,
    },
    /// Update version metadata, optionally writing the incoming value (§2.2, §12.4).
    Advance {
        /// Deterministic resulting head (§2.2).
        head: Vid,
        /// Merged ancestry with the resulting head retained (§2.4).
        lineage: Lineage,
        /// False for same-value convergence (§2.2).
        write_value: bool,
        /// Clear all candidates only after a complete approved resolve (§2.4).
        clear_conflict: bool,
    },
    /// Remove registration only; caller retains the keychain value (§2.5, §12.2).
    Retire,
}

/// Ordered decision and required ACK; caller must commit before sending it (§12.4, §12.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Result to ACK after durable handling (§12.3).
    pub ack: AckResult,
    /// Resulting state intent (§12.5).
    pub transition: Transition,
    /// Quarantine this peer's stream for this item on immutable-vid violation (§2.2).
    pub quarantine: bool,
}

impl Decision {
    pub(crate) fn held(reason: HoldReason) -> Self {
        Self {
            ack: AckResult::Held,
            transition: Transition::Hold { reason },
            quarantine: false,
        }
    }

    pub(crate) fn unchanged(ack: AckResult) -> Self {
        Self {
            ack,
            transition: Transition::Unchanged,
            quarantine: false,
        }
    }
}

fn conflict(state: &ItemState, current_fp: Fp, incoming: &Incoming) -> Decision {
    let mut candidates = state.conflict.clone().unwrap_or_default();
    candidates
        .candidates
        .entry(state.head)
        .or_insert_with(|| VidRecord {
            fp: current_fp,
            parents: state
                .record(&state.head)
                .map(|r| r.parents.clone())
                .unwrap_or_default(),
        });
    if let Some(fp) = incoming.value_fp {
        candidates.candidates.insert(
            incoming.new_vid,
            VidRecord {
                fp,
                parents: incoming.parents.clone(),
            },
        );
    }
    Decision {
        ack: AckResult::Conflict,
        transition: Transition::Conflict { candidates },
        quarantine: false,
    }
}

fn advance(state: &ItemState, incoming: &Incoming, convergence: bool, resolve: bool) -> Decision {
    if incoming.retire {
        return Decision {
            ack: AckResult::Applied,
            transition: Transition::Retire,
            quarantine: false,
        };
    }
    let head = if convergence {
        state.head.max(incoming.new_vid)
    } else {
        incoming.new_vid
    };
    let lineage = Lineage::merge(&state.lineage, &incoming.lineage);
    let lineage = Lineage::new(
        lineage
            .iter()
            .copied()
            .chain([state.head, incoming.new_vid]),
    )
    .with_head(head);
    Decision {
        ack: AckResult::Applied,
        quarantine: false,
        transition: Transition::Advance {
            head,
            lineage,
            write_value: !convergence,
            clear_conflict: resolve,
        },
    }
}

/// Implements the first-match table, rows 1–9, including resolve and non-deleting Retire (§12.5).
pub fn decide(
    state: &ItemState,
    current_fp: Fp,
    incoming: &Incoming,
    frozen: bool,
    approval: Option<&VerifiedApproval>,
    within_limits: bool,
) -> Decision {
    // Rows 1 and 2 deliberately outrank all other conditions.
    if incoming.generation != state.generation {
        return Decision::unchanged(AckResult::StaleGeneration);
    }
    if frozen {
        return Decision::held(HoldReason::Frozen);
    }
    // Row 3: consult all retained immutable bindings, not just the head.
    let violation = state
        .record(&incoming.new_vid)
        .is_some_and(|r| incoming.value_fp != Some(r.fp) || incoming.parents != r.parents)
        || (incoming.new_vid == state.head && incoming.value_fp != Some(current_fp));
    if violation {
        return Decision {
            ack: AckResult::Rejected,
            transition: Transition::Unchanged,
            quarantine: true,
        };
    }
    // Row 4: an already-known ancestor is acknowledged without another write.
    if incoming.new_vid == state.head || state.lineage.contains(&incoming.new_vid) {
        return Decision::unchanged(AckResult::Applied);
    }
    // Malformed operations cannot reach any value-writing transition.
    if incoming.retire == incoming.value_fp.is_some() {
        return Decision::unchanged(AckResult::Rejected);
    }
    // Retire has no candidate value; without approval it can only request review (§2.5).
    if incoming.retire && approval.is_none() {
        return Decision::held(HoldReason::NoApproval);
    }
    // Row 5: complete parent coverage is necessary even with a verified approval.
    if let Some(candidates) = &state.conflict {
        let complete = incoming.parents.contains(&state.head)
            && candidates
                .candidates
                .keys()
                .all(|vid| incoming.parents.contains(vid));
        if !complete {
            return conflict(state, current_fp, incoming);
        }
        if approval.is_none() {
            return Decision::held(HoldReason::Resolve);
        }
        if !within_limits {
            return Decision::held(HoldReason::OverLimit);
        }
        return advance(state, incoming, false, true);
    }
    // A resolve can reach a peer which never saw the competing changes. Its only
    // unresolved head is its current one; complete multi-parent coverage still requires
    // review in Phase 1, including when the selected value already matches (§2.4).
    if incoming.parents.len() > 1 && incoming.parents.contains(&state.head) && approval.is_none() {
        return Decision::held(HoldReason::Resolve);
    }
    // Row 6 is metadata-only convergence; Retire has no value to converge.
    if incoming.value_fp == Some(current_fp) {
        return advance(state, incoming, true, false);
    }
    let direct = incoming.parents.as_slice() == [state.head];
    // Row 7: callers cannot substitute claimed lineage for signed direct parents.
    if direct && approval.is_some() && within_limits {
        return advance(state, incoming, false, false);
    }
    // Row 8; an unapproved Retire is always review-only (§2.5).
    if direct || (incoming.retire && approval.is_none()) {
        return Decision::held(if approval.is_none() {
            HoldReason::NoApproval
        } else {
            HoldReason::OverLimit
        });
    }
    // Row 9.
    conflict(state, current_fp, incoming)
}
