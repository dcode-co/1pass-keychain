use serde::{Deserialize, Serialize};
use crate::{AckResult, ChangeId, Fp, Lineage, PeerId, Vid};

/// Complete remote transaction intent, persisted before slots or keychain writes (§12.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteJournalRecord {
    /// Exact acknowledged change (§12.4).
    pub change_id: ChangeId,
    /// Authenticated source peer (§12.4).
    pub sender: PeerId,
    /// Fingerprint before the intended write (§12.4).
    pub prev_fp: Fp,
    /// Intended fingerprint after the write (§12.4).
    pub new_fp: Fp,
    /// Head installed at step 4 (§12.4).
    pub head: Vid,
    /// Lineage installed at step 4 (§12.4).
    pub lineage: Lineage,
    /// Verified approval consumption key, absent for human-reviewed Phase 1 changes (§12.4).
    pub approval_key: Option<String>,
    /// ACK queued only after step 4 commits (§12.4).
    pub ack: AckResult,
    /// Recovery baseline slot reserved before writing (§12.4).
    pub checkpoint_slot: Option<String>,
    /// Slot holding the intended incoming value (§12.4).
    pub candidate_slot: String,
}

/// Receiver-specific queued target captured by the local transaction (§12.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueTarget {
    /// Destination peer (§12.4).
    pub peer: PeerId,
    /// Generation granted by this destination (§12.2, §12.4).
    pub generation: u64,
}

/// Complete local-change intent, including snapshot and target generations (§12.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalJournalRecord {
    /// Changed item name (§12.4).
    pub name: String,
    /// Previous keychain fingerprint (§12.4).
    pub prev_fp: Fp,
    /// Newly written or observed fingerprint (§12.4).
    pub new_fp: Fp,
    /// Caller-generated immutable version (§12.4).
    pub new_vid: Vid,
    /// Direct parents captured before writing (§12.4).
    pub parents: Vec<Vid>,
    /// Outbound value snapshot retained while queues reference it (§12.4).
    pub snapshot_slot: String,
    /// Exact destination peers and their registration generations (§12.4).
    pub targets: Vec<QueueTarget>,
}

/// Recovery action for a remote transaction; never overwrites unrelated current values (§12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteRecovery {
    /// Write happened: finish metadata, approval consumption, and ACK queue (§12.4).
    FinishFromStep4,
    /// Write did not happen: clear intent and retry (§12.4).
    Retry,
    /// Another value is current: preserve it and record a conflict (§12.4).
    Conflict,
}

/// Classifies a remote journal by fingerprint, with intended-value equality taking precedence (§12.4).
pub fn recover_remote(record: &RemoteJournalRecord, current_fp: Fp) -> RemoteRecovery {
    if current_fp == record.new_fp { RemoteRecovery::FinishFromStep4 }
    else if current_fp == record.prev_fp { RemoteRecovery::Retry }
    else { RemoteRecovery::Conflict }
}

/// Exactly the six local-journal recovery rows, in design-table order (§12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRecovery {
    /// Row 1: copy current value into the missing snapshot, then commit and clean journal (§12.4).
    RebuildSnapshotAndCommit,
    /// Row 2: existing snapshot is ready; commit metadata then clean journal (§12.4).
    Commit,
    /// Row 3: already committed and value matches; clean journal only (§12.4).
    CleanJournal,
    /// Row 4: retain queued snapshot, clean journal, and scan current value as a new version (§12.4).
    KeepSnapshotAndScan,
    /// Row 5: write never happened; delete any unreferenced snapshot and clean journal (§12.4).
    DiscardSnapshot,
    /// Row 6: discard uncommitted snapshot, clean journal, and scan current value (§12.4).
    DiscardSnapshotAndScan,
}

/// Classifies all six rows; `committed` means stored head equals the journal's new vid (§12.4).
pub fn recover_local(prev_fp: Fp, new_fp: Fp, current_fp: Fp, committed: bool, snapshot_exists: bool) -> LocalRecovery {
    if current_fp == new_fp {
        if committed { LocalRecovery::CleanJournal }
        else if snapshot_exists { LocalRecovery::Commit }
        else { LocalRecovery::RebuildSnapshotAndCommit }
    } else if committed { LocalRecovery::KeepSnapshotAndScan }
    else if current_fp == prev_fp { LocalRecovery::DiscardSnapshot }
    else { LocalRecovery::DiscardSnapshotAndScan }
}
