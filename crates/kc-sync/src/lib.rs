//! Side-effect-free `kc sync` policy from docs/design/sync.md §§2, 4, 12.2–12.5.
//! Callers own authentication, durable storage, locks, fingerprints, and ACK delivery.
//! A returned transition is an intent: ACK only after its durable commit (§12.4).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod decision;
mod generation;
mod limiter;
mod outbox;
mod recovery;
mod slots;
mod state;

pub use decision::*;
pub use generation::*;
pub use limiter::*;
pub use outbox::*;
pub use recovery::*;
pub use slots::*;
pub use state::*;
