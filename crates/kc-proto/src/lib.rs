//! 1pass keychain transfer protocol, v1. See `docs/PROTOCOL.md`.
//!
//! This crate is the protocol logic with no I/O of its own:
//!
//! - [`code`]: the codes people type (`4721-absurd-amulet`), built on [`words`].
//! - [`pake`]: SPAKE2, the key schedule, key confirmation and channel encryption.
//! - [`payload`]: what travels inside the encryption (postcard, padded).
//! - [`device`] and [`inbox`]: remembered devices and their HPKE inbox messages.
//! - [`relay`]: the [`relay::RelayApi`] trait. `kc-cli` implements it over HTTP.
//! - [`session`]: the receiver and sender flows over any `RelayApi`.
//!
//! The HTTP contract itself is the frozen `kc-wire` crate, re-exported as [`wire`].
//!
//! # Memory hygiene
//!
//! Wiped on drop: item values ([`SecretBytes`]), codes and the SPAKE2 password
//! we build, the shared key `K`, the HKDF PRK and every derived channel key,
//! decrypted plaintext buffers, writer tokens, side tokens held by sessions,
//! and the device secret key (inside `hpke`'s `StaticSecret`). SHA-256 and
//! HMAC states are wiped through the `sha2`/`hmac` `zeroize` features.
//!
//! Not wiped, because they live inside dependencies we can't change without
//! `unsafe` or a fork: the password and scalar copies that `spake2` 0.4 keeps,
//! the padded-key scratch block in `hmac`'s key setup, and the HKDF
//! intermediates inside `hpke`. These are short-lived stack and heap copies
//! in a short-lived process.
#![forbid(unsafe_code)]

pub use kc_wire as wire;

mod aead;
pub mod code;
pub mod device;
pub mod inbox;
pub mod names;
mod pad;
pub mod pake;
pub mod payload;
pub mod relay;
mod rng;
pub mod secret;
pub mod session;
pub mod words;

#[cfg(any(test, feature = "test-util"))]
pub mod memory_relay;

pub use code::{Code, CodeError, CodeKind};
pub use device::{DeviceKeyPair, DevicePublicKey, Fingerprint};
pub use names::{ItemName, Label};
pub use payload::{ChannelAck, ChannelPayload, Item, ItemResult, ItemStatus, PairOffer};
pub use secret::SecretBytes;
