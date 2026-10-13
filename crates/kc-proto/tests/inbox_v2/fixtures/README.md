# Inbox v2 golden vectors

Each `*.body.hex` file contains the postcard bytes of `Body`. Each matching
`*.envelope.hex` contains the complete postcard `InboxEnvelope`, including
HPKE ciphertext and tag. Hex is lowercase, with a trailing newline.

Fixed inputs (synthetic, never production keys or secrets):

- Sender X25519 private-key bytes: `11` repeated 32 times.
- Recipient X25519 private-key bytes: `22` repeated 32 times.
- HPKE ephemeral RNG output: `33` repeated 32 times (the IKM passed to
  DHKEM's `DeriveKeyPair`, not a raw ephemeral private scalar).
- Message ID: `44` repeated 16 times.
- Created at: `1760000000`; TTL: `3600`; expires at: `1760003600`.
- Envelope and plaintext version: `2`; cipher suite: `1`.
- AAD: postcard `(2u8, 1u16, sender_fp, recipient_fp)`.
- Info: ASCII `kc2 inbox` followed by the two raw 32-byte fingerprints.
- Plaintext: 4-byte big-endian postcard length, postcard `InboxPlain2`, then
  zeros to 4096 bytes; HPKE adds a 16-byte tag.

The complete expected messages are declared in `../mod.rs::cases`. They cover
all eight SyncMsg discriminants, both Body and Op discriminants, both ItemKind
values, all six AckResult discriminants, and both approval_ref option cases.
`changes` contains both a Put and a Retire. The fixture files are read-only
inputs to tests; tests never rewrite them.

`../mod.rs` is included as `inbox::v2_tests` by `src/inbox.rs` under `cfg(test)`.
This lets ordinary `cargo test -p kc-proto` exercise the production sealing
path with fixed randomness without exposing a deterministic production API
or requiring the test-util feature.
