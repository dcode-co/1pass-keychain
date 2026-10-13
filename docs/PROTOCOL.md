# kc transfer protocol v1

`kc` moves secrets between the OS keychains of one person's devices. The relay
(`relay.1pass.dev`) passes opaque bytes between two devices for a few minutes,
and keeps a small inbox for devices that were paired before. It never sees
plaintext, keeps nothing beyond the TTLs below, and has no accounts.

The HTTP contract is frozen in `crates/kc-wire` (paths, limits, JSON types,
error codes). Crypto constants live in `crates/kc-proto`, with golden test
vectors. This document and those two crates change together.

## 1. Primitives

| Purpose | Choice |
|---|---|
| Password-authenticated key exchange | SPAKE2 over Ed25519 (`spake2` 0.4), **fixed roles**: `start_a` = receiver, `start_b` = sender. The crate is unaudited; see SECURITY.md |
| Key derivation | HKDF-SHA256 |
| Key confirmation | HMAC-SHA256, constant-time compare, checked before anything else is sent |
| Channel encryption | XChaCha20-Poly1305, random 24-byte nonce |
| Remembered-device messages | HPKE auth mode (RFC 9180): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 |
| Serialization inside encryption | postcard |
| Padding | encrypted plaintexts padded to a multiple of 4096 bytes |

## 2. Codes

- **One-shot transfer:** `<channel>-<even>-<odd>`, e.g. `4721-absurd-amulet`.
  The two words come from the PGP even and odd lists (16 bits).
- **Pairing** (`kc pair`, `--remember`): `<channel>-<even>-<odd>-<even>` (24 bits), e.g. `4721-absurd-amulet-apple`.
- **Input:**
  - Case-insensitive. `-` or whitespace separate the parts.
  - Words are checked locally against the lists, so a typo never burns the code.
  - The code is read from a prompt or from `--code -` (stdin), never from argv.
- **Canonical form:** lowercase, joined with `-`.

## 3. Channel session

`R` = receiver (shows the code), `S` = sender (enters it). After allocate or
join, every call carries `Authorization: Bearer <side_token>`; the token tells
the relay the caller's role.

1. R `POST /v1/channels` → `{channel, side_token, expires_at}`. R generates the words and shows the code.
2. S `POST /v1/channels/{c}/join` → `{side_token, expires_at}`.
   - A third join gets `409 crowded`. S reports "someone else used this code (possible interception)" and never retries automatically.
3. Both write their SPAKE2 message: R `start_a(pw, idA, idB)`, S `start_b(pw, idA, idB)`, then `PUT …/pake`. Both read the peer's `GET …/pake?wait=25` and call `finish` → `K`.
4. Derive the keys:
   ```
   T   = SHA-256("kc1-transcript" || u16be(channel) || lp(msgA) || lp(msgB))      lp(x) = u32be(len x) || x
   prk = HKDF-Extract(salt = T, ikm = K)
   kR  = Expand(prk, "kc1 confirm R"), kS = Expand(prk, "kc1 confirm S")
   kS2R = Expand(prk, "kc1 data S2R"),  kR2S = Expand(prk, "kc1 data R2S")
   sas = Expand(prk, "kc1 sas")   -> first 4 bytes -> 4 PGP words (pairing only)
   ```
   where `pw = "kc1:" || canonical code`, `idA = "kc1/receiver"`, `idB = "kc1/sender"`.
5. Confirm:
   - R writes `HMAC(kR, T)` to `confirm` and S writes `HMAC(kS, T)`.
   - Each side checks the peer's MAC in constant time **before** writing anything else.
   - On mismatch: R `DELETE ?reason=bad_confirm`, and both sides report "wrong code or interception" (exit 7).
6. S writes `payload = nonce(24) || XChaCha20-Poly1305(kS2R, nonce, pad(postcard(ChannelPayload)), aad)`.
7. R decrypts and shows the item names (and, for pairing, the SAS words and the sender's device label).
   - A human confirms; see §6 for when that's required.
   - R stores the accepted items, then writes `ack` sealed with `kR2S`.
8. S reads `ack` and reports. Both `DELETE ?reason=done`.

`aad = "kc1" || u16be(channel) || phase.byte() || role.byte() || T`.

### Session details

- **Closing after the ack:**
  - The receiver waits up to 15 s for the sender's `DELETE ?reason=done`.
  - If none comes, the receiver lets the channel expire instead of deleting it. Deleting could destroy an `ack` the sender is still retrying to read.
- **Bad MAC:**
  - The receiver keeps the channel up to 3 s before `DELETE ?reason=bad_confirm`, so the sender can still read the receiver's MAC and see the mismatch itself.
  - A sender whose channel closes while it waits for confirmation also reports a wrong code.
- **Pair offers** are accepted only over 3-word pairing codes, in both directions.
- **Item names in one payload must be unique.** A duplicate rejects the whole payload. So does an invalid `ItemName`, `Label` or device key from the peer.
- **`Rejected(u16)` codes:**

  | Code | Meaning |
  |---|---|
  | 1 | invalid item |
  | 2 | refused by policy (non-interactive, or declined by the user) |
  | 3 | keychain write failed |
  | 4 | too large for the local store |
`phase.byte()` and `role.byte()` are defined in `kc-wire`. The role is the writer's role.

### Structures (postcard, inside the encryption)

```text
ChannelPayload { v: 1, items: Vec<Item>, pair: Option<PairOffer> }
ChannelAck     { v: 1, results: Vec<ItemResult>, pair: Option<PairOffer> }
Item           { name: ItemName, value: bytes (zeroizing), updated_at: i64 unix secs }
ItemResult     { name, status: Stored | Unchanged | SkippedConflict | Renamed(ItemName) | Rejected(u16) }
PairOffer      { suggested_label: String, device_pk: [u8; 32], inbox_id: [u8; 16], writer_token: [u8; 32] }
```

- `ItemName` matches `^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`, with no `..` and no leading or trailing `/`.
- Labels are printable ASCII, at most 64 characters. They are checked when sent, received and displayed.

### Encoding details

- **Number types:** `v` is a `u8`. `created_at`, `expires_at` and `updated_at` are `i64` Unix seconds.
- **`ItemStatus`:** the postcard variant order is as listed above (`Stored` = 0 … `Rejected` = 4).
- **Padding:** `pad(x) = u32be(len x) || x || zeros` up to the next multiple of 4096. Unpadding rejects:
  - a total that isn't a multiple of 4096
  - a length that doesn't fit
  - non-zero padding
- **Tokens** (side, owner, writer):
  - 32 random bytes, sent as `Authorization: Bearer <b64url_nopad(raw)>`.
  - The relay decodes the token, hashes the **raw** bytes with SHA-256, and compares in constant time.
  - `writer_token_sha256 = b64url_nopad(SHA-256(raw))`.
- **Writer limit:** registering a 17th writer answers `507 inbox_full`.
- **`InboxEnvelope.suite = 1`:** DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305.
- **Fingerprint short form:** lowercase hex of the first 8 bytes, in 4 groups joined by `-`, e.g. `3f2a-91bc-0d4e-77a1`.
- **SAS:** 4 bytes become words from the even, odd, even and odd lists.

## 4. Remembered devices

- **Device key.**
  - An X25519 key pair; the secret key lives in the OS keychain (`sys:device-key`).
  - `fp = SHA-256(device_pk)`. The display form is the first 8 bytes in hex, in groups of 4.
- **Pairing.** Each side sends a `PairOffer` inside the channel:
  - the other side's writer token for our inbox, which we registered with `POST /v1/inboxes/{id}/writers`;
  - our inbox id;
  - our device key.
- **Labels.**
  - The receiving side picks the peer's label locally. The suggestion is sanitised and must be unique.
  - A label's key never changes unless you run `kc peers rm`.
  - Both screens show the same 4 SAS words.
- **Sending to a peer** (`kc send --to <label> --names …`) posts an HPKE auth-mode message to the peer's inbox with the writer token:
  ```text
  InboxEnvelope { v: 1, suite: u16, sender_fp: [u8;32], recipient_fp: [u8;32], enc: [u8;32], ct: bytes }
  aad  = postcard(header fields: v, suite, sender_fp, recipient_fp)
  info = "kc1 inbox" || sender_fp || recipient_fp
  plaintext = pad(postcard(InboxPlain { v: 1, msg_id: [u8;16], sender_fp, recipient_fp,
                                        created_at, expires_at (≤ created_at + 72h), items }))
  ```
- **Receiving** (`kc inbox`):
  - Reject a message if any of these hold:
    - `sender_fp` isn't a remembered peer
    - the outer and inner fingerprints differ
    - `recipient_fp` isn't ours
    - it has expired (±5 min clock skew)
    - its `msg_id` is already in the saved seen-set
  - Inbox imports never overwrite an existing item without an explicit flag.
- **Rotation.**
  - `kc device rotate` creates a new key and a new inbox, deletes the old inbox and asks you to re-pair.
  - The old private key is kept for 72 h to open messages already in flight.

### v2: sync-capable inbox messages

The outer postcard `InboxEnvelope` has exactly the v1 fields and order above;
only `v` changes to `2`. `suite` remains `1`. A v1 reader decodes the envelope
and rejects version `2` **before decryption**. `seal` and `open` remain v1-only;
`seal_v2` writes v2 and `open_any` accepts both, mapping v1 items to `Body::Items`.

```text
aad  = postcard(v: 2, suite: 1, sender_fp, recipient_fp)
info = "kc2 inbox" || sender_fp || recipient_fp
plaintext = pad(postcard(InboxPlain2 { v: 2, msg_id: [u8;16], sender_fp, recipient_fp,
                                      created_at: i64, expires_at: i64, body }))
Body = Items(Vec<Item>) | Sync(SyncMsg)
```

`enc` and `ct` are not part of AAD. HPKE auth mode and padding are unchanged.
The inner version must equal the outer version; a mismatch returns
`UnsupportedVersion(inner_v)`. Fingerprint, recipient, remembered-sender,
lifetime (0 through 72 hours on receive, 1 through 72 hours on send), 5-minute
clock skew, and replay checks are the same as v1. The encoded envelope must
fit the 256 KiB relay limit; `open_any` checks this before decoding. Duplicate
names in `Body::Items` reject the message as malformed. Values remain
zeroize-on-drop `SecretBytes`, including values in `Offer` and `Op::Put`.

The following field and variant orders are fixed by golden vectors:

```text
Vid         = [u8;16]
ItemKind    = Text | File
ChangeId    { name: ItemName, generation: u64, new_vid: Vid }
Op          = Put { kind: ItemKind, value: bytes } | Retire
Change      { name: ItemName, generation: u64, new_vid: Vid, parents: Vec<Vid>,
              lineage: Vec<Vid>, op: Op, approval_ref: Option<[u8;16]> }
AckResult   = Applied | Held | Conflict | StaleGeneration | DeferredCapacity | Rejected
DigestEntry { name: ItemName, generation: u64, head: Vid }
SyncMsg     = Hello { features: Vec<String>, is_reply: bool }
            | Offer { name: ItemName, known_generation: u64, vid: Vid, lineage: Vec<Vid>, kind: ItemKind, value: bytes }
            | Accept { name: ItemName, generation: u64 }
            | Leave { name: ItemName, generation: u64 }
            | Changes { changes: Vec<Change> }
            | Ack { results: Vec<(ChangeId, AckResult)> }
            | Digest { entries: Vec<DigestEntry> }
            | Approvals { docs: Vec<Vec<u8>> }
```

- Postcard discriminants: `Body::Items = 0`, `Sync = 1`; `SyncMsg::Hello = 0`
  through `Approvals = 7`; `Op::Put = 0`, `Retire = 1`; `AckResult::Applied = 0`
  through `Rejected = 5`; `ItemKind::Text = 0`, `File = 1`.
- v1 `Item` has no kind field. v2 sync defines `ItemKind` separately, with the
  store's text/file presentation meanings; the v1 `Item` layout is unchanged.
- `Vid` is 16 raw bytes in postcard and 32 hex characters in human-readable
  formats (lowercase when written), just like `MessageId`. Fresh Vids use the
  operating system CSPRNG. Generations use postcard's `u64` varint encoding.
- `Change.lineage` is limited to 64 entries on decode and validation. Names
  must be unique within a `Changes` batch. Either violation rejects the entire
  opened message as `Malformed`. `parents` are the sender's claimed direct
  parents; approval and application policy are outside this wire layer.
- `Approvals` holds opaque reserved documents; this layer does not interpret them.
- Unknown peers' v2 capabilities are probed with one `Hello`; other sync messages
  wait for its reply. Ordinary `send --to` stays v1. Sync changes must never be
  downgraded to v1 items. This negotiation policy is implemented above the codec.

Golden vectors in `crates/kc-proto/tests/inbox_v2/fixtures` freeze both body
postcard bytes and complete encrypted envelopes, including all enum variants.

## 5. Relay rules

- **Channels:** in memory.
  - The channel number is random in `1..=9999` and isn't reused while it's a tombstone.
  - The TTL is 600 s. Each role writes each phase once (`409 already_written`).
  - `payload` can only be written by S and `ack` only by R (`403 wrong_role`).
  - Per-phase size caps come from `kc-wire`.
  - Long-poll `GET` waits up to 25 s.
  - After `DELETE` or expiry, everything is discarded at once, and the channel answers `410` for 10 min, then `404`.
  - Global caps: 1000 channels and 32 MiB, else `503 capacity` with `Retry-After`.
- **Inboxes:** in SQLite.
  - Messages are ≤256 KiB. An inbox holds ≤20 messages and ≤4 MiB in total (`507 inbox_full`), and ≤16 writers.
  - Messages expire after 72 h. Inboxes unread for 30 days are deleted. At most 5000 inboxes.
  - The database stores only `H(inbox_id)` and `H(token)`, with `secure_delete=ON` and a page cap of about 256 MiB.
  - An unknown inbox and a wrong token both answer `401`.
- **Client IP:**
  - Taken from `X-Kc-Client-Ip`, which the kc Caddy block sets to `{remote_host}`, and trusted only from the Caddy network CIDR.
  - IPv6 addresses are grouped by /64.
- **Rate limits** (5 devices behind one home IP must be fine):
  - allocate/join: 20 per hour
  - inbox create: 5 per day
  - inbox reads: 120 per hour
  - writes: 60 per hour per writer
  - concurrent long-polls: ≤8 per IP
  - A 429 carries `Retry-After`; clients back off with jitter.
- **Logs:**
  - Logged: route template, status, latency, size bucket.
  - Not logged: IPs (or only an HMAC with an in-memory key that rotates daily), user agents, ids, tokens, bodies.
- **Responses:** carry `Cache-Control: no-store`.

## 6. Who may do what without a human

A prompt-injected agent must not be able to send secrets to a code an attacker
controls. A session is **interactive** only if stdin and stderr are both
terminals and none of `CI`, `CLAUDECODE` or `--no-input` is set.

| Action | Non-interactive (agents, scripts) | Interactive |
|---|---|---|
| `get`, `exec`, `list`, `set` (value from stdin) | allowed | allowed |
| `send --to <peer> --names …` | allowed | allowed |
| `inbox` | allowed, conflicts skipped | allowed |
| `send` with a code (named items only) | **refused, exit 5** unless the device config sets `agent_code_send = true` | allowed after showing names |
| `pair`, `--remember`, `--all`, overwrite on receive or inbox | **always refused, exit 5** (`agent_code_send` doesn't change this) | allowed after showing names and peer label/SAS |
| `receive` (shows a code) | allowed, conflicts skipped | allowed |

For sync, **L** means confirmation by a human on the local device through
Touch ID (or the OS password fallback), Windows Hello, or polkit. A terminal
prompt alone is not L. Missing, denied or unavailable L returns exit 5.

| Sync action | Non-interactive (agents, scripts) | Interactive |
|---|---|---|
| `sync`, `sync offer NAME` | allowed to queue/send changes and proposals within the already approved scope; no remote overwrite | same |
| `sync status`, `sync status --json`, `sync peer list` | allowed; no values displayed | allowed |
| `sync freeze` | allowed; holds incoming changes | allowed without L |
| `sync add NAME`, `sync rm NAME`, `sync peer add LABEL`, `sync peer rm LABEL` | refused, exit 5 | L required |
| `sync review` | refused, exit 5 | accepting proposals or held changes requires L; rejecting or leaving them for later does not |
| `sync resolve NAME --keep mine`, `sync resolve NAME --keep LABEL`, `sync restore-checkpoint NAME` | refused, exit 5 | L required |
| `sync status --confirm-checkpoint NAME`, `sync unfreeze` | refused, exit 5 | L required |

Nothing syncs by default. Agents can create proposals and queue/send changes,
but cannot enroll items, expand sharing scope or accept remote values. Phase 1
holds **every remote overwrite** for human review on the receiving device;
conflicts require explicit resolution. Even a resolution sent by another device
cannot bypass local review. Ordinary local writes such as `set` retain the
permissions above; their queued changes do not authorize a remote overwrite.

Without a TTY, kc never prompts. Operations that require interaction exit 5.

## 7. Using values without leaking them

- `kc get NAME` refuses to print to a terminal without `--reveal`.
- To pass a value to a program, prefer `kc exec --env VAR=NAME -- cmd …` or
  `VAR="$(kc get NAME)" cmd`. Agents must not print values, because their
  transcripts keep them.
- Never put a value in argv, e.g. `curl -H "…$(kc get X)"`: `/proc/*/cmdline`
  is world-readable.
- `kc get --check NAME` only sets the exit code. `kc get --fingerprint NAME`
  prints a short hash for comparing devices.

## 8. Exit codes

Defined in `kc_wire::exit`.

| Code | Meaning |
|---|---|
| 0 | ok |
| 2 | usage |
| 3 | not found |
| 4 | keychain unavailable |
| 5 | interaction required |
| 6 | relay unavailable or rate limited |
| 7 | auth failed (bad code or MAC, tampering, replay) |
| 8 | partial; for sync, work remains pending or blocked (proposals, held changes, conflicts, queued delivery, re-offer needed, frozen state, capacity, quarantine or a tripped limit) |
| 9 | expired |

## 9. Reserved for later phases

Signed sync approvals (A/A+) and FIDO2 verification are planned for Phase 1b;
the 1pass.dev phone approver is planned for Phase 2b. None ships in this
release. Phase 1 ignores signed approval documents and never uses them to
authorize an automatic overwrite.

The following approval lock is also reserved for phase 2:

`/v1/locks/*`: an approval lock for selected items. A key share is held by the
relay and released only after an authenticator code (TOTP) or a passkey
approval. The relay still never holds item values.
