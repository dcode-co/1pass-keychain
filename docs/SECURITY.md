# Security model

## What kc protects

Secret values (API keys, tokens, `.env` files) while they move between devices
that belong to one person, and while they sit in each device's OS keychain.

## Trust boundaries

| Party | Trusted with | Not trusted with |
|---|---|---|
| Your devices and OS keychains | the values | — |
| The relay (`relay.1pass.dev`) | delivering bytes, keeping them only briefly | reading or changing values; it can drop or delay messages |
| The network | nothing | everything (TLS plus end-to-end encryption) |
| A paired sync device | proposing items and sending changes within the approved scope | authorizing an overwrite on the receiving device |

The relay sees client IPs, timing and message sizes. It stores no account, no
long-term data, and only ciphertext: channel messages for at most 10 minutes,
inbox envelopes for at most 72 hours.

Pairing does not enable sync: each item must be explicitly enrolled. A
compromised paired device can propose items and send changes, but cannot
overwrite a sync item's value without a human on the receiving device. Phase 1
holds every remote overwrite for review or conflict resolution. Local OS
confirmation (L) uses Touch ID (or the OS password fallback), Windows Hello,
or polkit; agents cannot supply this confirmation.

## Properties

- **Code pairing:** SPAKE2 with explicit key confirmation.
  - A passive relay learns nothing.
  - An active attacker gets one guess per code: 1 in 65,536 for a transfer code, 1 in 16.7 million for a pairing code.
  - A failed guess is visible to both people and burns the code.
- **Remembered devices:** inbox messages use HPKE auth mode (RFC 9180), which authenticates the sender's device key.
  - Envelopes carry an id and an expiry, and replays are dropped.
  - Each message uses a fresh ephemeral key, so a sender's leaked device key can't open its past messages. A leaked recipient key can open messages still waiting in that recipient's inbox. If a device is lost, rotate its key (`kc device rotate`) and re-pair the others.
- **Local handling:**
  - kc never reads values from command-line arguments or its own environment. `kc exec --env` hands a value to a child process's environment on purpose. Only the same user (and root) can read a process environment, unlike argv, which every local user can read.
  - Buffers are zeroized.
  - `kc get` refuses to print to a terminal without `--reveal`.
- **Sync storage:** persisted values stay in OS keychain slots, including held
  proposals, conflict candidates, outgoing snapshots and recovery checkpoints.
  Values never go into `sync.json` or `sync.log`; they are read into zeroizing
  memory for processing and end-to-end encrypted transport. Sync value
  fingerprints use HMAC-SHA256 with a device-local key kept in the keychain.
  They are not sent to peers or stored in public metadata; displayed sync
  fingerprints compare values on one device, not across devices.
- **Locked keychains:** kc reports an error instead of waiting on an OS unlock prompt, so unattended agents don't hang.

## Known limits

- **Unaudited PAKE crate:** the `spake2` crate has not had an independent
  audit. kc uses fixed roles (`start_a`/`start_b`), explicit key confirmation
  before anything else is sent, and direction-separated keys, so a reflected
  message fails.
- **No per-app access control on Linux and Windows:** any process running as
  the same user can read the user's keychain there. macOS restricts each item
  to the app that created it.
- **Linux keyring:** on some Linux setups the default keyring has no password
  (for example with auto-login). Values are then protected only by file
  permissions and disk encryption.
- **macOS prompts:** macOS can ask "allow access" when the `kc` binary changes.
  Release builds are code-signed so updates keep the same identity.
- **Changes outside kc:** an external keychain change from A to B and back to A
  between syncs cannot be detected.
- **Originating device lost:** devices send only changes they originate. If the
  originating device disappears, a human must re-send unreceived changes as a
  new local publication from a remaining copy.
- **Linux sync confirmation:** L currently uses polkit's
  `org.freedesktop.policykit.exec` action, which may ask for an administrator
  password. polkit only shows that action's generic text ("run a program as
  another user"), so kc prints what is being confirmed on the terminal first.
  The OS policy controls authentication and caching. A kc-specific
  policy is planned with the later sync installer; neither ships in Phase 1.
- **No signed sync approvals yet:** A/A+ and FIDO2 are Phase 1b work; the
  1pass.dev phone approver is Phase 2b work. They cannot authorize overwrites
  in this release.
- **Planned approval lock (phase 2):** selected items will need an
  authenticator code or a passkey before they can be read.

## Reporting a vulnerability

Email support@1pass.dev. Please don't open a public issue for security reports.
