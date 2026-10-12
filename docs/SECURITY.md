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

The relay sees client IPs, timing and message sizes. It stores no account, no
long-term data, and only ciphertext: channel messages for at most 10 minutes,
inbox envelopes for at most 72 hours.

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
- **Planned approval lock (phase 2):** selected items will need an
  authenticator code or a passkey before they can be read.

## Reporting a vulnerability

Email support@1pass.dev. Please don't open a public issue for security reports.
