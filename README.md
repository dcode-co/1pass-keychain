# 1pass keychain (`kc`)

**English** · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-Hans.md) · [繁體中文](README.zh-Hant.md) · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md)

Move secrets between **your own devices' OS keychains** — macOS Keychain,
Linux Secret Service and Windows Credential Manager — at the moment you need
them, without a cloud vault.

```console
# on the new machine
$ kc receive
Code: 4721-absurd-amulet   (waiting up to 10 minutes)

# on a machine that has the keys
$ kc send GITHUB_TOKEN RENDER_API_KEY
Code: 4721-absurd-amulet
Sent 2 items. omarchy accepted 2.
```

- **Nothing is stored in the cloud.** The relay (`relay.1pass.dev`) passes
  end-to-end encrypted bytes between two devices and forgets them within
  minutes. It never sees plaintext.
- **No account.** A one-time code authenticates the two devices (SPAKE2, the
  same idea as magic-wormhole). A wrong guess burns the code.
- **Remembered devices.** Pair once with `--remember`. After that,
  `kc send NAME --to omarchy` works without a code, even if the other device
  is offline for up to 72 hours.
- **Bulk moves.** Run `kc send` with no names to pick items from a checklist,
  or use `--bundle new-machine.toml`.
- **Agent friendly.** `kc get NAME` prints a secret to a pipe for scripts and
  AI agents. It never blocks on a GUI unlock prompt, and it won't print to a
  terminal without `--reveal`.

## Install

With [Homebrew](https://brew.sh) on macOS or Linux:

```console
$ brew install dcode-co/tap/kc
```

With npm or [Bun](https://bun.sh) on macOS, Linux or Windows. The package is
`1pass-keychain`; the command it installs is `kc`:

```console
$ npm install -g 1pass-keychain        # or: bun install -g 1pass-keychain
$ npx 1pass-keychain doctor            # or: bunx 1pass-keychain doctor (no install)
```

Or download the archive for your system from
[Releases](https://github.com/dcode-co/1pass-keychain/releases) and put `kc`
on your `PATH`:

| System | Archive |
|---|---|
| macOS, Apple silicon | `kc-<version>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `kc-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (static, any distribution) | `kc-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (static, any distribution) | `kc-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `kc-<version>-x86_64-pc-windows-msvc.zip` |

```console
$ tar -xzf kc-v0.2.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.2.0-aarch64-apple-darwin/kc ~/.local/bin/kc
$ kc doctor
```

`SHA256SUMS` in the release lists every archive's checksum. The macOS binaries
are signed with a Developer ID and notarized by Apple.

`kc doctor` checks the keychain, the relay and the configuration.

**Linux** needs a running Secret Service, such as gnome-keyring. Desktop
installs usually have one; a headless server or a minimal install may not.

**Windows**: Credential Manager isn't available in an SSH session that logged
in with a key, so run kc from a desktop session.

To build from source instead, use Rust 1.88 or newer:

```console
$ cargo install --locked --git https://github.com/dcode-co/1pass-keychain kc-cli
```

## First use: set up a new machine

1. On the machine that has the secret, store it once:

   ```console
   $ kc set GITHUB_TOKEN              # asks for the value; it never echoes
   $ kc set SSH_DEPLOY_KEY --from-file ~/.ssh/deploy_key
   $ kc adopt --service my-cli        # or copy an entry another tool already keeps
   ```

2. On the new machine, run `kc receive`. It shows a code like `4721-absurd-amulet`.
3. Back on the first machine, run `kc send GITHUB_TOKEN SSH_DEPLOY_KEY` and type
   that code. Both machines show what was sent and stored.
4. On the new machine, use the values:

   ```console
   $ kc get SSH_DEPLOY_KEY --to-file ~/.ssh/deploy_key   # written with mode 600
   $ kc exec --env GITHUB_TOKEN=GITHUB_TOKEN -- gh repo list
   ```

A code works once, for 10 minutes. Sending with a code needs a person at a
terminal; scripts and agents send to remembered devices instead.

## Remembered devices

Pair two machines once, and later sends need no code:

```console
laptop$  kc pair              # shows a pairing code
desktop$ kc pair --join       # type that code
```

Each side remembers the other under a **label**, by default its host name.
`kc peers` lists them; the `LABEL` column is what `--to` takes:

```console
laptop$ kc peers
LABEL    FINGERPRINT          PAIRED
desktop  0faf-98f4-0dfe-7133  2026-10-12T13:08:13Z

laptop$ kc send GITHUB_TOKEN --to desktop    # works while desktop is off
desktop$ kc inbox                            # stores what arrived (kept up to 72 hours)
```

`kc device rename` changes the label this machine suggests when pairing.
`kc peers rm LABEL` unpairs a device; run it on your other machines if one is
lost. See [docs/SECURITY.md](docs/SECURITY.md) for when to use `kc device rotate`.

## Sync

Sync keeps selected items shared between paired devices. **Nothing syncs by
default.** Replace `NAME` with an existing item name:

```console
$ kc sync add NAME          # enroll and offer to paired devices
$ kc sync                   # run on both devices to exchange changes
$ kc sync review            # on the receiving device: review proposals and held changes
$ kc sync status            # show state and local fingerprints, never values
```

This release holds every remote overwrite for review. Every sync step that applies
a value asks for local OS confirmation: Touch ID (or the OS password fallback),
Windows Hello, or polkit. Enrollment also requires this confirmation; ordinary
local writes can queue changes without authorizing an overwrite elsewhere.
Conflicts preserve candidate values: use `kc sync resolve NAME --keep mine`
or `kc sync resolve NAME --keep LABEL` to choose a version. Other devices still
review the result. `kc sync freeze` holds incoming changes without confirmation;
`kc sync unfreeze` requires OS confirmation. Exit 8 means pending or blocked
work remains. See [the security limits](docs/SECURITY.md).

## Commands

| Command | What it does |
|---|---|
| `kc set NAME` | store a value read from stdin or a hidden prompt (`--from-file PATH` for whole files) |
| `kc get NAME` | print a value to a pipe (`--to-file PATH` writes it with mode 600, `--reveal` prints to a terminal) |
| `kc exec --env VAR=NAME -- CMD…` | run a command with values in its environment, without a shell |
| `kc list [--verify]` / `kc rm NAME` / `kc restore NAME` | list, remove, or undo the last overwrite |
| `kc adopt --service S [--account A] [--as NAME]` | copy an existing keychain item into kc |
| `kc receive` / `kc send [NAMES…]` | move items with a one-time code |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | remembered devices |
| `kc sync` | sync selected items with paired devices |
| `kc doctor` | check the keychain, the relay and the configuration |

## Troubleshooting

- **`kc doctor` shows `device FAIL: the OS keychain refused access`** (macOS).
  The keychain asks before a different kc binary reads items another one
  stored, for example after switching between Homebrew, npm and a source
  build. Run the failing command (or `kc doctor`) in a terminal once and choose
  **Always Allow**; `kc --help` and `kc --version` don't touch the keychain.
  Scripts and agents can't answer that prompt, so do it before they run.
- **`kc: … is missing. Reinstall 1pass-keychain with optional dependencies
  enabled`** (npm or Bun). The binary comes in a per-platform package that
  npm installs as an optional dependency: `1pass-keychain-darwin-arm64`,
  `-darwin-x64`, `-linux-arm64`, `-linux-x64`, and `@1pass/keychain-win32-x64`
  for Windows. Installing with `--omit=optional` (or `--no-optional`) leaves
  it out; reinstall without that flag.
- **macOS over SSH: the keychain is locked or unavailable.** macOS keeps the
  login keychain locked in an SSH login, so no keychain prompt can appear
  there. Run kc in a Terminal on the Mac itself, or first run
  `security unlock-keychain ~/Library/Keychains/login.keychain-db` in the SSH
  session (it asks for the Mac's login password).
- **Windows: `no Credential Manager logon session`.** Credential Manager
  doesn't exist in an SSH session that logged in with a key. Run kc from a
  desktop session, or connect over SSH with a password.
- **Linux: the keychain is unavailable.** Start a Secret Service (for example
  gnome-keyring) and unlock it; `kc doctor` says which part is missing.
- **Messages in the wrong language.** Set `KC_LANG` (see Languages below).
  When neither stdout nor stderr is a terminal (scripts, agents), kc writes
  English unless `KC_LANG` is set.

## Languages

kc's messages and `kc --help` come in English, 한국어, 日本語, 简体中文, 繁體中文,
Español, Français and Deutsch. At a terminal kc follows your locale (`LC_ALL`,
`LC_MESSAGES`, `LANG` and `LANGUAGE`, then the system language). Scripts and
agents get English unless `KC_LANG` is set. Pick one with `KC_LANG`:

```console
$ KC_LANG=ko kc doctor
```

`KC_LANG` takes `en`, `ko`, `ja`, `zh-Hans`, `zh-Hant`, `es`, `fr` or `de`.
Values, item names, codes and JSON output are never translated.

## Status

Early release (v0.2). Tested on real machines:

- paired sends both ways between macOS and Linux, and between macOS and Windows 11
- a one-time-code send from macOS to Linux
- storing, reading and removing items in each OS keychain

Not yet tested on real machines: one-time-code sends from Linux or Windows.
The PAKE crate has not had an independent audit. The protocol is in
[docs/PROTOCOL.md](docs/PROTOCOL.md) and the threat model in
[docs/SECURITY.md](docs/SECURITY.md).

Maintainers: releasing steps and known pitfalls are in
[docs/RELEASING.md](docs/RELEASING.md).

## License

MIT
