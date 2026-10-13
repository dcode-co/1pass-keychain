# 1pass keychain (`kc`)

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
$ tar -xzf kc-v0.1.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.1.0-aarch64-apple-darwin/kc ~/.local/bin/kc
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
| `kc doctor` | check the keychain, the relay and the configuration |

## Status

Early release (v0.1). Tested on real machines:

- paired sends both ways between macOS and Linux, and between macOS and Windows 11
- a one-time-code send from macOS to Linux
- storing, reading and removing items in each OS keychain

Not yet tested on real machines: one-time-code sends from Linux or Windows.
The PAKE crate has not had an independent audit. The protocol is in
[docs/PROTOCOL.md](docs/PROTOCOL.md) and the threat model in
[docs/SECURITY.md](docs/SECURITY.md).

## License

MIT
