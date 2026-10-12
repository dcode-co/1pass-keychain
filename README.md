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

## Commands

| Command | What it does |
|---|---|
| `kc set NAME` | store a value read from stdin or a hidden prompt (`--from-file PATH` for whole files) |
| `kc get NAME` | print a value (`--to-file PATH` writes it with mode 600) |
| `kc list [--verify]` / `kc rm NAME` | list or remove items |
| `kc adopt --service S [--account A] [--as NAME]` | copy an existing keychain item into kc |
| `kc receive` / `kc send [NAMES…]` | move items with a one-time code |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | remembered devices |

## Status

Early development. The protocol is in [docs/PROTOCOL.md](docs/PROTOCOL.md) and
the threat model in [docs/SECURITY.md](docs/SECURITY.md).

## License

MIT
