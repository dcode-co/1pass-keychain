# Releasing kc

How a version goes out, and what went wrong the first times. Each script's
header has its own options and environment variables.

## Steps

1. In the workspace `Cargo.toml`, bump `version` and the `version` of
   `kc-wire`, `kc-proto` and `kc-store` under `[workspace.dependencies]`. Run
   `cargo check` so `Cargo.lock` follows (release builds use `--locked`), and
   merge both files to `main`.
2. Push the tag (`git tag v0.2.0 && git push origin v0.2.0`).
   `.github/workflows/release.yml` checks that the tag matches the workspace
   version, builds the five targets and opens a **draft** release with
   `SHA256SUMS`.
3. On a Mac with the Developer ID certificate:
   `scripts/release-sign-macos.sh v0.2.0 --publish`. It signs and notarizes the
   macOS binaries, replaces them in the draft, publishes the release and
   updates the Homebrew formula (`scripts/update-homebrew-tap.sh`).
4. npm: `scripts/publish-npm.sh v0.2.0 --dry-run`, then without `--dry-run`.
   Run it after step 3, so npm gets the signed macOS binaries.
5. Check what people get:
   - `brew install dcode-co/tap/kc` (or `brew upgrade kc`), then `kc --version`
   - `npm install 1pass-keychain@<version>` in an empty directory, then
     `npx kc --version` and `KC_LANG=ko npx kc --help`

## npm

The `1pass-keychain` package holds only `bin/kc.js`; the binary comes from one
optional dependency per platform:

| Platform | Package |
|---|---|
| macOS arm64 | `1pass-keychain-darwin-arm64` |
| macOS x64 | `1pass-keychain-darwin-x64` |
| Linux arm64 | `1pass-keychain-linux-arm64` |
| Linux x64 | `1pass-keychain-linux-x64` |
| Windows x64 | `@1pass/keychain-win32-x64` |

Things that have bitten us:

- **Spam detection.** npm rejected the name `1pass-keychain-win32-x64` with
  `403 … Package name triggered spam detection`, and again four minutes
  later. The Windows package therefore lives in the `@1pass` scope, which the
  publishing account owns. A new platform package should get a scoped name
  from the start.
- **New packages appear late.** The first publish of a new package shows only
  `0.0.0-stage` in `npm view` for one to five minutes before the real version
  is visible. Don't republish in that window; wait and check again.
- **One-time passwords.** With 2FA on, `npm publish` asks for a code at a
  terminal. Without one (a script, an agent, Claude Code's `!`) it fails with
  `EOTP`. Pass `NPM_CONFIG_OTP=<code>`; a code may expire partway through, so
  rerun with a new one. The script skips packages already published at this
  version, so reruns are safe. A granular token that bypasses 2FA also works:
  put it in a temporary `npmrc` (mode 600) passed with `NPM_CONFIG_USERCONFIG`,
  never on the command line, and delete the file afterwards. A token limited to
  selected packages can't create a new package, so new platform packages need
  a token for all packages (or the scope).
- **Order.** Platform packages go first and `1pass-keychain` last, so its
  optional dependencies already exist when it appears.

## CI

A red check blocks the merge, even when the change can't have caused it.
Rerun the failed job (`gh run rerun <id> --failed`) to tell a flaky test from a
real failure, and fix a test that fails by chance instead of rerunning it
forever. `backend::tests::a_timed_out_call_that_panics_is_still_settled`
(kc-store) was such a test: its worker slept 100 ms against a 20 ms timeout,
and a busy macOS runner let the panic win. Its worker now panics only after the
caller has timed out and signals it, so the order is fixed (PR #8).
