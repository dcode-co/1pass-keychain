#!/usr/bin/env bash
# Publishes a release to npm: one package per platform holding that platform's
# kc binary from the GitHub release, then the `1pass-keychain` package
# (npm/1pass-keychain) whose `kc` command runs the right one.
#
#   scripts/publish-npm.sh v0.1.0 [--dry-run]
#
# Needs `npm login` with publish rights, `gh`, `node` and `unzip`. Packages
# already published at this version are skipped, so a failed run can be
# repeated. Run it after the release is published, so the macOS binaries are
# the signed ones.
#
#   KC_REPO      [default: dcode-co/1pass-keychain]
#   NPM_CONFIG_OTP  a one-time password, if your npm account asks for one
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tag=${1:?usage: $0 vX.Y.Z [--dry-run]}
dry=${2:-}
repo=${KC_REPO:-dcode-co/1pass-keychain}
version=${tag#v}

if [ "$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft)" != false ]; then
  echo "$tag is not a published release" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh release download "$tag" --repo "$repo" --dir "$work/dist" \
  --pattern "kc-$tag-*" --pattern SHA256SUMS
(cd "$work/dist" && shasum -a 256 -c SHA256SUMS >/dev/null)

publish() {
  local dir=$1 name
  name=$(node -p 'require(process.argv[1]).name' "$dir/package.json")
  if npm view "$name@$version" version >/dev/null 2>&1; then
    echo "skip: $name@$version is already published"
    return
  fi
  if [ "$dry" = --dry-run ]; then
    (cd "$dir" && npm publish --access public --dry-run)
  else
    (cd "$dir" && npm publish --access public)
  fi
}

# target  platform  os  cpu
while read -r target platform os cpu; do
  pkg="1pass-keychain-$platform"
  dir="$work/$pkg"
  mkdir -p "$dir/bin"
  if [ "$os" = win32 ]; then
    unzip -q -j "$work/dist/kc-$tag-$target.zip" "kc-$tag-$target/kc.exe" -d "$dir/bin"
  else
    tar -xzf "$work/dist/kc-$tag-$target.tar.gz" -C "$dir/bin" --strip-components 1 "kc-$tag-$target/kc"
    chmod 755 "$dir/bin/kc"
  fi
  cp "$root/LICENSE" "$dir/"
  # shellcheck disable=SC2016 # ${...} below is a JavaScript template literal
  PKG=$pkg VERSION=$version OS=$os CPU=$cpu node -e '
    const e = process.env;
    console.log(JSON.stringify({
      name: e.PKG,
      version: e.VERSION,
      description: `The kc binary of 1pass-keychain for ${e.OS}-${e.CPU}. Install 1pass-keychain instead.`,
      homepage: "https://github.com/dcode-co/1pass-keychain#readme",
      repository: { type: "git", url: "git+https://github.com/dcode-co/1pass-keychain.git" },
      license: "MIT",
      os: [e.OS],
      cpu: [e.CPU],
      files: ["bin"],
    }, null, 2));
  ' > "$dir/package.json"
  publish "$dir"
done <<'EOF'
aarch64-apple-darwin darwin-arm64 darwin arm64
x86_64-apple-darwin darwin-x64 darwin x64
aarch64-unknown-linux-musl linux-arm64 linux arm64
x86_64-unknown-linux-musl linux-x64 linux x64
x86_64-pc-windows-msvc win32-x64 win32 x64
EOF

main="$work/1pass-keychain"
cp -R "$root/npm/1pass-keychain" "$main"
cp "$root/README.md" "$root/LICENSE" "$main/"
(cd "$main" && VERSION=$version node -e '
  const fs = require("fs");
  const p = JSON.parse(fs.readFileSync("package.json", "utf8"));
  p.version = process.env.VERSION;
  for (const dep of Object.keys(p.optionalDependencies)) p.optionalDependencies[dep] = process.env.VERSION;
  fs.writeFileSync("package.json", JSON.stringify(p, null, 2) + "\n");
')
publish "$main"
if [ "$dry" = --dry-run ]; then
  echo "npm (dry run): 1pass-keychain@$version and its 5 platform packages are ready"
else
  echo "npm: 1pass-keychain@$version and its 5 platform packages are published"
fi
