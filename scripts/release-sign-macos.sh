#!/usr/bin/env bash
# Signs and notarizes the macOS binaries of a draft release made by
# .github/workflows/release.yml, uploads them over the unsigned ones and
# updates SHA256SUMS. With --publish it then publishes the draft.
#
#   scripts/release-sign-macos.sh v0.1.0 [--publish]
#
# Needs a Mac with the Developer ID Application certificate in the keychain,
# an App Store Connect API key for notarytool, and `gh` logged in with write
# access to the repository:
#
#   KC_SIGN_IDENTITY   e.g. "Developer ID Application: Example (TEAMID)"
#   KC_NOTARY_KEY_ID   App Store Connect API key id
#   KC_NOTARY_ISSUER   its issuer id
#   KC_NOTARY_KEY      path to the .p8 file
#                      [default: ~/.appstoreconnect/private_keys/AuthKey_$KC_NOTARY_KEY_ID.p8]
#   KC_REPO            [default: dcode-co/1pass-keychain]
#
# The code-signing identifier stays dev.1pass.kc across releases, so macOS
# keeps the keychain access a user already granted to kc.
set -euo pipefail

tag=${1:?usage: $0 vX.Y.Z [--publish]}
publish=${2:-}
repo=${KC_REPO:-dcode-co/1pass-keychain}
identity=${KC_SIGN_IDENTITY:?set KC_SIGN_IDENTITY}
key_id=${KC_NOTARY_KEY_ID:?set KC_NOTARY_KEY_ID}
issuer=${KC_NOTARY_ISSUER:?set KC_NOTARY_ISSUER}
key=${KC_NOTARY_KEY:-$HOME/.appstoreconnect/private_keys/AuthKey_$key_id.p8}
[ -r "$key" ] || { echo "notary key not readable: $key" >&2; exit 1; }
key="$(cd "$(dirname "$key")" && pwd)/$(basename "$key")"  # the script cd's below

if [ "$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft)" != true ]; then
  echo "$tag is not a draft release; refusing to replace published assets" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
gh release download "$tag" --repo "$repo" --pattern 'kc-*-apple-darwin.tar.gz' --pattern SHA256SUMS

shopt -s nullglob
archives=(kc-*-apple-darwin.tar.gz)
[ ${#archives[@]} -gt 0 ] || { echo "no macOS archives in $tag" >&2; exit 1; }

for archive in "${archives[@]}"; do
  dir=${archive%.tar.gz}
  tar -xzf "$archive"
  bin="$dir/kc"
  codesign --force --options runtime --timestamp \
    --identifier dev.1pass.kc --sign "$identity" "$bin"
  codesign --verify --strict --verbose=2 "$bin"

  # A bare executable can't be stapled; Gatekeeper looks the ticket up online.
  ditto -c -k "$bin" "$dir-notarize.zip"
  result=$(xcrun notarytool submit "$dir-notarize.zip" \
    --key "$key" --key-id "$key_id" --issuer "$issuer" \
    --wait --output-format json)
  status=$(printf '%s' "$result" | plutil -extract status raw -o - -)
  if [ "$status" != Accepted ]; then
    echo "notarization of $archive: $status" >&2
    printf '%s\n' "$result" >&2
    exit 1
  fi
  rm "$dir-notarize.zip"

  rm "$archive"
  tar -czf "$archive" "$dir"
  new=$(shasum -a 256 "$archive" | cut -d' ' -f1)
  # Replace this archive's line, keep every other platform's.
  awk -v f="$archive" -v h="$new" '$2 == f { $1 = h } { print }' OFS='  ' SHA256SUMS > SHA256SUMS.new
  mv SHA256SUMS.new SHA256SUMS
  grep -q "^$new  $archive\$" SHA256SUMS || { echo "SHA256SUMS has no line for $archive" >&2; exit 1; }
  echo "signed and notarized: $archive"
done

gh release upload "$tag" --repo "$repo" --clobber "${archives[@]}" SHA256SUMS
echo "uploaded ${#archives[@]} signed archives and SHA256SUMS to the $tag draft"

if [ "$publish" = --publish ]; then
  gh release edit "$tag" --repo "$repo" --draft=false
  echo "published $tag"
else
  echo "review the draft, then: gh release edit $tag --repo $repo --draft=false"
fi
