#!/usr/bin/env bash
set -euo pipefail

# Usage: wait-registry-resolution.sh PACKAGE
#
# Wait until Cargo resolves this revision's version of PACKAGE from crates.io,
# as a dependent's `cargo publish` must. A successful registry lookup alone does
# not guarantee that resolution
# (https://github.com/release-plz/release-plz/issues/2946).
cd -- "$(dirname -- "$0")/.."
package=$1
version=$(cargo metadata --locked --no-deps --format-version 1 |
  jq -r --arg name "$package" '.packages[] | select(.name == $name) | .version')
if [ -z "$version" ]; then
  printf 'wait-registry-resolution: %s is not a workspace package\n' "$package" >&2
  exit 1
fi
probe=$(mktemp -d)
trap 'rm -rf -- "$probe"' EXIT
mkdir -- "$probe/src"
: > "$probe/src/lib.rs"
printf '[package]\nname = "resolution-probe"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n[dependencies]\n%s = "=%s"\n\n[workspace]\n' \
  "$package" "$version" > "$probe/Cargo.toml"
for attempt in $(seq 60); do
  if cargo generate-lockfile --manifest-path "$probe/Cargo.toml" >/dev/null 2>&1; then
    printf 'wait-registry-resolution: %s %s resolves after %d attempts\n' "$package" "$version" "$attempt"
    exit 0
  fi
  sleep 10
done
printf 'wait-registry-resolution: %s %s did not resolve within 10 minutes\n' "$package" "$version" >&2
exit 1
