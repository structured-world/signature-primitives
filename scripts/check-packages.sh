#!/usr/bin/env bash
set -euo pipefail

# Cargo's temporary workspace registry can retain a same-version dependency
# archive from an earlier source tree. Verify this tree in fresh package state.
cd -- "$(dirname -- "$0")/.."
source scripts/package-files.sh
package_dir=$(mktemp -d)
trap 'rm -rf -- "$package_dir"' EXIT
cargo package --locked --workspace --target-dir "$package_dir" "$@"

status=0
for archive in "$package_dir"/package/*.crate; do
  base=$(basename -- "$archive" .crate)
  tar -tzf "$archive" | while IFS= read -r path; do
    printf '%s\n' "${path#"$base"/}"
  done | LC_ALL=C sort > "$package_dir/$base.packaged"
  root=$(tar -xzOf "$archive" "$base/.cargo_vcs_info.json" | jq -r .path_in_vcs)
  git ls-files -- "$root" | while IFS= read -r path; do
    printf '%s\n' "${path#"$root"/}"
  done | LC_ALL=C sort > "$package_dir/$base.tracked"
  package_file_problems "$base" "$package_dir/$base.packaged" "$package_dir/$base.tracked" || status=1
done
exit "$status"
