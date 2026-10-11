#!/usr/bin/env bash
set -euo pipefail

# Cargo's temporary workspace registry can retain a same-version dependency
# archive from an earlier source tree. Verify this tree in fresh package state.
cd -- "$(dirname -- "$0")/.."
package_dir=$(mktemp -d)
trap 'rm -rf -- "$package_dir"' EXIT
cargo package --locked --workspace --target-dir "$package_dir" "$@"
