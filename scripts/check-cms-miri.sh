#!/usr/bin/env bash
set -euo pipefail

# The dev-only SHA-2 oracle can select ARM intrinsics which Miri cannot execute.
# RustCrypto documents this software backend; production features are unchanged.
# https://github.com/RustCrypto/hashes/tree/master/sha2#configuration-flags
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }--cfg sha2_backend=\"soft\""
cargo +nightly miri nextest run -p structured-cms "$@"
