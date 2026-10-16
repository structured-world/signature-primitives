#!/usr/bin/env bash
set -euo pipefail

# Test-only P-256/SHA-2 fixtures must use the documented software backend under
# Miri. No production feature or verification contract is changed.
# https://github.com/RustCrypto/hashes/tree/master/sha2#configuration-flags
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }--cfg sha2_backend=\"soft\""
cargo +nightly miri nextest run -p structured-xades "$@"
