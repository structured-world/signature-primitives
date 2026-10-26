#!/usr/bin/env bash
# Generate public test inputs with Bouncy Castle; no private keys are retained.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
version=1.80
classpath=""
for name in bcprov bcpkix bcutil; do
  case "$name" in
    bcprov) expected=e8ad209f8c58d291a37ca9750e9e9fac60596956c983e49dd8282381dd8b3249 ;;
    bcpkix) expected=4f4ba6a92617ea19dc183f0fa5db492eee426fdde2a0a2d6c94777ffd1af6413 ;;
    bcutil) expected=22eca687f7955411f456af33e6ea8e68fc73cd80cb8b32aa5f7a8b1827d7c678 ;;
  esac
  jar="$work/$name.jar"
  curl -fsSL --retry 3 "https://repo.maven.apache.org/maven2/org/bouncycastle/$name-jdk18on/$version/$name-jdk18on-$version.jar" -o "$jar"
  actual=$(shasum -a 256 "$jar" | cut -d' ' -f1)
  if [ "$actual" != "$expected" ]; then
    printf 'Bouncy Castle archive checksum mismatch: %s\n' "$name" >&2
    exit 1
  fi
  classpath="$classpath${classpath:+:}$jar"
done
java -cp "$classpath" crates/structured-pkix/tests/support/HybridVectors.java \
  crates/structured-pkix/tests/data/hybrid
