#!/usr/bin/env bash
set -euo pipefail

# Usage: qualify-registry.sh [REVISION]
#
# Qualify what crates.io serves for the packages and versions of REVISION
# (default HEAD): every archive was packaged from exactly that commit, its
# index checksum matches, its files are the commit's, and its packaged tests
# pass against the registry dependency graph. Every problem is reported
# before the script fails.
cd -- "$(dirname -- "$0")/.."
source scripts/package-files.sh
revision=$(git rev-parse --verify "${1:-HEAD}^{commit}")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -- "$work/archives" "$work/packages" "$work/tree"
export CARGO_TARGET_DIR="$work/target"
problems=()

problem() {
  printf 'qualify-registry: %s\n' "$*" >&2
  problems+=("$*")
}

digest() {
  if command -v sha256sum >/dev/null; then
    sha256sum -- "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 -- "$1" | cut -d ' ' -f 1
  fi
}

# The sparse index can lag a just-finished publication by a few minutes.
index_entry() {
  local name=$1 version=$2 file="$work/index-$1" entry attempt
  for attempt in $(seq 60); do
    if curl -fsS --retry 3 -o "$file" "https://index.crates.io/${name:0:2}/${name:2:2}/$name"; then
      entry=$(jq -c --arg version "$version" 'select(.vers == $version)' "$file")
      if [ -n "$entry" ]; then
        printf '%s\n' "$entry"
        return
      fi
    fi
    if [ "$attempt" -lt 60 ]; then sleep 10; fi
  done
  return 1
}

# Packaged files other than those cargo generates are byte-identical to the
# commit, and the archive holds exactly its committed source and test files.
compare_sources() {
  local label=$1 package=$2 commit=$3 root=$4 file committed line
  (cd -- "$package" && find . -type f | while IFS= read -r file; do
    printf '%s\n' "${file#./}"
  done | LC_ALL=C sort) > "$work/$label.packaged"
  while IFS= read -r file; do
    case $file in
      .cargo_vcs_info.json | Cargo.lock | Cargo.toml) continue ;;
      Cargo.toml.orig) committed="$root/Cargo.toml" ;;
      *) committed="$root/$file" ;;
    esac
    if ! git cat-file -e "$commit:$committed" 2>/dev/null; then
      problem "$label: packaged $file is not in $commit"
    elif ! git show "$commit:$committed" | cmp -s - "$package/$file"; then
      problem "$label: $file differs from $commit"
    fi
  done < "$work/$label.packaged"
  git ls-tree -r --name-only "$commit" -- "$root" | while IFS= read -r file; do
    printf '%s\n' "${file#"$root"/}"
  done | LC_ALL=C sort > "$work/$label.tracked"
  while IFS= read -r line; do
    problem "$line"
  done < <(package_file_problems "$label" "$work/$label.packaged" "$work/$label.tracked" || true)
}

check() {
  local label=$1
  shift
  "$@" || problem "$label: $* failed"
}

# Packages and versions come from REVISION itself, not the working tree.
git archive "$revision" | tar -x -C "$work/tree"
cargo metadata --locked --no-deps --format-version 1 --manifest-path "$work/tree/Cargo.toml" > "$work/metadata.json"
msrv=$(jq -r '[.packages[].rust_version] | unique | if length == 1 then .[0] else error("rust-version differs") end' "$work/metadata.json")
# A two-component rust-version names its .0 release; rustup's two-component
# channel would follow later patch releases instead.
case $msrv in
  *.*.*) ;;
  *.*) msrv="$msrv.0" ;;
  *) printf 'qualify-registry: unsupported rust-version %s\n' "$msrv" >&2; exit 1 ;;
esac
packages=()
while read -r name version; do
  label="$name-$version"
  if ! entry=$(index_entry "$name" "$version"); then
    problem "$label is not in the crates.io index"
    continue
  fi
  [ "$(jq -r .yanked <<<"$entry")" = false ] || problem "$label is yanked"
  archive="$work/archives/$label.crate"
  curl -fsS --retry 3 -o "$archive" "https://static.crates.io/crates/$name/$label.crate"
  checksum=$(digest "$archive")
  if [ "$checksum" != "$(jq -r .cksum <<<"$entry")" ]; then
    problem "$label: archive does not match the index checksum"
    continue
  fi

  tar -xzf "$archive" -C "$work/packages"
  package="$work/packages/$label"
  vcs="$package/.cargo_vcs_info.json"
  [ "$(jq -r '.git.dirty // false' "$vcs")" = false ] || problem "$label was packaged from a dirty tree"
  commit=$(jq -r .git.sha1 "$vcs")
  # An earlier commit's archive under the same version does not contain the
  # changes this revision released, so it is not tested in its place.
  if [ "$commit" != "$revision" ]; then
    problem "$label was packaged from $commit, not $revision"
    continue
  fi
  compare_sources "$label" "$package" "$commit" "$(jq -r .path_in_vcs "$vcs")"
  printf 'qualify-registry: %s %s sha256:%s\n' "$label" "$commit" "$checksum"
  packages+=("$label")
done < <(jq -r '.packages[] | select(.publish == null) | "\(.name) \(.version)"' "$work/metadata.json")

for label in "${packages[@]}"; do
  cd -- "$work/packages/$label"
  check "$label" cargo +stable nextest run --locked --all-features --no-tests=pass
  check "$label" cargo +stable test --locked --doc --all-features
  check "$label" cargo "+$msrv" nextest run --locked --all-features --no-tests=pass
  for target in wasm32-unknown-unknown thumbv7em-none-eabihf; do
    check "$label" cargo +stable check --locked --no-default-features --features alloc --target "$target"
  done
  cd - >/dev/null
done

if [ "${#problems[@]}" -gt 0 ]; then
  printf 'qualify-registry: %d problems\n' "${#problems[@]}" >&2
  exit 1
fi
printf 'qualify-registry: %d packages qualified\n' "${#packages[@]}"
