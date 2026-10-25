#!/usr/bin/env bash
# Fail if any crate under contracts/ or examples/ is missing from the root
# Cargo.toml's [workspace] members list.
#
# A crate that isn't a workspace member silently misses `cargo test
# --workspace`, `cargo clippy --workspace`, and the wasm-build CI job — its
# tests stop running without anyone noticing. This script catches that gap
# before it ships.
#
# Usage:
#   scripts/check-workspace-members.sh
#
# Exit status:
#   0 - every contracts/*/Cargo.toml and examples/*/Cargo.toml directory is
#       listed as a workspace member
#   1 - at least one is missing (the missing paths are printed)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Directories that are intentionally excluded from workspace membership.
# `contracts/pausable` is a shared library crate with no wasm exports of its
# own (see contracts/pausable/Cargo.toml); it's consumed exclusively via a
# path dependency from other crates and doesn't need to be a member for that
# to work. Keep this list short — anything else with a Cargo.toml should be
# a member so its tests actually run in CI.
EXCLUDED=(
  "contracts/pausable"
)

is_excluded() {
  local candidate="$1"
  local excluded
  for excluded in "${EXCLUDED[@]}"; do
    if [ "$candidate" = "$excluded" ]; then
      return 0
    fi
  done
  return 1
}

missing=()
duplicates=()

# Check for duplicate entries in the workspace members list.
# Extract member paths from Cargo.toml and look for any that appear more than once.
while IFS= read -r member; do
  count=$(grep -c "^\s*\"${member}\",\?\s*$" Cargo.toml || true)
  if [ "$count" -gt 1 ]; then
    duplicates+=("$member")
  fi
done < <(grep -oP '(?<=")(contracts|examples)/[^"]+(?=")' Cargo.toml | sort -u)

if [ "${#duplicates[@]}" -gt 0 ]; then
  echo "error: the following crates appear more than once in [workspace] members in Cargo.toml:" >&2
  for dir in "${duplicates[@]}"; do
    echo "  - ${dir}" >&2
  done
  echo "" >&2
  echo "Remove the duplicate entries from the 'members' list in Cargo.toml." >&2
  exit 1
fi

for dir in contracts/*/ examples/*/; do
  dir="${dir%/}"
  [ -f "${dir}/Cargo.toml" ] || continue
  is_excluded "$dir" && continue

  if ! grep -q "^\s*\"${dir}\",\?\s*$" Cargo.toml; then
    missing+=("$dir")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "error: the following crates are missing from [workspace] members in Cargo.toml:" >&2
  for dir in "${missing[@]}"; do
    echo "  - ${dir}" >&2
  done
  echo "" >&2
  echo "Add each path to the 'members' list in Cargo.toml, or add it to the" >&2
  echo "EXCLUDED list in scripts/check-workspace-members.sh if it's a shared" >&2
  echo "library crate that's intentionally path-dependency-only." >&2
  exit 1
fi

echo "OK: every contracts/ and examples/ crate is a workspace member."
