#!/usr/bin/env bash
# The gate CI applies, run locally and in the same order, so a red build is
# something you see before you push rather than after.
#
# Mirrors .github/workflows/ci.yml. If you change one, change the other — the
# whole value here is that the two agree.
#
#   ./testing/check.sh          fmt, clippy, tests        (the pre-commit hook)
#   ./testing/check.sh --full   the above plus coverage   (the pre-push hook)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 1

# CI sets this for the whole job, and it changes the build fingerprint: sharing
# `target/` with ordinary `cargo build` would make the two invalidate each other
# on every switch. A directory of its own costs disk and saves a rebuild.
export RUSTFLAGS="-D warnings"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/check}"

FULL=0
[ "${1:-}" = "--full" ] && FULL=1

fail() {
  echo
  echo "  ✗ $1"
  echo "    fix:  $2"
  exit 1
}

echo "fmt"
cargo fmt --all -- --check >/dev/null 2>&1 || {
  cargo fmt --all -- --check
  fail "formatting" "cargo fmt --all"
}

echo "clippy"
cargo clippy --all-targets --all-features 2>&1 | grep -E "^(error|warning)" -A8 && \
  fail "clippy" "read the diagnostics above"

echo "tests"
cargo test --all-features --locked >/dev/null 2>&1 || {
  cargo test --all-features --locked 2>&1 | grep -E "^(error|failures:|---- |test result: FAILED)" -A6
  fail "tests" "cargo test --all-features --locked"
}

if [ "$FULL" -eq 1 ]; then
  echo "coverage"
  if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    fail "cargo-llvm-cov is not installed" "cargo install cargo-llvm-cov"
  fi
  # Same flags as CI, including the 99 floor and the binaries it excludes.
  cargo llvm-cov --all-features --locked \
    --ignore-filename-regex 'src/main\.rs|src/bin/' \
    --fail-under-lines 99 \
    --show-missing-lines >/dev/null 2>&1 || {
    cargo llvm-cov --all-features --locked \
      --ignore-filename-regex 'src/main\.rs|src/bin/' \
      --fail-under-lines 99 \
      --show-missing-lines 2>&1 | tail -12
    fail "coverage below the floor" "cover the lines listed above, or justify the change to the gate"
  }
fi

echo "  ✓ green"
