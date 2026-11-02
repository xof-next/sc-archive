#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
./scripts/test-ruby.sh
./scripts/check-shell.sh
if command -v cargo >/dev/null 2>&1; then
  (cd public/rust && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test)
else
  echo 'Cargo unavailable: Rust checks were not run.' >&2
fi
