#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUST_MANIFEST="$SCRIPT_DIR/public/rust/Cargo.toml"
RUST_BIN="$SCRIPT_DIR/public/rust/target/release/sc"
RUBY_APP="$SCRIPT_DIR/public/ruby/sc.rb"


META_REQUEST=0
for argument in "$@"; do
  case "$argument" in
    --help|-h|--version) META_REQUEST=1 ;;
  esac
done

case "${SC_RUNTIME:-auto}" in
  rust)
    if [ -x "$RUST_BIN" ]; then
      exec "$RUST_BIN" "$@"
    fi
    if command -v cargo >/dev/null 2>&1; then
      exec cargo run --release --quiet --manifest-path "$RUST_MANIFEST" -- "$@"
    fi
    echo "Error: Rust runtime requested, but neither a release binary nor Cargo is available." >&2
    exit 127
    ;;
  ruby)
    if ! command -v ruby >/dev/null 2>&1; then
      echo "Error: Ruby is not installed." >&2
      exit 127
    fi
    if [ "$META_REQUEST" -ne 1 ] && ! ruby -e 'require "zip"' >/dev/null 2>&1; then
      echo "Error: RubyZip is missing. Run: gem install rubyzip" >&2
      exit 127
    fi
    exec ruby "$RUBY_APP" "$@"
    ;;
  auto)
    if [ -x "$RUST_BIN" ]; then
      exec "$RUST_BIN" "$@"
    fi
    if command -v ruby >/dev/null 2>&1; then
      if [ "$META_REQUEST" -eq 1 ] || ruby -e 'require "zip"' >/dev/null 2>&1; then
        exec ruby "$RUBY_APP" "$@"
      fi
    fi
    if command -v cargo >/dev/null 2>&1; then
      exec cargo run --release --quiet --manifest-path "$RUST_MANIFEST" -- "$@"
    fi
    echo "Error: No usable SC Archive runtime was found." >&2
    echo "Install Rust 1.88+ (recommended), or Ruby 3.0+ with RubyZip." >&2
    echo "Then run: ./sc.sh --help" >&2
    exit 127
    ;;
  *)
    echo "Error: SC_RUNTIME must be auto, rust, or ruby." >&2
    exit 2
    ;;
esac
