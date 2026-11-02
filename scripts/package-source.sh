#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=1.0.0
OUT_DIR=${OUT_DIR:-"$ROOT/dist"}
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/sc-archive-v${VERSION}-source.zip"
rm -f "$OUT" "$OUT.sha256"
cd "$ROOT"
zip -qr "$OUT" . \
  -x '*/target/*' '*/.bundle/*' '*/vendor/*' \
     '*.sc' '*.recovery' '*.zip' 'dist/*' '.git/*' '.sc-archive/*'
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$OUT" > "$OUT.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$OUT" > "$OUT.sha256"
else
  echo 'Error: sha256sum or shasum is required to create the release checksum.' >&2
  rm -f "$OUT"
  exit 127
fi
printf 'Created %s\n' "$OUT"
printf 'Created %s.sha256\n' "$OUT"
