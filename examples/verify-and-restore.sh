#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 ARCHIVE.sc DESTINATION [RECOVERY_TOKEN_FILE]" >&2
  exit 2
fi

archive=$1
destination=$2
token_file=${3:-}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -n "$token_file" ]; then
  "$root/sc.sh" verify --token-file "$token_file" "$archive"
  exec "$root/admin/recover.sh" "$archive" -C "$destination" --token-file "$token_file"
fi

"$root/sc.sh" verify "$archive"
exec "$root/sc.sh" unpack "$archive" -C "$destination"
