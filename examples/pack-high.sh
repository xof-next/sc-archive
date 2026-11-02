#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 INPUT_DIRECTORY [OUTPUT.sc] [RECOVERY_FILE]" >&2
  exit 2
fi

input=$1
output=${2:-"${input%/}.sc"}
token_file=${3:-"${output}.recovery"}

exec "$(dirname "$0")/../sc.sh" pack "$input" \
  --output "$output" \
  --obfuscation high \
  --recovery-file "$token_file"
