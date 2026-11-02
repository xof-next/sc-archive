#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
for file in sc.sh sc admin/recover.sh scripts/*.sh examples/*.sh; do
  sh -n "$file"
done
