#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
sh -n sc.sh sc admin/recover.sh scripts/*.sh examples/*.sh
