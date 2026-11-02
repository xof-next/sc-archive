#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
ruby -Ipublic/ruby -e 'Dir["public/ruby/test/test_*.rb"].sort.each { |file| require_relative file }'
