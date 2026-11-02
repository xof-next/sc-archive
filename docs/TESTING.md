# Testing guide

## Ruby unit suite

```sh
ruby -Ipublic/ruby -e 'Dir["public/ruby/test/test_*.rb"].sort.each { |file| require_relative file }'
```

The Ruby tests cover cryptographic envelope handling, cross-language vectors, malformed headers, password policy, portable ZIP names, symlink rejection, token-file permissions, archive path validation, and audit-log redaction.

## Rust suite

```sh
cd public/rust
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Rust tests include deterministic wrapping and payload-record vectors plus path-validation tests.

## Shell checks

```sh
sh scripts/check-shell.sh
```

## Manual end-to-end test

Use a disposable folder with nested directories and files. Include spaces and Unicode in safe file names. Do not include symlinks, special files, or names reserved on Windows.

```sh
mkdir -p /tmp/sc-demo/input/nested
printf 'SC Archive test\n' > '/tmp/sc-demo/input/hello world.txt'
printf 'nested payload\n' > '/tmp/sc-demo/input/nested/data.txt'
./sc.sh pack /tmp/sc-demo/input -o /tmp/sc-demo/demo.sc \
  --obfuscation standard \
  --recovery-file /tmp/sc-demo/demo.sc.recovery
./sc.sh inspect /tmp/sc-demo/demo.sc
./sc.sh verify /tmp/sc-demo/demo.sc
./sc.sh verify --token-file /tmp/sc-demo/demo.sc.recovery /tmp/sc-demo/demo.sc
./sc.sh unpack /tmp/sc-demo/demo.sc -C /tmp/sc-demo/restored
```

Compare restored content hashes against the source. Repeat with Rust and Ruby runtimes to verify cross-implementation compatibility.

## Fuzzing recommendations

Fuzz the header parser, record lengths, record counters, truncated record boundaries, terminal authentication, ZIP central directory, path normalization, and ZIP entry-size metadata. Keep fuzz inputs bounded and run in a disposable environment.

## Resource tests

Measure both profiles on the lowest-memory supported target. The `high` profile needs more memory and CPU than `standard`. Confirm the OS does not kill the process under the expected deployment memory limit.

## Release gate

A release should not be published until the Ruby suite, Rust suite, formatter, linter, shell syntax checks, and cross-runtime integration tests pass on supported operating systems. Record any untested runtime and do not describe it as verified.
