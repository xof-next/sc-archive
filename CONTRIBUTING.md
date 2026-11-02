# Contributing

Contributions should preserve the SCAR v2 format unless a separately versioned format proposal is approved.

## Before submitting

1. Read `FORMAT.md`, `docs/THREAT_MODEL.md`, and `docs/SECURITY_CHECKLIST.md`.
2. Keep Ruby and Rust behavior aligned.
3. Add regression tests for every security-sensitive change.
4. Never add real passwords, recovery tokens, or private archives to fixtures.
5. Keep command output and documentation in English.
6. Do not add remote telemetry, hidden unlock paths, or silent file uploads.

## Validation

```sh
ruby -Ipublic/ruby -e 'Dir["public/ruby/test/test_*.rb"].sort.each { |file| require_relative file }'
sh -n sc.sh sc admin/recover.sh scripts/*.sh examples/*.sh
cd public/rust && cargo fmt --check && cargo test
```

## Pull requests

Describe the behavior change, security impact, compatibility impact, tests executed, and any runtime that could not be tested. Keep unrelated formatting changes out of security patches.
