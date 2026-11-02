# Changelog

## 1.0.0 — 2026-11-02

Initial public release of SC Archive with the SCAR v2 container format and matching Ruby and Rust command-line implementations.

### Security
- Encrypt the ZIP payload with AES-256-GCM and scrypt-derived wrapping keys.
- Keep password and recovery credentials as separate unlock methods without a hidden master key or remote unlock service.
- Require at least 16 characters for newly created archive passwords while retaining unlock support for earlier SCAR v2 development archives.
- Validate recovery-token file type, size, and Unix permissions; refuse symbolic-link token files.
- Validate ZIP paths against traversal, drive prefixes, control characters, Windows device names, alternate data streams, trailing dots or spaces, duplicate entries, and case-fold collisions.
- Bound ZIP entry count, per-file size, and total expanded size during archive creation, verification, and extraction.
- Reject symbolic links, special filesystem objects, malformed directory records, and trailing bytes after the encrypted terminal record.

### Features
- Provide `pack`, `unpack`, `recover`, `inspect`, and `verify` commands.
- Provide Ruby and Rust implementations that use the same SCAR v2 layout.
- Include a POSIX shell launcher, local audit tooling, security tests, operational runbooks, and shell examples.
