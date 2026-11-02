# Repository file layout

## Public implementation

- `public/ruby/sc.rb`: Ruby command-line entry point and SCAR v2 stream implementation.
- `public/ruby/lib/sc_archive/security.rb`: password policy, input tree checks, path validation, and ZIP path registry.
- `public/ruby/lib/sc_archive/token_store.rb`: recovery-token storage and permission validation.
- `public/ruby/lib/sc_archive/audit_log.rb`: local redacted audit log with rotation.
- `public/ruby/test/`: cryptographic, path, token, audit, and archive validation tests.
- `public/rust/src/main.rs`: Rust command-line entry point and encrypted stream orchestration.
- `public/rust/src/secure_paths.rs`: archive path validation and ZIP collision registry.
- `public/rust/src/token_store.rs`: recovery-token generation, storage, and permission checks.
- `public/rust/src/audit.rs`: local redacted audit writer with bounded rotation and no-follow file opening on Unix.

## Admin-only utilities

- `admin/recover.sh`: invokes the regular recovery command with an explicit token credential.
- `admin/audit_viewer.rb`: read-only local audit viewer.
- `admin/POLICY.md`: rules for authorized use.
- `admin/ABUSE_REPORT.md`: sanitized abuse report template.

The admin folder does not contain a master key, hidden bypass, or remote unlock service.

## Development and operations

- `docs/`: format, architecture, security, testing, and operational documentation.
- `examples/`: copyable shell workflows.
- `scripts/`: local test and packaging helpers.
- `.github/workflows/`: continuous integration checks.
