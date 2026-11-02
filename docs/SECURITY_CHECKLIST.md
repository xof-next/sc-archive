# Security checklist

## Input handling

- [x] Reject missing input paths.
- [x] Reject symbolic-link roots and symbolic links inside source directories.
- [x] Reject special filesystem objects.
- [x] Bound input entry count, per-file bytes, and aggregate bytes.
- [x] Reject archive outputs inside the source directory.
- [x] Refuse to overwrite existing archive and recovery-token outputs.

## Credentials

- [x] Prompt without terminal echo.
- [x] Never accept secrets as command-line arguments.
- [x] Require stronger passwords for new archives.
- [x] Retain legacy password-length compatibility for existing SCAR v2 archives.
- [x] Generate 256-bit random recovery tokens.
- [x] Save tokens using owner-only permissions where supported.
- [x] Reject symlink, non-regular, oversized, or broadly permissioned token files.
- [x] Zeroize selected in-memory secret buffers where runtime support allows.

## Archive format

- [x] Validate fixed KDF parameters before deriving keys.
- [x] Authenticate wrapped DEKs with domain-separated AAD.
- [x] Authenticate every payload record.
- [x] Authenticate terminal record.
- [x] Reject truncation and trailing data.
- [x] Reject invalid record lengths and excessive record counts.

## ZIP validation and extraction

Implementation ceilings: 50,000 entries, 1 GiB per file, and 4 GiB aggregate expanded data. The archive parser also rejects encrypted records larger than the fixed 1 MiB chunk size. These are hard safety limits, not performance guarantees.


- [x] Reject absolute, drive-prefixed, and parent-traversal names.
- [x] Reject control characters, Windows device names, alternate data streams, and trailing dot/space names.
- [x] Reject duplicate and case-fold-colliding paths.
- [x] Reject file/directory path collisions.
- [x] Reject symbolic-link entries.
- [x] Reject non-empty directory entries.
- [x] Bound entry count, per-entry size, and total expanded size.
- [x] Extract to a staging directory and refuse overwrite.

## Operational controls

- [x] Local audit records exclude credentials, paths, and contents.
- [x] Local audit is documented as mutable and non-authoritative.
- [x] Admin recovery requires the actual recovery token.
- [x] No remote reporting, remote unlock endpoint, or hidden master key exists.

## Remaining review

- [ ] Independent cryptographic audit.
- [ ] Cross-platform integration tests on Windows and macOS.
- [ ] Fuzz testing of malformed SCAR and ZIP inputs.
- [ ] Race testing against concurrent local filesystem modification.


## Credential and audit file handling

- Recovery-token files are bounded in size, validated for canonical token length, opened without following symbolic links on supported Unix platforms, and checked again through the opened file descriptor.
- Unix recovery-token files must not grant group or world permissions. Newly written token files use owner-only permissions.
- Audit paths must be regular files in a private per-user directory. Audit writes do not follow symbolic links on supported Unix platforms.
- Audit logs contain only operation, result, version, and timestamp metadata; they exclude file paths and credentials. Rotation is bounded to three previous files.
- Audit logs are local convenience records, not tamper-proof security evidence.
