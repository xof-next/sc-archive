# Security policy

## Supported version

Security fixes are developed against SC Archive 1.2.x. The SCAR v2 binary format is stable across application releases 1.1.x and 1.2.x.

## Reporting a vulnerability

Do not publish recovery tokens, passwords, private archives, or personal data in a report. Prepare a minimal reproduction that does not include secrets. Report the affected release, runtime (Ruby or Rust), operating system, exact command, expected behavior, observed behavior, and relevant sanitized logs.

For a private report, use a private security contact supplied by the repository owner. If no private contact is published, request a private reporting channel before sharing exploit details publicly.

## Scope

In scope:
- Authentication bypass or cryptographic format errors.
- Password or recovery-token exposure.
- ZIP path traversal or unsafe extraction.
- Memory-safety or denial-of-service issues caused by crafted archives.
- Cross-language incompatibility that weakens integrity checks.

Out of scope:
- Lost credentials without a vulnerability.
- The intentional ability of a valid password or recovery token to restore content.
- Compromise of the host operating system or third-party dependencies without a SC Archive-specific impact.
- Attacks that require access to the user's unlocked session or credentials.

## Disclosure

Allow maintainers to reproduce and assess the report before publication. Do not include weaponized proof-of-concept archives targeting other users.
