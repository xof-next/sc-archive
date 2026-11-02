# Threat model

## Assets

- Source file contents and internal file names.
- Archive password.
- Independent admin recovery token.
- Temporary decrypted ZIP payload.
- Restored files.

## Security objectives

1. Confidentiality of archive contents and internal paths while stored as `.sc`.
2. Integrity and authenticity of each encrypted record and the complete stream.
3. Rejection of malformed archives before extraction.
4. Prevention of archive path traversal and file overwrite during extraction.
5. Protection of recovery-token files against accidental broad Unix permissions.
6. No hidden administrative credential, remote unlock endpoint, or covert telemetry.

## Adversaries considered

- A person who obtains only the `.sc` file and attempts offline password guessing.
- A person who supplies a modified, truncated, oversized, or malformed `.sc` file.
- A malicious ZIP payload containing traversal names, duplicate paths, links, or size inconsistencies.
- An untrusted process attempting to place symlinks or pre-existing files in the extraction destination.
- An operator who accidentally exposes a recovery-token file through loose filesystem permissions.

## Not guaranteed

- Protection against a compromised host, debugger, keylogger, malicious runtime, or privileged local attacker.
- Protection after a user has restored and opened the files.
- Secure erasure from SSDs, snapshots, journaling filesystems, backups, or swap.
- Concealment of the encrypted archive's total size or record-length pattern.
- Protection against weak passwords or sufficiently resourced offline guessing.
- Tamper-proof audit records or proof of an operator's identity.
- Availability against deliberate deletion or storage exhaustion.

## Credential model

The password and recovery token are independent credentials that unwrap the same random DEK. Either credential is sufficient to restore. The recovery token is a bearer secret, not a separate human identity system. Anyone who gets it can use it.

## Residual risk

SC Archive has not undergone an independent cryptographic audit. It should not be treated as a certified encryption product or a substitute for a reviewed organizational key-management system.
