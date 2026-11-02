# Admin Policy — SC Archive

## Purpose

SC Archive is intended to protect and transport files that an operator owns or is authorized to handle. Users are responsible for applicable law, contractual obligations, privacy, and third-party rights.

## Prohibited use

Do not use SC Archive to conceal stolen data, distribute malicious payloads, evade lawful access controls, or obstruct an authorized investigation. Do not package files that you are not permitted to access or distribute.

## Recovery-token controls

1. Treat every recovery token as a high-value bearer credential.
2. Store tokens in an approved password manager or protected secret store.
3. Do not commit token files to public repositories or include them in support tickets.
4. Limit access to the smallest authorized administrator group.
5. Record token issuance and revocation procedures in the operator's own access-control system.
6. Remember that SC Archive itself does not identify or authenticate a human administrator. Possession of the token grants recovery access.
7. Do not add hidden master passwords, secret bypasses, remote file collection, or covert telemetry.

## Open-source review

Keep the source code and release artifacts public. Review changes to cryptography, archive extraction, path handling, token handling, and audit behavior before publishing a release. Publish security fixes and release notes when a vulnerability is confirmed.

## Audit and abuse reports

Review local audit records only when the device owner voluntarily provides them and has authority to share them. Do not ask reporters to send passwords, recovery tokens, `.sc` archives, or private file contents.

## Enforcement limitations

SC Archive is an offline command-line program. It cannot remotely inspect or disable copies already downloaded, verify an administrator's identity, or determine whether a user's purpose is lawful. Local audit records can be modified or deleted and are not tamper-proof evidence.
