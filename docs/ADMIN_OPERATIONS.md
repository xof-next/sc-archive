# Admin operations

The admin area contains recovery instructions and local audit utilities. It is not a separate privileged cryptographic runtime.

## Recovery authority

The only recovery authority is the per-archive recovery token. A maintainer or administrator cannot recover an archive without its password or the corresponding token.

## Token storage

- Keep the token separate from the archive.
- Restrict access to the token file.
- On Unix-like systems, use `chmod 600 token-file`.
- Do not commit token files or include them in public release archives.
- Do not paste the token into issue trackers, chat, or support logs.

## Audit viewer

```sh
ruby admin/audit_viewer.rb
```

The viewer reads local JSON Lines events. The records are informational, mutable, and do not prove user identity. The viewer must not attempt network access or alter the audit file.

## Abuse reports

Use `admin/ABUSE_REPORT.md` as a template. Do not attach archives or credentials belonging to another person. Reports should minimize personal data and include only sanitized reproduction details.
