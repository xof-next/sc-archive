# SC Archive

SC Archive is an open-source, password-protected archive format and command-line tool. It stores ZIP data inside an opaque `.sc` container and encrypts the complete payload.

## Project summary

- **Release:** 1.0.0
- **Container format:** SCAR v2
- **Implementations:** Ruby and Rust
- **Launcher:** POSIX shell (`sh`)
- **Encryption:** AES-256-GCM with scrypt-derived wrapping keys
- **Recovery:** Separate recovery token; no hidden master key or remote unlock service
- **License:** MIT

SC Archive supports creating, inspecting, verifying, and restoring encrypted `.sc` archives. The Ruby and Rust implementations share the SCAR v2 format in this initial public release.

## Download

- [Download source ZIP](https://github.com/xof-next/sc-archive/archive/refs/heads/main.zip)
- [Open repository](https://github.com/xof-next/sc-archive)
- [XOF organization dashboard](https://github.com/orgs/xof-next/dashboard)

The source ZIP link becomes available after the repository is published and the `main` branch exists.

## Quick start

```sh
./sc.sh pack . --obfuscation high --recovery-file ./project.sc.recovery
./sc.sh inspect ./project.sc
./sc.sh verify ./project.sc
./sc.sh unpack ./project.sc -C ./restored
```

Use `./admin/recover.sh` with the recovery-token file to restore an archive when the original password is unavailable.

## Requirements

- Ruby 3.0+ with OpenSSL and RubyZip 3.x, or
- Rust stable 1.88+
- POSIX-compatible shell for `sc.sh`

See `docs/` for the format specification, architecture, compatibility notes, security checklist, testing guide, and recovery runbook.

## Security notes

Use a long, unique password and store the recovery token separately from the archive. Anyone holding either valid credential can restore the archive. SC Archive has not received an independent cryptographic audit; review `docs/THREAT_MODEL.md` before using it for sensitive production data.

## License

MIT. See [LICENSE](LICENSE).
