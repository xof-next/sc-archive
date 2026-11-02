# Architecture

## Data flow

```text
Source file tree
      |
      v
Input validation ---- reject symlinks, special files, excess sizes
      |
      v
ZIP builder --------- normalize portable paths and check collisions
      |
      v
SCAR v2 envelope ---- password slot + recovery slot wrap a random DEK
      |
      v
AES-256-GCM records - 1 MiB blocks + authenticated terminal record
      |
      v
      .sc
```

Restore reverses the process into a private temporary ZIP file. The complete encrypted stream must authenticate before ZIP validation or extraction begins. Extraction takes place in a new staging directory and is moved to the requested destination after all entries pass validation.

## Cryptographic components

- Random 256-bit DEK per archive.
- Scrypt-derived 256-bit wrapping keys with independent 128-bit salts.
- AES-256-GCM key wrapping with domain-separated AAD labels.
- AES-256-GCM payload records with a per-archive random 64-bit nonce prefix and a 32-bit monotonically increasing counter.
- Header, counter, and plaintext record length are authenticated for each record.
- A zero-length authenticated terminal record detects truncation.

See `FORMAT.md` for byte-accurate serialization rules.

## Trust boundaries

The archive header, encrypted records, ZIP central directory, ZIP entry names, and recovery-token file are untrusted input. The implementation validates bounded KDF parameters before key derivation and validates archive structure before extraction.

The host OS, runtime, OpenSSL implementation, Rust dependencies, filesystem, and terminal are outside the archive format's trust boundary. A compromised host can capture secrets before encryption or after decryption.

## Runtime parity

Ruby and Rust must use the same byte order, KDF parameters, salts, nonce sizes, authenticated data, and terminal-record rules. Cross-language vectors are stored under `docs/TEST_VECTORS.md` and `public/ruby/test/fixtures/`.
