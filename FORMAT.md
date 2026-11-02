# SC Archive binary format — v2

This document defines the `.sc` binary format shared by the Ruby and Rust implementations. All multi-byte integers are unsigned big-endian values. Format version 2 uses envelope encryption with separate password and recovery key slots.

## Header (178 bytes)

### Prefix (58 bytes)

| Offset | Length | Meaning |
|---:|---:|---|
| 0 | 4 | Magic bytes: ASCII `SCAR` |
| 4 | 1 | Format version: `2` |
| 5 | 1 | Scrypt `log2(N)`: `17` for standard, `18` for high |
| 6 | 4 | Scrypt `r`: `8` |
| 10 | 4 | Scrypt `p`: `1` |
| 14 | 16 | Random password-slot salt |
| 30 | 16 | Random recovery-slot salt |
| 46 | 8 | Random payload nonce prefix |
| 54 | 4 | Payload chunk size: `1,048,576` bytes |

### Key slots (120 bytes)

| Offset | Length | Meaning |
|---:|---:|---|
| 58 | 12 | Random password-slot AES-GCM nonce |
| 70 | 48 | Password-wrapped DEK: 32-byte ciphertext + 16-byte tag |
| 118 | 12 | Random recovery-slot AES-GCM nonce |
| 130 | 48 | Recovery-wrapped DEK: 32-byte ciphertext + 16-byte tag |

The complete header is the 58-byte prefix followed by the two 60-byte key slots. The prefix is authenticated as additional authenticated data (AAD) during key wrapping.

## Key derivation and wrapping

A random 32-byte data-encryption key (DEK) is generated for each archive.

For each credential slot:

- Derive a 32-byte wrapping key with scrypt.
- Standard profile: `N = 2^17`, `r = 8`, `p = 1`.
- High profile: `N = 2^18`, `r = 8`, `p = 1`.
- Password and recovery slot use separate random 16-byte salts.
- Use AES-256-GCM with an independently generated 12-byte nonce.
- Password slot AAD: `prefix || ASCII("SCAR-V2-PASSWORD-WRAP")`.
- Recovery slot AAD: `prefix || ASCII("SCAR-V2-RECOVERY-WRAP")`.
- Stored wrapped key is the 32-byte ciphertext immediately followed by its 16-byte GCM tag.

The recovery credential is a 256-bit random value encoded as 43 unpadded URL-safe Base64 characters. It is independent of the user password. Anyone possessing the token can recover the archive, so the token must be protected as a credential.

## Encrypted payload records

The 178-byte header is followed by records until the zero-length terminator:

```text
u32 plaintext_length
byte[plaintext_length] ciphertext
byte[16] GCM_tag
```

For a non-terminal record:

- `plaintext_length` is from 1 through 1,048,576.
- Nonce = `payload_nonce_prefix[8] || u32_be(record_counter)`.
- AAD = `header[178] || u32_be(record_counter) || u32_be(plaintext_length)`.
- Cipher = AES-256-GCM with the random DEK.
- Stored bytes are ciphertext followed by the 16-byte GCM tag.

The terminal record has `plaintext_length = 0`, no ciphertext, and a 16-byte GCM tag. Its nonce uses the next counter value and its AAD is `header || u32_be(counter) || u32_be(0)`. The terminal tag authenticates the end of the stream and detects truncation.

## Profile validation

Readers MUST accept only version `2`, `log2(N)` equal to `17` or `18`, `r=8`, `p=1`, and a chunk size of `1,048,576`. Readers MUST reject unknown KDF parameters instead of trusting attacker-controlled work factors.

## Cross-language requirements

Ruby and Rust implementations MUST:

1. Encode integer fields as big-endian.
2. Use the exact offsets and lengths in this document.
3. Derive keys from the UTF-8 credential bytes and their respective salts.
4. Use the exact AAD labels, including capitalization and hyphens.
5. Store AES-GCM output as ciphertext followed by tag.
6. Authenticate the full 178-byte header for every payload record.
7. Reject trailing bytes after the terminal record.

## Metadata visibility

The `.sc` file does not expose ZIP entries, source file names, directory names, or file contents. The format does expose the profile, random salts/nonces, encrypted record lengths, and approximate total archive size.

## Compatibility

SC Archive v2 is not backward-compatible with v1. V1 used a password-derived payload key and a 42-byte header. V2 uses a random DEK and two independently wrapped key slots. Do not interpret a v1 header as v2.

## Cross-language test vectors

The repository tests include deterministic Ruby/Rust-compatible AES-GCM wrapping and payload-record vectors. The fixture uses `log2(N)=14` only to keep tests fast; production readers accept only `17` and `18`.

Fixture credentials and inputs:

- Password: `Cross-language passphrase 2026`
- Recovery token: 43 ASCII `A` characters
- Password salt: 16 ASCII `P` bytes
- Recovery salt: 16 ASCII `R` bytes
- Payload nonce prefix: 8 ASCII `N` bytes
- Password nonce: 12 ASCII `p` bytes
- Recovery nonce: 12 ASCII `r` bytes
- DEK: 32 ASCII `D` bytes
- Payload plaintext: `Cross-language encrypted record fixture.`
- Payload record counter: `7`

Expected password-wrapped DEK:

```text
d38950ae3318bdd71bb554d2cba4d9dc84a9c4725dbf20ebd34d9608239fb2618e17115dc412847c2fb842a838bb517f
```

Expected recovery-wrapped DEK:

```text
de4645061092c8b19abcd45957b13a07c012342aa5725ce6d5977ebd21dbfac94a1d3f7399ae7b4b472e7a908e4a5d56
```

Expected encrypted payload record (ciphertext followed by tag):

```text
51f23b3c7f809b82e26eb3732cca95a2778894743fcd9dc80ae12e830f35eef98b8271e6b6d12ea184ad9458122c0897b40d40635b0f79d7
```
