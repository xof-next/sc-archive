# Compatibility

## Container format

| Application release | SCAR format | Compatibility |
|---|---|---|
| 1.0.0 | v2 | Initial public release |

Application version and container format version are separate concepts. SC Archive 1.0.0 uses the 178-byte SCAR v2 header and the SCAR v2 encrypted record layout.

## Credential compatibility

New archives require at least 16 password characters. The reader also permits the 12-character minimum used by earlier SCAR v2 development archives. This unlock-compatibility rule does not weaken password requirements for newly created archives.

Recovery tokens are 43-character unpadded URL-safe Base64 encodings of 32 random bytes.

## Cross-runtime compatibility

Ruby and Rust implementations must produce and consume the same SCAR v2 byte layout. A format change must increment the binary format version and include new cross-language vectors.

## Legacy v1 archives

SCAR v1 archives use a different container layout and are not supported by the SCAR v2 reader. Preserve the source and runtime that created any legacy archive that still needs to be restored.

## Resource profile

The SCAR v2 `standard` profile uses scrypt parameters that require approximately 128 MiB of working memory. The `high` profile requires approximately 256 MiB. Actual process memory is higher due to runtime and allocator overhead. Concurrent operations multiply the approximate KDF memory requirement.
