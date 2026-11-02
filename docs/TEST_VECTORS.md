# Cross-language test vectors

These values validate serialization and AES-GCM interoperability. The reduced scrypt work factor (`log2(N)=14`) is for fast deterministic tests only. Production readers accept only `17` and `18`.

## Inputs

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

## Expected outputs

Password-wrapped DEK:

```text
d38950ae3318bdd71bb554d2cba4d9dc84a9c4725dbf20ebd34d9608239fb2618e17115dc412847c2fb842a838bb517f
```

Recovery-wrapped DEK:

```text
de4645061092c8b19abcd45957b13a07c012342aa5725ce6d5977ebd21dbfac94a1d3f7399ae7b4b472e7a908e4a5d56
```

Encrypted payload record (ciphertext followed by tag):

```text
51f23b3c7f809b82e26eb3732cca95a2778894743fcd9dc80ae12e830f35eef98b8271e6b6d12ea184ad9458122c0897b40d40635b0f79d7
```

The same vectors are embedded in the Ruby and Rust unit-test source. A format change must update the implementation, this document, and the fixture JSON together.
