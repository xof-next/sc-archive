# Release process

1. Update the application version in Ruby and Rust manifests/source.
2. Confirm whether the binary format changed. If it did, increment the format version and write a migration note.
3. Add cross-language vectors before changing cryptographic serialization.
4. Run the complete Ruby, Rust, and shell suites.
5. Run an end-to-end pack, inspect, verify, password restore, and token restore using both runtimes.
6. Confirm output paths, token-file permissions, and recovery instructions on supported platforms.
7. Review the threat model and security checklist.
8. Create a source archive and SHA-256 checksum.
9. Record actual test results and known limitations in the release notes.
10. Never describe a runtime as tested if it was not built and exercised.
