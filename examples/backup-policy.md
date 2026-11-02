# Backup policy example

1. Create an encrypted `.sc` archive from a directory that you own or are authorized to handle.
2. Store the `.sc` file in the normal backup location.
3. Store the recovery token in a separate access-controlled location.
4. Keep at least one additional copy of the archive if it is important.
5. Verify the archive after copying it to backup storage.
6. Perform a restore test on a separate destination before relying on a backup.
7. Do not place the archive and its only recovery token in the same public repository or shared folder.
8. Document who is authorized to access the recovery token outside of SC Archive.

The token is sufficient to recover the archive. Protect it with the same care as the source data.
