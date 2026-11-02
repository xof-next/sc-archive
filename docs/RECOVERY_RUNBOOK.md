# Recovery runbook

## Before creating an archive

1. Choose a unique passphrase of at least 16 characters.
2. Decide where the recovery token will be stored independently from the `.sc` archive.
3. Ensure the token directory is trusted and not synchronized to an unintended location.
4. Confirm the input tree does not contain symbolic links or special filesystem objects.

## Create the archive and token

```sh
./sc.sh pack ./project \
  --obfuscation high \
  --recovery-file /secure/offline/project.sc.recovery
```

The CLI displays the generated token once. Keep it private and verify that the token file exists with restrictive permissions.

## Verify before moving backups

```sh
./sc.sh inspect ./project.sc
./sc.sh verify ./project.sc
```

For a recovery-credential check:

```sh
./sc.sh verify --token-file /secure/offline/project.sc.recovery ./project.sc
```

## Restore with the password

```sh
./sc.sh unpack ./project.sc -C ./project-restored
```

## Restore with the admin token

```sh
./admin/recover.sh ./project.sc \
  -C ./project-restored \
  --token-file /secure/offline/project.sc.recovery
```

## If recovery fails

- Check that the token file is not truncated and contains one 43-character URL-safe Base64 token.
- On Unix-like systems, set permissions with `chmod 600 /path/to/token`.
- Confirm that the `.sc` file is complete and has not been modified.
- Use `inspect` to confirm the reader recognizes the SCAR v2 header.
- Keep an untouched copy of the original archive before attempting recovery again.

There is no administrative bypass. If both the password and recovery token are lost, the archive cannot be restored.
