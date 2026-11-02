# CLI reference

The command-line interface is exposed through `./sc.sh`, `./sc`, or a compiled `sc` executable.

## Runtime selection

```sh
SC_RUNTIME=auto ./sc.sh --help
SC_RUNTIME=rust ./sc.sh --version
SC_RUNTIME=ruby ./sc.sh --version
```

`auto` prefers a prebuilt Rust release binary, then Ruby with RubyZip installed, then Cargo. Explicit `rust` may compile using Cargo when the release binary is absent. Explicit `ruby` does not invoke Cargo.

## Create

```sh
sc pack [OPTIONS] INPUT
```

Options:

- `-o, --output PATH`: write to a new `.sc` file. Default: `INPUT.sc` beside the source.
- `--obfuscation LEVEL`: `standard` or `high`. Default: `standard`.
- `--recovery-file PATH`: write the recovery token to a new file with owner-only permissions where supported.

The password is prompted interactively and confirmed. New archives require at least 16 characters. Output and token files must not be inside the source directory. Existing outputs are never overwritten.

Examples:

```sh
sc pack . --obfuscation high
sc pack ./assets -o ../assets-backup.sc --recovery-file ../assets-backup.recovery
sc pack "/data/project with spaces" --obfuscation standard
```

## Restore

```sh
sc unpack [OPTIONS] ARCHIVE.sc
sc recover [OPTIONS] ARCHIVE.sc
```

- `-C, --output-dir PATH`: destination directory; it must not exist.
- `--token-file PATH`: `recover` only; read the admin token from a private file.

The password or token is requested without echo. Credential values must not be supplied as CLI arguments.

## Inspect

```sh
sc inspect ARCHIVE.sc
```

Displays the format version, scrypt profile, payload cipher, and encrypted file size. It does not validate the password slot or decrypt any payload data.

## Verify

```sh
sc verify ARCHIVE.sc
sc verify --token-file ./archive.sc.recovery ARCHIVE.sc
```

Authenticates the full encrypted stream, checks the terminal record and ZIP structure, validates entry names and sizes, and reads every file stream without restoring files.

## Path syntax

The launcher passes paths without shell glob expansion and supports `.`, `./name`, `../name`, absolute paths, and quoted paths with spaces. A path beginning with `-` should be passed after `--` when the selected runtime's argument parser supports it.

## Exit status

- `0`: requested operation completed.
- `1`: validation, authentication, I/O, or runtime error.
- `2`: invalid launcher configuration.
- `127`: requested runtime is unavailable.
- `130`: interrupted operation in the Ruby CLI.
