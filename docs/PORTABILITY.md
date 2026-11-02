# Portability notes

## Supported path forms

The shell launcher accepts current-directory paths (`.` and `./name`), parent-relative paths (`../name`), absolute paths, and quoted names containing spaces. All paths are passed as separate arguments; the launcher does not reconstruct commands using `eval`.

## Portable archive names

The writer and reader reject names that are unsafe or ambiguous on common platforms, including absolute paths, traversal components, drive prefixes, control characters, alternate data streams, reserved Windows device names, trailing dots/spaces, duplicate names, and case-fold collisions.

Symbolic links are not archived. Special filesystem objects such as sockets, FIFOs, and device nodes are not archived or restored.

## Permissions

On Unix-like systems, newly written `.sc` files and recovery-token files are created with owner-only permissions where supported. Token files with group or world permissions are rejected. Windows ACL behavior depends on the user's environment and is not equivalent to POSIX mode bits.

## Filesystem race limitations

The tool stages extraction under a newly created private directory and rejects symlink components. It cannot provide a universal guarantee against a privileged local attacker or every concurrent filesystem race on every operating system.
