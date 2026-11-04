use anyhow::{Result, bail};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

pub fn validate_archive_path(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| anyhow::anyhow!("Archive file does not exist"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("Archive path must be a regular file, not a symbolic link.");
    }
    if metadata.len() < 178 + 4 + 16 {
        bail!("Archive file is unexpectedly small.");
    }
    Ok(())
}

fn canonical_future_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut cursor = absolute;
    let mut missing_components = Vec::new();
    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = cursor
                    .file_name()
                    .ok_or_else(|| anyhow::anyhow!("Destination path could not be normalized"))?;
                missing_components.push(name.to_os_string());
                cursor = cursor
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("Destination path could not be normalized"))?
                    .to_path_buf();
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut resolved = fs::canonicalize(cursor)?;
    for component in missing_components.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

pub fn ensure_outside_source(source: &Path, destination: &Path, label: &str) -> Result<()> {
    let source = fs::canonicalize(source)?;
    let normalized_destination = canonical_future_path(destination)?;
    if source.is_dir() && normalized_destination.starts_with(&source) {
        bail!("{label} must be outside the source directory.");
    }
    if source.is_file() && normalized_destination == source {
        bail!("{label} must not overwrite the input file.");
    }
    Ok(())
}

pub fn safe_zip_relative_path(name: &str, is_directory: bool) -> Result<PathBuf> {
    let normalized = name.replace('\\', "/");
    if normalized.is_empty()
        || normalized.len() > 4096
        || normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized.as_bytes().contains(&0)
        || normalized.chars().any(char::is_control)
        || normalized.as_bytes().get(1) == Some(&b':')
        || (is_directory && normalized.ends_with("//"))
    {
        bail!("Unsafe path found in ZIP archive.");
    }

    let trimmed = if is_directory {
        normalized.trim_end_matches('/')
    } else {
        normalized.as_str()
    };
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.is_empty()
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.len() > 255
                || part.ends_with('.')
                || part.ends_with(' ')
                || part.contains(':')
        })
    {
        bail!("Unsafe path found in ZIP archive.");
    }

    for part in &parts {
        let stem = part.split('.').next().unwrap_or("");
        let upper = stem.to_ascii_uppercase();
        let numbered_device = upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0';
        if upper == "CON"
            || upper == "PRN"
            || upper == "AUX"
            || upper == "NUL"
            || upper == "CONIN$"
            || upper == "CONOUT$"
            || numbered_device
        {
            bail!("Unsafe path found in ZIP archive.");
        }
    }

    let mut path = PathBuf::new();
    for part in parts {
        path.push(part);
    }
    Ok(path)
}

pub fn register_zip_path(
    registry: &mut HashMap<String, u8>,
    relative: &Path,
    is_directory: bool,
) -> Result<()> {
    let portable = relative.to_string_lossy().replace('\\', "/");
    let normalized = portable.nfkc().collect::<String>();
    let pieces: Vec<String> = normalized.split('/').map(str::to_lowercase).collect();
    let key = pieces.join("/");
    let mut ancestors = Vec::new();
    for piece in pieces.iter().take(pieces.len().saturating_sub(1)) {
        ancestors.push(piece.clone());
        let parent_key = ancestors.join("/");
        if registry.get(&parent_key) == Some(&2) {
            bail!("ZIP file/directory path collision.");
        }
        registry.entry(parent_key).or_insert(0);
    }
    match registry.get(&key).copied() {
        Some(0) if is_directory => {
            registry.insert(key, 1);
        }
        Some(_) => bail!("Duplicate ZIP entry or cross-platform path collision."),
        None => {
            registry.insert(key, if is_directory { 1 } else { 2 });
        }
    }
    Ok(())
}

pub fn reject_symlink_components(root: &Path, destination: &Path) -> Result<()> {
    let relative = destination.strip_prefix(root)?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        cursor.push(component);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("Refusing to traverse a symbolic link during extraction.");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn rejects_destination_inside_source_through_symlink_with_missing_suffix() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir()?;
        let real = root.path().join("real");
        let source = real.join("project");
        fs::create_dir_all(&source)?;
        let alias = root.path().join("alias");
        symlink(&real, &alias)?;
        let destination = alias.join("project").join("not-created").join("archive.sc");
        assert!(ensure_outside_source(&source, &destination, "Archive output").is_err());
        Ok(())
    }

    #[test]
    fn rejects_traversal_and_windows_special_paths() {
        for name in [
            "../escape",
            "/absolute",
            "C:/drive",
            "folder/../../escape",
            "folder\\..\\escape",
            "CON",
            "folder/file:stream",
            "trailing.",
            "trailing ",
            "folder//",
        ] {
            assert!(
                safe_zip_relative_path(name, name.ends_with('/')).is_err(),
                "accepted {name}"
            );
        }
    }

    #[test]
    fn accepts_nested_relative_paths() -> Result<()> {
        let path = safe_zip_relative_path("folder/nested/file.txt", false)?;
        assert_eq!(
            path,
            PathBuf::from("folder").join("nested").join("file.txt")
        );
        Ok(())
    }

    #[test]
    fn rejects_casefold_duplicates() -> Result<()> {
        let mut registry = HashMap::new();
        let first = safe_zip_relative_path("Folder/item.txt", false)?;
        let second = safe_zip_relative_path("folder/ITEM.TXT", false)?;
        register_zip_path(&mut registry, &first, false)?;
        assert!(register_zip_path(&mut registry, &second, false).is_err());
        Ok(())
    }

    #[test]
    fn rejects_file_directory_collisions() -> Result<()> {
        let mut registry = HashMap::new();
        let first = safe_zip_relative_path("folder", false)?;
        let second = safe_zip_relative_path("folder/child.txt", false)?;
        register_zip_path(&mut registry, &first, false)?;
        assert!(register_zip_path(&mut registry, &second, false).is_err());
        Ok(())
    }
}
