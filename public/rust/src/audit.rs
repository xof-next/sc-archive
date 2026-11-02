use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn audit(action: &str, result: &str, version: &str) {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let Some(home) = home else { return };
    let dir = home.join(".sc-archive");
    if fs::symlink_metadata(&dir)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        eprintln!("Warning: local audit directory is a symbolic link; audit skipped.");
        return;
    }
    if fs::create_dir_all(&dir).is_err() {
        eprintln!("Warning: local audit log could not be written.");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }

    let path = dir.join("audit.jsonl");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            eprintln!("Warning: local audit path is not a regular file; audit skipped.");
            return;
        }
        Ok(metadata) if metadata.len() >= 1_048_576 => {
            if rotate(&dir, &path).is_err() {
                eprintln!("Warning: local audit log rotation failed.");
                return;
            }
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            eprintln!("Warning: local audit path could not be inspected.");
            return;
        }
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    if let Ok(mut file) = options.open(&path) {
        if !file.metadata().map(|metadata| metadata.is_file()).unwrap_or(false) {
            eprintln!("Warning: local audit log is not a regular file; audit skipped.");
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        let line = format!(
            "{{\"at_unix\":{timestamp},\"action\":\"{action}\",\"result\":\"{result}\",\"version\":\"{version}\"}}\n"
        );
        if file.write_all(line.as_bytes()).is_err() || file.flush().is_err() {
            eprintln!("Warning: local audit log could not be written.");
        }
    } else {
        eprintln!("Warning: local audit log could not be opened safely.");
    }
}

fn rotate(directory: &std::path::Path, current: &std::path::Path) -> std::io::Result<()> {
    for index in (1..=3).rev() {
        let source = if index == 1 {
            current.to_path_buf()
        } else {
            directory.join(format!("audit.jsonl.{}", index - 1))
        };
        let destination = directory.join(format!("audit.jsonl.{index}"));
        match fs::symlink_metadata(&source) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        match fs::symlink_metadata(&destination) {
            Ok(existing) if existing.is_dir() && !existing.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "audit rotation destination is a directory",
                ));
            }
            Ok(_) => fs::remove_file(&destination)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::rename(&source, &destination)?;
    }
    Ok(())
}
