use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub fn validate_token(token: &str) -> Result<()> {
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(token)
            .context("Invalid recovery token encoding")?,
    );
    if token.len() != 43 || decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != token {
        bail!("Invalid recovery token format.");
    }
    Ok(())
}

pub fn read_token_file(path: &Path) -> Result<Zeroizing<String>> {
    let metadata = fs::symlink_metadata(path).context("Could not inspect recovery-token file")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("Recovery-token path must be a regular file, not a symbolic link.");
    }
    if metadata.len() > 128 {
        bail!("Recovery-token file is too large.");
    }
    let mut open_options = OpenOptions::new();
    open_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = open_options.open(path).context("Could not safely open recovery-token file")?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        bail!("Recovery-token path must be a regular file.");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if opened_metadata.permissions().mode() & 0o077 != 0 {
            bail!("Recovery-token file permissions are too broad; use chmod 600.");
        }
    }

    let mut raw = Vec::with_capacity(128);
    file.take(129).read_to_end(&mut raw)?;
    if raw.len() > 128 {
        raw.zeroize();
        bail!("Recovery-token file is too large.");
    }
    let mut contents = Zeroizing::new(
        String::from_utf8(raw).context("Recovery-token file is not valid UTF-8")?,
    );
    let token = Zeroizing::new(contents.trim().to_owned());
    contents.zeroize();
    validate_token(token.as_str())?;
    Ok(token)
}

pub fn generate_recovery_token() -> Result<Zeroizing<String>> {
    let mut raw = [0_u8; 32];
    getrandom::fill(&mut raw).context("Secure random generator failed")?;
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(raw));
    raw.zeroize();
    Ok(token)
}

pub fn save_recovery_token(token: &str, path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("Recovery file already exists or cannot be created: {}", path.display()))?;
    file.write_all(token.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_256_bit_token() {
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(validate_token(token).is_ok());
    }

    #[test]
    fn rejects_non_canonical_base64url_tail_bits() {
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB";
        assert!(validate_token(token).is_err());
    }

    #[test]
    fn generated_token_passes_validation() -> Result<()> {
        let token = generate_recovery_token()?;
        assert_eq!(token.len(), 43);
        validate_token(token.as_str())?;
        Ok(())
    }
}
