use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use rpassword::prompt_password as read_password;
use scrypt::{Params, scrypt};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use walkdir::WalkDir;
mod audit;
mod secure_paths;
mod token_store;

use audit::audit;
use secure_paths::{
    ensure_outside_source, register_zip_path, reject_symlink_components, safe_zip_relative_path,
    validate_archive_path,
};
use token_store::{generate_recovery_token, read_token_file, save_recovery_token, validate_token};
use zeroize::{Zeroize, Zeroizing};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const MAGIC: &[u8; 4] = b"SCAR";
const FORMAT_VERSION: u8 = 2;
const VERSION_TEXT: &str = "1.0.0";
const STANDARD_LOG_N: u8 = 17;
const HIGH_LOG_N: u8 = 18;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const NONCE_PREFIX_LEN: usize = 8;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 1_048_576;
const PREFIX_LEN: usize = 58;
const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;
const HEADER_LEN: usize = PREFIX_LEN + NONCE_LEN + WRAPPED_KEY_LEN + NONCE_LEN + WRAPPED_KEY_LEN;
const MAX_ENTRIES: usize = 50_000;
const MAX_ENTRY_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_EXTRACT_SIZE: u64 = 4 * 1024 * 1024 * 1024;
const PASSWORD_AAD: &[u8] = b"SCAR-V2-PASSWORD-WRAP";
const RECOVERY_AAD: &[u8] = b"SCAR-V2-RECOVERY-WRAP";

#[derive(Parser)]
#[command(
    name = "sc",
    version = VERSION_TEXT,
    about = "Encrypted .sc archives with password and admin recovery credentials",
    long_about = "SC Archive creates opaque .sc files. The entire ZIP payload is encrypted; file names and folder structure are not exposed."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Copy)]
enum Obfuscation {
    Standard,
    High,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an encrypted .sc archive and generate a one-time recovery token.
    Pack {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "standard")]
        obfuscation: Obfuscation,
        #[arg(long)]
        recovery_file: Option<PathBuf>,
    },
    /// Restore an archive using its password.
    Unpack {
        archive: PathBuf,
        #[arg(short = 'C', long = "output-dir")]
        output: Option<PathBuf>,
    },
    /// Restore an archive using its admin recovery token.
    Recover {
        archive: PathBuf,
        #[arg(short = 'C', long = "output-dir")]
        output: Option<PathBuf>,
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Display safe archive metadata without unlocking the archive.
    Inspect { archive: PathBuf },
    /// Authenticate all records and validate the encrypted ZIP payload.
    Verify {
        archive: PathBuf,
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
}

fn prompt_password(confirm: bool, new_archive: bool) -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(read_password("Password: ").context("Could not read password")?);
    let minimum = if new_archive { 16 } else { 12 };
    if password.chars().count() < minimum {
        bail!("Password must contain at least {minimum} characters.");
    }
    if password.len() > 4096 {
        bail!("Password is too long (maximum 4096 UTF-8 bytes).");
    }
    if new_archive {
        if password.chars().any(char::is_control) {
            bail!("Password must not contain control characters.");
        }
        if password
            .chars()
            .collect::<std::collections::HashSet<_>>()
            .len()
            == 1
        {
            bail!("Password must not consist of one repeated character.");
        }
    }
    if confirm {
        let second = Zeroizing::new(
            read_password("Confirm password: ").context("Could not read password confirmation")?,
        );
        if password.as_str() != second.as_str() {
            bail!("Passwords do not match.");
        }
    }
    Ok(password)
}

fn derive_key(secret: &str, salt: &[u8], log_n: u8) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params =
        Params::new(log_n, SCRYPT_R, SCRYPT_P).map_err(|_| anyhow!("Invalid scrypt parameters"))?;
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    scrypt(secret.as_bytes(), salt, &params, &mut key[..])
        .map_err(|_| anyhow!("Could not derive encryption key"))?;
    Ok(key)
}

fn make_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u32) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn make_prefix(
    password_salt: &[u8; SALT_LEN],
    recovery_salt: &[u8; SALT_LEN],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    log_n: u8,
) -> [u8; PREFIX_LEN] {
    let mut prefix = [0_u8; PREFIX_LEN];
    let mut cursor = 0;
    prefix[cursor..cursor + 4].copy_from_slice(MAGIC);
    cursor += 4;
    prefix[cursor] = FORMAT_VERSION;
    cursor += 1;
    prefix[cursor] = log_n;
    cursor += 1;
    prefix[cursor..cursor + 4].copy_from_slice(&SCRYPT_R.to_be_bytes());
    cursor += 4;
    prefix[cursor..cursor + 4].copy_from_slice(&SCRYPT_P.to_be_bytes());
    cursor += 4;
    prefix[cursor..cursor + SALT_LEN].copy_from_slice(password_salt);
    cursor += SALT_LEN;
    prefix[cursor..cursor + SALT_LEN].copy_from_slice(recovery_salt);
    cursor += SALT_LEN;
    prefix[cursor..cursor + NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
    cursor += NONCE_PREFIX_LEN;
    prefix[cursor..cursor + 4].copy_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
    prefix
}

fn make_aad(prefix: &[u8], label: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + label.len());
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(label);
    aad
}

fn wrap_data_key(
    credential: &str,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    prefix: &[u8; PREFIX_LEN],
    label: &[u8],
    data_key: &[u8; KEY_LEN],
    log_n: u8,
) -> Result<Vec<u8>> {
    let wrapping_key = derive_key(credential, salt, log_n)?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key[..])
        .map_err(|_| anyhow!("Invalid wrapping key"))?;
    let aad = make_aad(prefix, label);
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: data_key,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("Could not wrap archive data key"))
}

fn unwrap_data_key(
    header: &[u8; HEADER_LEN],
    credential: &str,
    recovery_mode: bool,
    log_n: u8,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let prefix = &header[..PREFIX_LEN];
    let (salt_range, nonce_range, wrap_range, label) = if recovery_mode {
        (30..46, 118..130, 130..178, RECOVERY_AAD)
    } else {
        (14..30, 58..70, 70..118, PASSWORD_AAD)
    };
    let salt: [u8; SALT_LEN] = header[salt_range].try_into()?;
    let nonce: [u8; NONCE_LEN] = header[nonce_range].try_into()?;
    let wrapping_key = derive_key(credential, &salt, log_n)?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key[..])
        .map_err(|_| anyhow!("Invalid wrapping key"))?;
    let aad = make_aad(prefix, label);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &header[wrap_range],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow!("Authentication failed: incorrect credential or damaged archive")
            })?,
    );
    if plaintext.len() != KEY_LEN {
        bail!("Invalid wrapped data key.");
    }
    let mut data_key = Zeroizing::new([0_u8; KEY_LEN]);
    data_key.copy_from_slice(plaintext.as_slice());
    Ok(data_key)
}

fn create_zip(input_path: &Path, zip_path: &Path) -> Result<()> {
    let original_metadata = fs::symlink_metadata(input_path)?;
    if original_metadata.file_type().is_symlink() {
        bail!("Symbolic links are not accepted as input.");
    }
    let input = fs::canonicalize(input_path).context("Input path could not be resolved")?;
    let metadata = fs::metadata(&input)?;
    if !metadata.is_file() && !metadata.is_dir() {
        bail!("Input must be a regular file or directory.");
    }

    let output = File::create(zip_path)?;
    let mut zip = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut item_count = 0_usize;
    let mut total_size = 0_u64;

    let mut registry = HashMap::new();
    if metadata.is_file() {
        total_size = metadata.len();
        if total_size > MAX_ENTRY_SIZE || total_size > MAX_EXTRACT_SIZE {
            bail!("Input file exceeds the archive safety limit.");
        }
        let name = input
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("Input filename must be valid UTF-8"))?
            .replace('\\', "/");
        let safe_name = safe_zip_relative_path(&name, false)?;
        register_zip_path(&mut registry, &safe_name, false)?;
        zip.start_file(name, options.clone())?;
        let mut source = File::open(&input)?;
        std::io::copy(&mut source, &mut zip)?;
    } else {
        let parent = input.parent().unwrap_or(Path::new("."));
        let root_name = input
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("Input directory name must be valid UTF-8"))?
            .replace('\\', "/");
        let safe_root = safe_zip_relative_path(&format!("{root_name}/"), true)?;
        register_zip_path(&mut registry, &safe_root, true)?;
        zip.add_directory(format!("{root_name}/"), options.clone())?;
        item_count += 1;

        for entry in WalkDir::new(&input).follow_links(false).sort_by_file_name() {
            let entry = entry.context("Could not walk input directory")?;
            let path = entry.path();
            if path == input.as_path() {
                continue;
            }
            if entry.file_type().is_symlink() {
                bail!("Symbolic links are not accepted: {}", path.display());
            }
            item_count += 1;
            if item_count > MAX_ENTRIES {
                bail!("Input contains too many filesystem entries.");
            }
            let relative = path
                .strip_prefix(parent)?
                .to_str()
                .ok_or_else(|| anyhow!("Input path contains non-UTF-8 characters"))?
                .replace('\\', "/");
            if entry.file_type().is_dir() {
                let safe_relative =
                    safe_zip_relative_path(&format!("{}/", relative.trim_end_matches('/')), true)?;
                register_zip_path(&mut registry, &safe_relative, true)?;
                zip.add_directory(
                    format!("{}/", relative.trim_end_matches('/')),
                    options.clone(),
                )?;
            } else if entry.file_type().is_file() {
                let file_size = entry.metadata()?.len();
                if file_size > MAX_ENTRY_SIZE {
                    bail!(
                        "Input file exceeds the per-file safety limit: {}",
                        path.display()
                    );
                }
                total_size = total_size
                    .checked_add(file_size)
                    .ok_or_else(|| anyhow!("Input size overflow"))?;
                if total_size > MAX_EXTRACT_SIZE {
                    bail!("Input exceeds the total archive safety limit.");
                }
                let safe_relative = safe_zip_relative_path(&relative, false)?;
                register_zip_path(&mut registry, &safe_relative, false)?;
                zip.start_file(relative, options.clone())?;
                let mut source = File::open(path)?;
                std::io::copy(&mut source, &mut zip)?;
            } else {
                bail!("Unsupported filesystem object: {}", path.display());
            }
        }
    }
    zip.finish()?;
    Ok(())
}

fn create_private_new(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn encrypt_zip(
    zip_path: &Path,
    output_path: &Path,
    password: &str,
    recovery_token: &str,
    log_n: u8,
) -> Result<()> {
    let mut password_salt = [0_u8; SALT_LEN];
    let mut recovery_salt = [0_u8; SALT_LEN];
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_LEN];
    let mut password_nonce = [0_u8; NONCE_LEN];
    let mut recovery_nonce = [0_u8; NONCE_LEN];
    let mut data_key_bytes = [0_u8; KEY_LEN];
    getrandom::fill(&mut password_salt).context("Secure random generator failed")?;
    getrandom::fill(&mut recovery_salt).context("Secure random generator failed")?;
    getrandom::fill(&mut nonce_prefix).context("Secure random generator failed")?;
    getrandom::fill(&mut password_nonce).context("Secure random generator failed")?;
    getrandom::fill(&mut recovery_nonce).context("Secure random generator failed")?;
    getrandom::fill(&mut data_key_bytes).context("Secure random generator failed")?;
    let data_key = Zeroizing::new(data_key_bytes);
    data_key_bytes.zeroize();

    let prefix = make_prefix(&password_salt, &recovery_salt, &nonce_prefix, log_n);
    let password_wrap = wrap_data_key(
        password,
        &password_salt,
        &password_nonce,
        &prefix,
        PASSWORD_AAD,
        &data_key,
        log_n,
    )?;
    let recovery_wrap = wrap_data_key(
        recovery_token,
        &recovery_salt,
        &recovery_nonce,
        &prefix,
        RECOVERY_AAD,
        &data_key,
        log_n,
    )?;
    if password_wrap.len() != WRAPPED_KEY_LEN || recovery_wrap.len() != WRAPPED_KEY_LEN {
        bail!("Unexpected wrapped key length.");
    }

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&prefix);
    header.extend_from_slice(&password_nonce);
    header.extend_from_slice(&password_wrap);
    header.extend_from_slice(&recovery_nonce);
    header.extend_from_slice(&recovery_wrap);
    if header.len() != HEADER_LEN {
        bail!("Internal header length mismatch.");
    }

    let cipher =
        Aes256Gcm::new_from_slice(&data_key[..]).map_err(|_| anyhow!("Invalid AES key"))?;
    let mut output = create_private_new(output_path).with_context(|| {
        format!(
            "Output already exists or cannot be created: {}",
            output_path.display()
        )
    })?;

    let result = (|| -> Result<()> {
        output.write_all(&header)?;
        let mut input = File::open(zip_path)?;
        let mut buffer = vec![0_u8; CHUNK_SIZE];
        let mut counter: u32 = 0;
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            if counter == u32::MAX {
                bail!("Archive is too large for this format version.");
            }
            let length = read as u32;
            let mut aad = Vec::with_capacity(HEADER_LEN + 8);
            aad.extend_from_slice(&header);
            aad.extend_from_slice(&counter.to_be_bytes());
            aad.extend_from_slice(&length.to_be_bytes());
            let nonce_bytes = make_nonce(&nonce_prefix, counter);
            let encrypted = cipher
                .encrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: &buffer[..read],
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow!("Could not encrypt archive block"))?;
            output.write_all(&length.to_be_bytes())?;
            output.write_all(&encrypted)?;
            counter += 1;
        }
        let mut terminal_aad = Vec::with_capacity(HEADER_LEN + 8);
        terminal_aad.extend_from_slice(&header);
        terminal_aad.extend_from_slice(&counter.to_be_bytes());
        terminal_aad.extend_from_slice(&0_u32.to_be_bytes());
        let terminal_nonce = make_nonce(&nonce_prefix, counter);
        let terminal = cipher
            .encrypt(
                Nonce::from_slice(&terminal_nonce),
                Payload {
                    msg: &[],
                    aad: &terminal_aad,
                },
            )
            .map_err(|_| anyhow!("Could not authenticate archive terminator"))?;
        output.write_all(&0_u32.to_be_bytes())?;
        output.write_all(&terminal)?;
        output.flush()?;
        output.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(output_path);
    }
    result
}

fn read_exact<const N: usize>(input: &mut File) -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    input
        .read_exact(&mut bytes)
        .context("Damaged or incomplete archive")?;
    Ok(bytes)
}

fn decrypt_archive(
    archive_path: &Path,
    zip_path: &Path,
    credential: &str,
    recovery_mode: bool,
) -> Result<()> {
    validate_archive_path(archive_path)?;
    let mut input = File::open(archive_path).context("Could not open .sc archive")?;
    let prefix = read_exact::<PREFIX_LEN>(&mut input)?;
    if &prefix[..4] != MAGIC {
        bail!("This is not a supported SC Archive.");
    }
    let version = prefix[4];
    let log_n = prefix[5];
    let r = u32::from_be_bytes(prefix[6..10].try_into()?);
    let p = u32::from_be_bytes(prefix[10..14].try_into()?);
    let chunk_size = u32::from_be_bytes(prefix[54..58].try_into()?) as usize;
    if version != FORMAT_VERSION
        || (log_n != STANDARD_LOG_N && log_n != HIGH_LOG_N)
        || r != SCRYPT_R
        || p != SCRYPT_P
        || chunk_size != CHUNK_SIZE
    {
        bail!("Unsupported or invalid archive parameters.");
    }

    let mut header = [0_u8; HEADER_LEN];
    header[..PREFIX_LEN].copy_from_slice(&prefix);
    input
        .read_exact(&mut header[PREFIX_LEN..])
        .context("Damaged or incomplete archive header")?;
    let nonce_prefix: [u8; NONCE_PREFIX_LEN] = header[46..54].try_into()?;
    let data_key = unwrap_data_key(&header, credential, recovery_mode, log_n)?;
    let cipher =
        Aes256Gcm::new_from_slice(&data_key[..]).map_err(|_| anyhow!("Invalid AES key"))?;
    let mut output = create_private_new(zip_path)?;
    let mut counter: u32 = 0;
    let mut total: u64 = 0;
    let mut chunk_count = 0_u64;

    loop {
        let length = u32::from_be_bytes(read_exact::<4>(&mut input)?) as usize;
        if length == 0 {
            let terminal = read_exact::<TAG_LEN>(&mut input)?;
            let mut terminal_aad = Vec::with_capacity(HEADER_LEN + 8);
            terminal_aad.extend_from_slice(&header);
            terminal_aad.extend_from_slice(&counter.to_be_bytes());
            terminal_aad.extend_from_slice(&0_u32.to_be_bytes());
            let terminal_nonce = make_nonce(&nonce_prefix, counter);
            cipher
                .decrypt(
                    Nonce::from_slice(&terminal_nonce),
                    Payload {
                        msg: &terminal,
                        aad: &terminal_aad,
                    },
                )
                .map_err(|_| anyhow!("Authentication failed: damaged archive"))?;
            break;
        }
        if length > CHUNK_SIZE {
            bail!("Invalid encrypted block size.");
        }
        if counter == u32::MAX {
            bail!("Archive contains too many blocks.");
        }
        let mut encrypted = vec![0_u8; length + TAG_LEN];
        input
            .read_exact(&mut encrypted)
            .context("Damaged or incomplete archive block")?;
        let mut aad = Vec::with_capacity(HEADER_LEN + 8);
        aad.extend_from_slice(&header);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad.extend_from_slice(&(length as u32).to_be_bytes());
        let nonce_bytes = make_nonce(&nonce_prefix, counter);
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &encrypted,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("Authentication failed: damaged archive"))?;
        if plain.len() != length {
            bail!("Invalid decrypted block length.");
        }
        total = total
            .checked_add(plain.len() as u64)
            .ok_or_else(|| anyhow!("Decrypted payload size overflow"))?;
        if total > MAX_EXTRACT_SIZE {
            bail!("Decrypted payload exceeds the safety limit.");
        }
        output.write_all(&plain)?;
        counter += 1;
        chunk_count += 1;
    }
    if chunk_count == 0 {
        bail!("Archive payload is empty or invalid.");
    }
    let mut trailing = [0_u8; 1];
    if input.read(&mut trailing)? != 0 {
        bail!("Unexpected trailing data in archive.");
    }
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn validate_zip(zip_path: &Path) -> Result<()> {
    let mut archive = ZipArchive::new(File::open(zip_path)?)?;
    if archive.is_empty() || archive.len() > MAX_ENTRIES {
        bail!("ZIP entry count is outside the safety limits.");
    }
    let mut registry = HashMap::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        if entry.is_symlink() {
            bail!("Symbolic-link entries are not supported.");
        }
        let is_directory = entry.is_dir();
        let relative = safe_zip_relative_path(entry.name(), is_directory)?;
        register_zip_path(&mut registry, &relative, is_directory)?;
        if is_directory {
            if entry.size() != 0 || entry.compressed_size() != 0 {
                bail!("ZIP directory entries must not contain file data.");
            }
            continue;
        }
        let declared = entry.size();
        if declared > MAX_ENTRY_SIZE {
            bail!("ZIP entry exceeds the per-file safety limit.");
        }
        total = total
            .checked_add(declared)
            .ok_or_else(|| anyhow!("ZIP expanded size overflow"))?;
        if total > MAX_EXTRACT_SIZE {
            bail!("ZIP expanded size exceeds the safety limit.");
        }
        let mut limited = entry.take(declared.saturating_add(1));
        let copied = std::io::copy(&mut limited, &mut std::io::sink())?;
        if copied != declared {
            bail!("ZIP entry size did not match its directory record.");
        }
    }
    Ok(())
}

fn extract_zip(zip_path: &Path, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    let root = fs::canonicalize(output_dir)?;
    let mut archive = ZipArchive::new(File::open(zip_path)?)?;
    let mut total_size = 0_u64;
    let mut registry = HashMap::new();
    if archive.is_empty() || archive.len() > MAX_ENTRIES {
        bail!("ZIP entry count is outside the safety limits.");
    }
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        if entry.is_symlink() {
            bail!("Symbolic-link entries are not restored.");
        }
        let is_directory = entry.is_dir();
        let relative = safe_zip_relative_path(entry.name(), is_directory)?;
        register_zip_path(&mut registry, &relative, is_directory)?;
        let destination = root.join(&relative);
        reject_symlink_components(&root, &destination)?;
        if is_directory {
            if entry.size() != 0 || entry.compressed_size() != 0 {
                bail!("ZIP directory entries must not contain file data.");
            }
            fs::create_dir_all(&destination)?;
            continue;
        }
        let entry_size = entry.size();
        if entry_size > MAX_ENTRY_SIZE {
            bail!("ZIP entry exceeds the safety limit.");
        }
        total_size = total_size
            .checked_add(entry_size)
            .ok_or_else(|| anyhow!("ZIP expanded size overflow"))?;
        if total_size > MAX_EXTRACT_SIZE {
            bail!("ZIP expanded size exceeds the safety limit.");
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
            reject_symlink_components(&root, parent)?;
        }
        let mut output = create_private_new(&destination)
            .with_context(|| format!("Refusing to overwrite: {}", destination.display()))?;
        let mut limited = entry.take(entry_size.saturating_add(1));
        let copied = std::io::copy(&mut limited, &mut output)?;
        if copied != entry_size {
            bail!("ZIP entry size did not match its directory record.");
        }
        output.flush()?;
        output.sync_all()?;
    }
    Ok(())
}

fn absolute_path(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn default_pack_output(input: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(input)?;
    let name = canonical
        .file_name()
        .ok_or_else(|| anyhow!("Input name is missing"))?
        .to_string_lossy();
    let parent = canonical
        .parent()
        .ok_or_else(|| anyhow!("Input parent directory is missing"))?;
    Ok(parent.join(format!("{name}.sc")))
}

fn default_unpack_output(archive: &Path) -> PathBuf {
    let stem = archive.file_stem().unwrap_or_default().to_string_lossy();
    archive
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{stem}_restored"))
}

fn restore_archive(
    archive: &Path,
    output: PathBuf,
    credential: &str,
    recovery_mode: bool,
) -> Result<()> {
    validate_archive_path(archive)?;
    if output.exists() || fs::symlink_metadata(&output).is_ok() {
        bail!("Destination already exists; choose a new output directory.");
    }
    let output = absolute_path(output)?;
    let parent = output
        .parent()
        .ok_or_else(|| anyhow!("Output directory has no parent"))?;
    fs::create_dir_all(parent)?;
    let work = tempdir()?;
    let zip_path = work.path().join("payload.zip");
    decrypt_archive(archive, &zip_path, credential, recovery_mode)?;
    let staging = tempfile::Builder::new()
        .prefix(".sc-extract-")
        .tempdir_in(parent)?;
    extract_zip(&zip_path, staging.path())?;
    if output.exists() {
        bail!("Destination appeared while extracting.");
    }
    let staging_path = staging.keep();
    if let Err(error) = fs::rename(&staging_path, &output) {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(error.into());
    }
    println!("Restored: {}", output.display());
    Ok(())
}

fn inspect_archive(archive: &Path) -> Result<()> {
    validate_archive_path(archive)?;
    let mut input = File::open(archive)?;
    let prefix = read_exact::<PREFIX_LEN>(&mut input)?;
    if &prefix[..4] != MAGIC || prefix[4] != FORMAT_VERSION {
        bail!("This is not a supported SC Archive.");
    }
    let log_n = prefix[5];
    let r = u32::from_be_bytes(prefix[6..10].try_into()?);
    let p = u32::from_be_bytes(prefix[10..14].try_into()?);
    let chunk = u32::from_be_bytes(prefix[54..58].try_into()?);
    if (log_n != STANDARD_LOG_N && log_n != HIGH_LOG_N)
        || r != SCRYPT_R
        || p != SCRYPT_P
        || chunk as usize != CHUNK_SIZE
    {
        bail!("Unsupported or invalid archive parameters.");
    }
    println!("Format: SCAR v{}", prefix[4]);
    println!(
        "Profile: {}",
        if log_n == HIGH_LOG_N {
            "high"
        } else {
            "standard"
        }
    );
    println!("KDF: scrypt (N=2^{log_n}, r={r}, p={p})");
    println!("Payload: AES-256-GCM, 1 MiB authenticated records");
    println!("Archive size: {} bytes", fs::metadata(archive)?.len());
    Ok(())
}

fn verify_archive(archive: &Path, credential: &str, recovery_mode: bool) -> Result<()> {
    validate_archive_path(archive)?;
    let work = tempdir()?;
    let zip_path = work.path().join("payload.zip");
    decrypt_archive(archive, &zip_path, credential, recovery_mode)?;
    validate_zip(&zip_path)?;
    println!(
        "Verification: passed (credential, authenticated records, terminal tag, ZIP structure)"
    );
    Ok(())
}

fn run(cli: Cli) -> Result<&'static str> {
    match cli.command {
        Commands::Pack {
            input,
            output,
            obfuscation,
            recovery_file,
        } => {
            let source_meta = fs::symlink_metadata(&input).context("Input path does not exist")?;
            if source_meta.file_type().is_symlink() {
                bail!("Symbolic links are not accepted as the input.");
            }
            let input = fs::canonicalize(&input)?;
            let output = match output {
                Some(path) => absolute_path(path)?,
                None => default_pack_output(&input)?,
            };
            if !output
                .to_string_lossy()
                .to_ascii_lowercase()
                .ends_with(".sc")
            {
                bail!("Output filename must end with .sc.");
            }
            if output.exists() || fs::symlink_metadata(&output).is_ok() {
                bail!("Output file already exists or is a symbolic link.");
            }
            ensure_outside_source(&input, &output, "Archive output")?;
            if let Some(token_path) = &recovery_file {
                ensure_outside_source(&input, token_path, "Recovery-token file")?;
                if token_path.exists() || fs::symlink_metadata(token_path).is_ok() {
                    bail!("Recovery-token file already exists.");
                }
                if absolute_path(token_path.clone())? == output {
                    bail!("Archive output and recovery-token file must be different paths.");
                }
            }
            let password = prompt_password(true, true)?;
            let recovery_token = generate_recovery_token()?;
            let log_n = match obfuscation {
                Obfuscation::Standard => STANDARD_LOG_N,
                Obfuscation::High => HIGH_LOG_N,
            };
            let work = tempdir()?;
            let zip_path = work.path().join("payload.zip");
            create_zip(&input, &zip_path)?;
            encrypt_zip(
                &zip_path,
                &output,
                password.as_str(),
                recovery_token.as_str(),
                log_n,
            )?;
            if let Some(path) = recovery_file {
                let path = absolute_path(path)?;
                match save_recovery_token(recovery_token.as_str(), &path) {
                    Ok(()) => println!("Recovery token saved: {}", path.display()),
                    Err(error) => {
                        eprintln!("Warning: could not save recovery token file: {error:#}")
                    }
                }
            }
            println!("Created: {}", output.display());
            println!(
                "Obfuscation: {}",
                if log_n == HIGH_LOG_N {
                    "high"
                } else {
                    "standard"
                }
            );
            println!("RECOVERY TOKEN (store securely; displayed only once):");
            println!("{}", recovery_token.as_str());
            Ok("pack")
        }
        Commands::Unpack { archive, output } => {
            let archive = absolute_path(archive)?;
            let output = output.unwrap_or_else(|| default_unpack_output(&archive));
            let password = Zeroizing::new(prompt_password(false, false)?);
            restore_archive(&archive, output, password.as_str(), false)?;
            Ok("unpack")
        }
        Commands::Recover {
            archive,
            output,
            token_file,
        } => {
            let archive = absolute_path(archive)?;
            let output = output.unwrap_or_else(|| default_unpack_output(&archive));
            let token = Zeroizing::new(match token_file {
                Some(path) => read_token_file(&path)?.as_str().to_owned(),
                None => read_password("Admin recovery token: ")
                    .context("Could not read recovery token")?,
            });
            validate_token(token.as_str())?;
            restore_archive(&archive, output, token.as_str(), true)?;
            Ok("recover")
        }
        Commands::Inspect { archive } => {
            let archive = absolute_path(archive)?;
            inspect_archive(&archive)?;
            Ok("inspect")
        }
        Commands::Verify {
            archive,
            token_file,
        } => {
            let archive = absolute_path(archive)?;
            let (credential, recovery_mode) = match token_file {
                Some(path) => (read_token_file(&path)?, true),
                None => (prompt_password(false, false)?, false),
            };
            verify_archive(&archive, credential.as_str(), recovery_mode)?;
            Ok("verify")
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let action = match &cli.command {
        Commands::Pack { .. } => "pack",
        Commands::Unpack { .. } => "unpack",
        Commands::Recover { .. } => "recover",
        Commands::Inspect { .. } => "inspect",
        Commands::Verify { .. } => "verify",
    };
    match run(cli) {
        Ok(completed_action) => audit(completed_action, "ok", VERSION_TEXT),
        Err(error) => {
            audit(action, "error", VERSION_TEXT);
            eprintln!("Error: {error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod format_tests {
    use super::*;
    use std::collections::HashMap;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn rejects_unsafe_zip_paths() {
        for value in [
            "../escape",
            "/absolute",
            "C:/drive",
            "folder/../../escape",
            "folder\\..\\escape",
            "CON",
            "folder/file:stream",
            "trailing.",
            "trailing ",
        ] {
            assert!(
                safe_zip_relative_path(value, false).is_err(),
                "accepted unsafe path: {value}"
            );
        }
    }

    #[test]
    fn accepts_safe_nested_zip_paths() -> Result<()> {
        let value = safe_zip_relative_path("folder/nested/file.txt", false)?;
        assert_eq!(
            value,
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

    #[test]
    fn cross_language_key_wrap_vector_matches_ruby() -> Result<()> {
        let password = "Cross-language passphrase 2026";
        let recovery_token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let password_salt = [b'P'; SALT_LEN];
        let recovery_salt = [b'R'; SALT_LEN];
        let nonce_prefix = [b'N'; NONCE_PREFIX_LEN];
        let password_nonce = [b'p'; NONCE_LEN];
        let recovery_nonce = [b'r'; NONCE_LEN];
        let data_key = [b'D'; KEY_LEN];
        let prefix = make_prefix(&password_salt, &recovery_salt, &nonce_prefix, 14);

        let password_wrap = wrap_data_key(
            password,
            &password_salt,
            &password_nonce,
            &prefix,
            PASSWORD_AAD,
            &data_key,
            14,
        )?;
        let recovery_wrap = wrap_data_key(
            recovery_token,
            &recovery_salt,
            &recovery_nonce,
            &prefix,
            RECOVERY_AAD,
            &data_key,
            14,
        )?;

        assert_eq!(
            to_hex(&password_wrap),
            "d38950ae3318bdd71bb554d2cba4d9dc84a9c4725dbf20ebd34d9608239fb2618e17115dc412847c2fb842a838bb517f"
        );
        assert_eq!(
            to_hex(&recovery_wrap),
            "de4645061092c8b19abcd45957b13a07c012342aa5725ce6d5977ebd21dbfac94a1d3f7399ae7b4b472e7a908e4a5d56"
        );

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&prefix);
        header.extend_from_slice(&password_nonce);
        header.extend_from_slice(&password_wrap);
        header.extend_from_slice(&recovery_nonce);
        header.extend_from_slice(&recovery_wrap);
        assert_eq!(header.len(), HEADER_LEN);

        let plaintext = b"Cross-language encrypted record fixture.";
        let counter = 7_u32;
        let mut aad = header.clone();
        aad.extend_from_slice(&counter.to_be_bytes());
        aad.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        let nonce = make_nonce(&nonce_prefix, counter);
        let payload_cipher =
            Aes256Gcm::new_from_slice(&data_key).map_err(|_| anyhow!("Invalid test AES key"))?;
        let payload_record = payload_cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("Test payload encryption failed"))?;
        assert_eq!(
            to_hex(&payload_record),
            "51f23b3c7f809b82e26eb3732cca95a2778894743fcd9dc80ae12e830f35eef98b8271e6b6d12ea184ad9458122c0897b40d40635b0f79d7"
        );
        Ok(())
    }
}
