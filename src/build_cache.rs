//! Private, content-keyed completed-stage cache. Never executes a cache entry.
//! Like COPY, fingerprinting requires a stable context. Reads may update source
//! atimes; key their post-read values, which subsequent COPY preflight observes.
//! Strict-atime mounts and external readers can therefore reduce cache reuse.
use crate::build::{Error, Limits};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Error>;

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

pub(crate) fn key(
    inputs: &[u8],
    context: Option<&Path>,
    limits: Limits,
    policy: &crate::dockerignore::Policy,
    cancelled: &impl Fn() -> bool,
) -> Result<String> {
    let mut hash = Sha256::new();
    field(&mut hash, b"weld-stage-cache-v3-copy-budgets");
    field(&mut hash, inputs);
    // Development builds share a version string: bind cache entries to executable bytes.
    let mut executable = fs::File::open(std::env::current_exe()?)?;
    if executable.metadata()?.len() > 64 * 1024 * 1024 {
        return Err("builder executable exceeds cache identity budget".into());
    }
    let mut buf = [0u8; 65536];
    loop {
        if cancelled() {
            return Err("cache hashing cancelled".into());
        }
        let n = executable.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    if let Some(root) = context {
        #[cfg(target_os = "linux")]
        field(
            &mut hash,
            &crate::context::fingerprint(
                root,
                policy,
                crate::context::Limits {
                    max_bytes: limits
                        .max_rootfs_bytes
                        .min(limits.layer.max_uncompressed_bytes),
                    max_entries: limits.max_rootfs_entries.min(limits.layer.max_entries),
                    max_metadata_bytes: limits.layer.max_metadata_bytes,
                },
                cancelled,
            )?,
        );
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, limits, policy);
            return Err("cache requires Linux".into());
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(crate) fn lookup(path: &Path, lease: Option<&crate::store_lease::StoreLease>) -> Result<bool> {
    crate::store_access::validate_path(path, lease)?;
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => Ok(true),
        Ok(_) => Err("cache entry must be a real directory".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn publish(
    source: &Path,
    lease: Option<&crate::store_lease::StoreLease>,
    destination: &Path,
    targets: Option<&[Vec<Vec<u8>>]>,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    crate::store_access::validate_path(source, lease)?;
    if lookup(destination, lease)? {
        return Ok(());
    }
    let temporary = tempfile::Builder::new()
        .prefix(".publish-")
        .tempdir_in(destination.parent().ok_or("cache parent missing")?)?;
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        if cancelled() {
            return Err("cache publication cancelled".into());
        }
        for e in fs::read_dir(source.join(&relative))? {
            let e = e?;
            if relative.as_os_str().is_empty() && e.file_name() == COPY_TARGETS {
                continue;
            }
            let child = relative.join(e.file_name());
            let target = temporary.path().join(&child);
            let kind = e.file_type()?;
            if kind.is_dir() {
                fs::create_dir(&target)?;
                pending.push(child);
            } else if kind.is_file() {
                fs::copy(e.path(), target)?;
            } else {
                return Err("cache publication requires a regular OCI layout".into());
            }
        }
    }
    if let Some(targets) = targets {
        fs::write(
            temporary.path().join(COPY_TARGETS),
            serde_json::to_vec(targets)?,
        )?;
    }
    match fs::rename(temporary.path(), destination) {
        Ok(()) => {
            let _ = temporary.keep();
            Ok(())
        }
        Err(_) if lookup(destination, lease)? => Ok(()), // A concurrent successful build won publication.
        Err(e) => Err(e.into()),
    }
}

const COPY_TARGETS: &str = "weld-copy-targets.json";

pub(crate) fn copy_targets(
    path: &Path,
    lease: Option<&crate::store_lease::StoreLease>,
    metadata_limit: u64,
) -> Result<Vec<Vec<Vec<u8>>>> {
    crate::store_access::validate_path(path, lease)?;
    // JSON byte arrays take at most four bytes per destination byte.
    let limit = metadata_limit.saturating_mul(6).max(2);
    if !fs::symlink_metadata(path.join(COPY_TARGETS))?.is_file() {
        return Err("cached COPY targets must be a regular file".into());
    }
    let file = fs::File::open(path.join(COPY_TARGETS))?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err("cached COPY targets exceed metadata budget".into());
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("cached COPY targets exceed metadata budget".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
