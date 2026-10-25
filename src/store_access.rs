//! Integration policy: one store per operation. Cross-store inputs are rejected.
use crate::store_lease::StoreLease;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub fn validate_root(root: &Path, lease: &StoreLease) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(root)?;
        let id = lease.root_identity();
        if m.is_dir() && m.dev() == id.device && m.ino() == id.inode {
            return Ok(());
        }
    }
    let _ = (root, lease);
    Err(io::Error::other(
        "store lease root identity mismatch or unsupported platform",
    ))
}

// Resolve existing ancestors even for a not-yet-created output, including aliases.
pub fn resolved(path: &Path) -> io::Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(p) => Ok(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let absolute = std::path::absolute(path)?;
            let parent = absolute.parent().ok_or(e)?;
            Ok(resolved(parent)?.join(
                absolute
                    .file_name()
                    .ok_or_else(|| io::Error::other("invalid path"))?,
            ))
        }
        Err(e) => Err(e),
    }
}

/// Explicit paths never bypass store coordination. Recognizes the configured
/// store, persistent lease markers, and legacy managed cache/build areas.
/// shortcut: unmarked arbitrary external directories are caller-owned; introduce
/// ownership records before supporting maintenance of additional store formats.
pub fn validate_path(path: &Path, lease: Option<&StoreLease>) -> io::Result<()> {
    let path = resolved(path)?;
    let configured = resolved(&crate::store_inventory::resolve_store()?)?;
    for ancestor in path.ancestors() {
        if fs::metadata(ancestor).is_ok_and(|m| !m.is_dir()) {
            continue;
        }
        let area = ancestor.file_name().and_then(|n| n.to_str());
        let legacy_root =
            area.is_some_and(|n| matches!(n, "cache-v1" | "cache-v2" | "base-cache-v1"));
        let root = if ancestor == configured
            || marker_exists(&ancestor.join("store.lock"))?
            || ancestor.join("cache-v1").is_dir()
            || marker_exists(&ancestor.join("cache-v2"))?
            || ancestor.join("base-cache-v1").is_dir()
        {
            Some(ancestor)
        } else if legacy_root {
            ancestor.parent()
        } else {
            None
        };
        if let Some(root) = root {
            let lease = lease.ok_or_else(|| {
                io::Error::other(
                    "managed path requires a borrowed store lease; use build_with_lease",
                )
            })?;
            validate_root(root, lease).map_err(|_| {
                io::Error::other(
                    "cross-store managed input rejected; copy it outside managed stores first",
                )
            })?;
        }
    }
    Ok(())
}

// Even an invalid/dangling marker identifies a store boundary: never turn a
// malformed managed store into an unleased input by following the marker.
fn marker_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
