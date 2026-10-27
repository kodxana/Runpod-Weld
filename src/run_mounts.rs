//! Bounded RUN materialization for the trusted, stable-tree worker profile.
//!
//! No kernel mounts or namespaces are used. The builder must retain the guard
//! until the lease supervisor has reaped ALL descendants, then finish it before
//! taking any filesystem checkpoint. Secret bytes never belong in this API's AST.

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};

/// Mount descriptions, safe to include in instruction identity (no source paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mount {
    Secret {
        id: String,
        target: String,
        required: bool,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Cache {
        id: String,
        target: String,
        mode: u32,
        uid: u32,
        gid: u32,
    },
}

impl Mount {
    pub fn target(&self) -> &str {
        match self {
            Self::Secret { target, .. } | Self::Cache { target, .. } => target,
        }
    }
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret { .. })
    }
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("secret_count", &self.secrets.len())
            .field("cache_dir", &self.cache_dir)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Local inputs; deliberately absent from instruction/stage fingerprints.
#[derive(Clone, Default)]
pub struct Options {
    pub secrets: BTreeMap<String, PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub limits: Limits,
}

/// Aggregate persisted and per-RUN package data ceilings; builds use rootfs limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_entries: usize,
    pub max_metadata_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_CACHE_BYTES,
            max_entries: MAX_CACHE_ENTRIES,
            max_metadata_bytes: 64 * 1024 * 1024,
        }
    }
}

pub const MAX_MOUNTS: usize = 8;
pub const MAX_SECRET_BYTES: u64 = 64 * 1024;
pub const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_CACHE_ENTRIES: usize = 262_144;
pub const MAX_CACHE_DEPTH: usize = 32;

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn valid_target(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 1024
        && value != "/"
        && value[1..].split('/').count() <= MAX_CACHE_DEPTH
        && value[1..].split('/').all(|s| {
            !s.is_empty()
                && s.len() <= 255
                && s != "."
                && s != ".."
                && !s.chars().any(|c| c.is_control() || c == '\\' || c == '$')
        })
        && !["/proc", "/dev", "/sys"]
            .iter()
            .any(|s| value == *s || value.starts_with(&format!("{s}/")))
}

/// Parse repeatable Docker-style mount flags, returning the untouched command.
pub fn parse(mut payload: &str) -> Result<(Vec<Mount>, &str), String> {
    let mut mounts = Vec::new();
    while payload.starts_with("--") {
        let (flag, command) = payload
            .split_once([' ', '\t'])
            .ok_or("RUN mount requires a command")?;
        let options = flag
            .strip_prefix("--mount=")
            .ok_or("unsupported RUN flag")?;
        let mut fields = BTreeMap::new();
        for option in options.split(',') {
            let (key, value) = option
                .split_once('=')
                .ok_or("mount options must be key=value")?;
            if value.is_empty() || fields.insert(key, value).is_some() {
                return Err("empty or duplicate mount option".into());
            }
        }
        let kind = fields.remove("type").ok_or("mount requires type")?;
        let id = fields.remove("id");
        let target = fields.remove("target");
        let mode = fields
            .remove("mode")
            .map(|s| u32::from_str_radix(s, 8).map_err(|_| "invalid mount mode"))
            .transpose()?;
        if mode.is_some_and(|n| n > 0o777) {
            return Err("mount mode supports only permission bits".into());
        }
        let number = |s: Option<&str>| -> Result<u32, String> {
            match s {
                Some(s) if !s.bytes().all(|b| b.is_ascii_digit()) => {
                    Err("invalid mount uid/gid".into())
                }
                Some(s) => s
                    .parse::<u32>()
                    .ok()
                    .filter(|n| *n <= i32::MAX as u32)
                    .ok_or("invalid mount uid/gid".into()),
                None => Ok(0),
            }
        };
        let uid = number(fields.remove("uid"))?;
        let gid = number(fields.remove("gid"))?;
        let mount = match kind {
            "secret" => {
                let id = id
                    .filter(|id| valid_id(id))
                    .ok_or("secret requires a simple id")?
                    .to_owned();
                let target = target
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("/run/secrets/{id}"));
                let required = match fields.remove("required") {
                    None | Some("false") => false,
                    Some("true") => true,
                    _ => return Err("secret required must be true or false".into()),
                };
                Mount::Secret {
                    id,
                    target,
                    required,
                    mode: mode.unwrap_or(0o400),
                    uid,
                    gid,
                }
            }
            "cache" => {
                let target = target.ok_or("cache mount requires target")?.to_owned();
                match fields.remove("sharing") {
                    None | Some("shared" | "locked") => (),
                    _ => {
                        return Err(
                            "cache sharing supports shared/locked only (both serialized)".into(),
                        );
                    }
                }
                if id.is_some_and(|id| !valid_id(id)) {
                    return Err("cache id must be a simple identifier".into());
                }
                Mount::Cache {
                    id: id.unwrap_or(&target).to_owned(),
                    target,
                    mode: mode.unwrap_or(0o755),
                    uid,
                    gid,
                }
            }
            _ => return Err("RUN supports secret and cache mounts only".into()),
        };
        if !fields.is_empty() {
            return Err("unsupported mount option".into());
        }
        mounts.push(mount);
        if mounts.len() > MAX_MOUNTS {
            return Err("at most 8 RUN mounts are supported".into());
        }
        payload = command.trim_start_matches([' ', '\t']);
    }
    if payload.is_empty() {
        return Err("RUN requires a command".into());
    }
    validate_mounts(&mounts).map_err(|e| e.to_string())?;
    Ok((mounts, payload))
}

fn validate_mounts(mounts: &[Mount]) -> io::Result<()> {
    if mounts.len() > MAX_MOUNTS {
        return Err(invalid("at most 8 RUN mounts are supported"));
    }
    if mounts.iter().any(Mount::is_secret) && mounts.iter().any(|m| !m.is_secret()) {
        return Err(invalid(
            "secret and cache mounts cannot share a RUN in this profile",
        ));
    }
    for (index, mount) in mounts.iter().enumerate() {
        if !valid_target(mount.target()) {
            return Err(invalid(
                "mount target must be normalized, at most 1024 bytes/32 components, outside /proc, /dev and /sys",
            ));
        }
        let (id, mode, uid, gid) = match mount {
            Mount::Secret {
                id, mode, uid, gid, ..
            }
            | Mount::Cache {
                id, mode, uid, gid, ..
            } => (id, mode, uid, gid),
        };
        if (!valid_id(id) && (mount.is_secret() || id != mount.target()))
            || *mode > 0o777
            || *uid > i32::MAX as u32
            || *gid > i32::MAX as u32
        {
            return Err(invalid("invalid mount id/mode/uid/gid"));
        }
        for old in &mounts[..index] {
            if Path::new(old.target()).starts_with(mount.target())
                || Path::new(mount.target()).starts_with(old.target())
            {
                return Err(invalid("overlapping mount targets"));
            }
            if let Mount::Cache { id: old_id, .. } = old
                && !mount.is_secret()
                && old_id == id
            {
                return Err(invalid("repeated cache id in one RUN is unsupported"));
            }
        }
    }
    Ok(())
}

/// Parse an explicit file source. Environment secret sources are unsupported.
pub fn parse_secret(value: &str) -> Result<(String, PathBuf), String> {
    let mut fields = BTreeMap::new();
    for item in value.split(',') {
        let (key, value) = item
            .split_once('=')
            .ok_or("--secret requires id=ID,src=FILE")?;
        if value.is_empty() || fields.insert(key, value).is_some() {
            return Err("invalid --secret mapping".into());
        }
    }
    let id = fields
        .remove("id")
        .filter(|s| valid_id(s))
        .ok_or("--secret requires a simple id")?;
    let source = fields
        .remove("src")
        .ok_or("--secret requires src (env sources unsupported)")?;
    if !fields.is_empty() {
        return Err("unsupported --secret option".into());
    }
    Ok((id.into(), source.into()))
}

/// Measured additional allocation, checked before each known-size copy.
pub type Admission<'a> = Option<&'a dyn Fn(&Path, u64, u64) -> io::Result<()>>;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{MountGuard, validate_inputs, validate_targets};

#[cfg(not(target_os = "linux"))]
pub fn validate_inputs(
    _: &Options,
    _: &[&Path],
    _: Option<&crate::store_lease::StoreLease>,
) -> io::Result<()> {
    Err(invalid("RUN mounts require Linux"))
}
