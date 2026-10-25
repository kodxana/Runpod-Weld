//! Resolve RUN identities from bounded, image-rooted account files, never host NSS.
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUser {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
    pub home: String,
}

const MAX_ID: u32 = i32::MAX as u32;
const MAX_NAME: usize = 256;
#[cfg(target_os = "linux")]
const MAX_HOME: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_GROUPS: usize = 65536;
#[cfg(target_os = "linux")]
const MAX_ACCOUNT_BYTES: u64 = 1024 * 1024;

fn id(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    value.parse::<u32>().ok().filter(|&n| n <= MAX_ID)
}

fn component(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_NAME {
        return Err("USER components must contain 1..256 bytes".into());
    }
    if value.bytes().all(|c| c.is_ascii_digit()) {
        return id(value)
            .map(|_| ())
            .ok_or("USER IDs must be 0..2147483647".into());
    }
    if !value
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        || value.starts_with('-')
    {
        return Err(
            "USER names must use ASCII letters, digits, '_', '.', '-' and cannot start with '-'"
                .into(),
        );
    }
    Ok(())
}

/// Empty metadata selects the legacy root identity. An explicit USER must be
/// a name or decimal ID, optionally followed by one group name or decimal ID.
pub fn validate_user_spec(spec: &str) -> Result<(), String> {
    if spec.is_empty() {
        return Ok(());
    }
    let (user, group) = spec
        .split_once(':')
        .map_or((spec, None), |(u, g)| (u, Some(g)));
    component(user)?;
    if let Some(group) = group {
        component(group)?;
    }
    Ok(())
}

pub fn resolve_user(rootfs: &Path, spec: &str) -> Result<ResolvedUser, String> {
    validate_user_spec(spec)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(rootfs)
            .map_err(|e| format!("USER rootfs: {e}"))?;
        resolve_pinned(&root, spec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = rootfs;
        Err("USER resolution requires Linux openat2".into())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn resolve_pinned(root: &std::fs::File, spec: &str) -> Result<ResolvedUser, String> {
    validate_user_spec(spec)?;
    let passwd = account_file(root, c"etc/passwd")?;
    // Empty metadata retains legacy groups and GID, but HOME still follows passwd.
    resolve_accounts(spec, &passwd, &account_file(root, c"etc/group")?)
}

#[cfg(target_os = "linux")]
fn account_file(root: &std::fs::File, path: &std::ffi::CStr) -> Result<String, String> {
    use std::{
        io::Read,
        os::fd::{AsRawFd, FromRawFd},
    };
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = How {
        // Fail rather than changing account-file timestamps if O_NOATIME is denied.
        // Following image symlinks may update their atime (as ordinary COPY does);
        // restoring it would change ctime and is not a read-only operation.
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOATIME) as u64,
        mode: 0,
        // IN_ROOT | NO_MAGICLINKS | NO_XDEV: absolute symlinks stay in the image.
        resolve: 16 | 2 | 1,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<How>(),
        )
    };
    let label = path.to_string_lossy();
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(String::new());
        }
        if error.raw_os_error() == Some(libc::EPERM) {
            return Err(format!(
                "USER {label}: account read denied: {error}; O_NOATIME requires file ownership or CAP_FOWNER; refusing to alter account timestamps"
            ));
        }
        return Err(format!(
            "USER {label}: confined account lookup failed: {error}"
        ));
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!(
            "USER {label}: account database must be a regular file"
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_ACCOUNT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("USER {label}: {e}"))?;
    if bytes.len() as u64 > MAX_ACCOUNT_BYTES {
        return Err(format!("USER {label}: account database exceeds 1 MiB"));
    }
    String::from_utf8(bytes)
        .map_err(|_| format!("USER {label}: account database must be valid UTF-8"))
}

#[cfg(target_os = "linux")]
fn resolve_accounts(spec: &str, passwd: &str, groups: &str) -> Result<ResolvedUser, String> {
    let (user, group) = spec
        .split_once(':')
        .map_or((spec, None), |(u, g)| (u, Some(g)));
    let numeric = if user.is_empty() { Some(0) } else { id(user) };
    let mut selected = None;
    for line in passwd
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7 {
            return Err("USER malformed passwd record (expected 7 fields)".into());
        }
        component(fields[0])?;
        let uid = id(fields[2]).ok_or("USER invalid passwd UID")?;
        let gid = id(fields[3]).ok_or("USER invalid passwd GID")?;
        if numeric.map_or(fields[0] == user, |n| uid == n) {
            if selected.is_some() {
                return Err("USER ambiguous matching passwd records".into());
            }
            let home = fields[5];
            if home.len() > MAX_HOME
                || home.contains('\0')
                || (!home.is_empty() && !home.starts_with('/'))
            {
                return Err(
                    "USER passwd HOME must be an absolute path of at most 4096 bytes without NUL"
                        .into(),
                );
            }
            selected = Some((fields[0], uid, gid, home));
        }
    }
    let uid = numeric
        .or_else(|| selected.map(|p| p.1))
        .ok_or_else(|| format!("USER {user:?}: no matching image passwd entry"))?;
    let mut result = ResolvedUser {
        uid,
        gid: selected.map_or(0, |p| p.2),
        supplementary_gids: Vec::new(),
        home: selected
            .filter(|p| !p.3.is_empty())
            .map_or("/", |p| p.3)
            .into(),
    };
    let mut explicit_gid = group.and_then(id);
    for line in groups
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 4 {
            return Err("USER malformed group record (expected 4 fields)".into());
        }
        component(fields[0])?;
        let gid = id(fields[2]).ok_or("USER invalid group GID")?;
        for member in fields[3].split(',').filter(|m| !m.is_empty()) {
            component(member)?;
        }
        if group.is_some_and(|g| id(g).is_none() && g == fields[0]) {
            if explicit_gid.is_some() {
                return Err("USER ambiguous matching group records".into());
            }
            explicit_gid = Some(gid);
        }
        if group.is_none() && selected.is_some_and(|p| fields[3].split(',').any(|m| m == p.0)) {
            result.supplementary_gids.push(gid);
            if result.supplementary_gids.len() > MAX_GROUPS {
                return Err("USER too many supplementary groups".into());
            }
        }
    }
    if let Some(group) = group {
        result.gid = explicit_gid
            .ok_or_else(|| format!("USER group {group:?}: no matching image group entry"))?;
    }
    result.supplementary_gids.sort_unstable();
    result.supplementary_gids.dedup();
    if spec.is_empty() {
        result.gid = 0;
        result.supplementary_gids.clear();
    }
    Ok(result)
}
