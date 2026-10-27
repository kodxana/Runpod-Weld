use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, OsStr},
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    time::{Duration, Instant},
};

fn check(cancelled: &impl Fn() -> bool) -> io::Result<()> {
    if cancelled() {
        Err(invalid("RUN mount operation cancelled"))
    } else {
        Ok(())
    }
}
fn name(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| invalid("NUL in mount path"))
}
fn cvt(value: i32) -> io::Result<()> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    dev: u64,
    ino: u64,
}
fn identity(m: &Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
    }
}

fn directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
}
fn at(dir: &File, path: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let path = name(path)?;
    let how = How {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: mode as u64,
        resolve: 1 | 2 | 4 | 8,
    };
    // SAFETY: pointers and lengths describe live initialized values; success owns a new fd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<How>(),
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd as i32) })
    }
}
fn mkdir(dir: &File, path: &OsStr, mode: u32) -> io::Result<()> {
    let path = name(path)?;
    // SAFETY: borrowed live directory and NUL-terminated name.
    cvt(unsafe { libc::mkdirat(dir.as_raw_fd(), path.as_ptr(), mode) })
}
fn rename(from: &File, a: &OsStr, to: &File, b: &OsStr, flags: u32) -> io::Result<()> {
    let (a, b) = (name(a)?, name(b)?);
    // SAFETY: valid directory descriptors and initialized NUL-terminated names.
    cvt(unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from.as_raw_fd(),
            a.as_ptr(),
            to.as_raw_fd(),
            b.as_ptr(),
            flags,
        ) as i32
    })
}
fn metadata(dir: &File, path: &OsStr) -> io::Result<Option<Metadata>> {
    match at(dir, path, libc::O_PATH, 0) {
        Ok(file) => Ok(Some(file.metadata()?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn fd_path(dir: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}
fn private(m: &Metadata) -> bool {
    // SAFETY: geteuid has no preconditions.
    m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0
}
fn secret(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| invalid("cannot open secret source (path redacted)"))?;
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || !private(&m) || m.len() > MAX_SECRET_BYTES {
        return Err(invalid(
            "secret source must be a private, owned, single-link regular file of at most 65536 bytes",
        ));
    }
    Ok(file)
}

/// Validate all source locations before any source fingerprint or build mutation.
pub fn validate_inputs(
    options: &Options,
    excluded: &[&Path],
    lease: Option<&crate::store_lease::StoreLease>,
) -> io::Result<()> {
    if options.secrets.len() > MAX_MOUNTS {
        return Err(invalid("at most 8 secret sources are supported"));
    }
    let excluded = excluded
        .iter()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| crate::store_access::resolved(p))
        .collect::<io::Result<Vec<_>>>()?;
    let cache = options
        .cache_dir
        .as_deref()
        .map(crate::store_access::resolved)
        .transpose()?;
    if let Some(cache) = &cache {
        crate::store_access::validate_run_cache_path(cache, lease)?;
        if excluded
            .iter()
            .any(|p| cache.starts_with(p) || p.starts_with(cache))
        {
            return Err(invalid(
                "RUN cache directory must be disjoint from context, work, output and base images",
            ));
        }
        if let Ok(m) = fs::symlink_metadata(options.cache_dir.as_ref().unwrap())
            && (!m.is_dir() || !private(&m))
        {
            return Err(invalid(
                "RUN cache directory must be a real private owned directory",
            ));
        }
    }
    for (id, path) in &options.secrets {
        if !valid_id(id) {
            return Err(invalid("invalid secret id"));
        }
        let resolved = fs::canonicalize(path)
            .map_err(|_| invalid("cannot resolve secret source (path redacted)"))?;
        if excluded.iter().any(|p| resolved.starts_with(p))
            || cache.as_ref().is_some_and(|p| resolved.starts_with(p))
        {
            return Err(invalid(
                "secret sources must be outside context, work, output, base images and RUN caches",
            ));
        }
        crate::store_access::validate_path(&resolved, lease)
            .map_err(|_| invalid("secret source store coordination refused (path redacted)"))?;
        secret(path)?;
    }
    Ok(())
}

/// Check even on cache hits: optional missing secrets must not expose inherited paths.
pub fn validate_targets(root: &Path, mounts: &[Mount], options: &Options) -> io::Result<()> {
    validate_mounts(mounts)?;
    let root = directory(root)?;
    for mount in mounts {
        let target = OsStr::new(&mount.target()[1..]);
        let found = metadata(&root, target)?;
        match mount {
            Mount::Secret { id, required, .. } => {
                if found.is_some() {
                    return Err(invalid("secret target exists; refusing inherited path"));
                }
                match options.secrets.get(id) {
                    Some(path) => {
                        secret(path)?;
                    }
                    None if *required => {
                        return Err(invalid("required RUN secret source is missing"));
                    }
                    None => (),
                }
            }
            Mount::Cache { .. } => {
                if found.is_some_and(|m| !m.is_dir() || m.file_type().is_symlink()) {
                    return Err(invalid(
                        "cache target must be an absent path or real directory",
                    ));
                }
                if options.cache_dir.is_none() {
                    return Err(invalid(
                        "cache mount needs --cache-mount-dir for unmanaged builds",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u32,
    root: Identity,
    lock: Identity,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryOwner {
    version: u32,
    store: Identity,
    entry: Identity,
    payload: Identity,
    key: String,
}

fn write_json(dir: &File, file: &str, value: &impl Serialize) -> io::Result<()> {
    let mut output = at(
        dir,
        OsStr::new(file),
        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
        0o600,
    )?;
    serde_json::to_writer(&mut output, value).map_err(io::Error::other)?;
    output.sync_all()
}
fn read_json<T: serde::de::DeserializeOwned>(dir: &File, file: &str) -> io::Result<T> {
    let input = at(dir, OsStr::new(file), libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let m = input.metadata()?;
    if !m.is_file() || !private(&m) || m.nlink() != 1 || m.len() > 4096 {
        return Err(invalid("invalid RUN cache ownership record"));
    }
    serde_json::from_reader(input.take(4097))
        .map_err(|_| invalid("invalid RUN cache ownership record"))
}
struct Cache {
    root: File,
    lock: File,
    path: PathBuf,
    limits: Limits,
}
impl Cache {
    fn open(path: &Path, limits: Limits, cancelled: &impl Fn() -> bool) -> io::Result<Self> {
        let path = std::path::absolute(path)?;
        let parent = directory(
            path.parent()
                .ok_or_else(|| invalid("cache root needs parent"))?,
        )?;
        let leaf = path
            .file_name()
            .ok_or_else(|| invalid("invalid cache root"))?;
        if metadata(&parent, leaf)?.is_none() {
            let staging = tempfile::Builder::new()
                .prefix(".weld-run-cache-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(fd_path(&parent))?;
            let dir = directory(staging.path())?;
            let lock = at(
                &dir,
                OsStr::new("lock"),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600,
            )?;
            write_json(
                &dir,
                "owner.json",
                &Owner {
                    version: 1,
                    root: identity(&dir.metadata()?),
                    lock: identity(&lock.metadata()?),
                },
            )?;
            match rename(
                &parent,
                staging.path().file_name().unwrap(),
                &parent,
                leaf,
                libc::RENAME_NOREPLACE,
            ) {
                Ok(()) => {
                    let _ = staging.keep();
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e),
            }
        }
        let root = at(&parent, leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        if !private(&root.metadata()?) {
            return Err(invalid("RUN cache root must be private and owned"));
        }
        let owner: Owner = read_json(&root, "owner.json")?;
        let lock = at(
            &root,
            OsStr::new("lock"),
            libc::O_RDWR | libc::O_NONBLOCK,
            0,
        )?;
        let lm = lock.metadata()?;
        if !lm.is_file()
            || !private(&lm)
            || lm.nlink() != 1
            || owner.version != 1
            || owner.root != identity(&root.metadata()?)
            || owner.lock != identity(&lm)
        {
            return Err(invalid(
                "RUN cache ownership identity mismatch; unmarked directories are never adopted",
            ));
        }
        let start = Instant::now();
        loop {
            check(cancelled)?;
            // SAFETY: valid borrowed regular-file fd; locks are released by close only.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(io::Error::last_os_error());
            }
            if start.elapsed() > Duration::from_secs(86400) {
                return Err(invalid("RUN cache lock wait exceeded 86400 seconds"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        check(cancelled)?;
        let cache = Self {
            root,
            lock,
            path,
            limits,
        };
        cache.usage(cancelled)?;
        Ok(cache)
    }
    fn entry(&self, key: &str) -> io::Result<Option<File>> {
        if metadata(&self.root, OsStr::new(key))?.is_none() {
            return Ok(None);
        }
        let entry = at(
            &self.root,
            OsStr::new(key),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        if !private(&entry.metadata()?) {
            return Err(invalid("RUN cache entry must be private and owned"));
        }
        for child in fs::read_dir(fd_path(&entry))? {
            let child = child?.file_name();
            if child != "owner.json" && child != "data" {
                return Err(invalid(
                    "unknown RUN cache entry child; retained without adoption or deletion",
                ));
            }
        }
        let owner: EntryOwner = read_json(&entry, "owner.json")?;
        let payload = at(
            &entry,
            OsStr::new("data"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        if owner.version != 1
            || owner.store != identity(&self.root.metadata()?)
            || owner.entry != identity(&entry.metadata()?)
            || owner.payload != identity(&payload.metadata()?)
            || owner.key != key
        {
            return Err(invalid(
                "RUN cache entry ownership mismatch; unmarked entries are never adopted",
            ));
        }
        Ok(Some(payload))
    }
    fn usage(&self, cancelled: &impl Fn() -> bool) -> io::Result<Usage> {
        let _ = &self.lock;
        let mut total = Usage::new(self.limits);
        total.charge_metadata(8192)?; // Namespace record and persistent lock bookkeeping.
        for entry in fs::read_dir(fd_path(&self.root))? {
            check(cancelled)?;
            let entry = entry?;
            let key = entry.file_name();
            if key == "owner.json" || key == "lock" {
                continue;
            }
            let key = key
                .to_str()
                .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or_else(|| {
                    invalid("unknown RUN cache entry; retained for manual inspection")
                })?;
            total.charge_metadata(4096)?;
            let payload = self
                .entry(key)?
                .ok_or_else(|| invalid("RUN cache entry disappeared"))?;
            scan(&payload, 0, &mut total, cancelled)?;
        }
        Ok(total)
    }
    fn publish(
        &self,
        key: &str,
        source: &File,
        admission: Admission<'_>,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<()> {
        let mut usage = self.usage(cancelled)?;
        let old = self.entry(key)?;
        if old.is_none() {
            usage.charge_metadata(4096)?;
        }
        if let Some(old) = &old {
            let mut old_usage = Usage::new(self.limits);
            scan(old, 0, &mut old_usage, cancelled)?;
            usage.bytes -= old_usage.bytes;
            usage.entries -= old_usage.entries;
            usage.metadata = usage.metadata.saturating_sub(old_usage.metadata);
        }
        let mut added = Usage::new(self.limits);
        scan(source, 0, &mut added, cancelled)?;
        usage.add(added.bytes, added.entries)?;
        usage.charge_metadata(added.metadata)?;
        if let Some(admit) = admission {
            admit(
                &self.path,
                added.allocation()?.saturating_add(8192),
                added.entries as u64 + 2,
            )?;
        }
        let staging = tempfile::Builder::new()
            .prefix(".write-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(fd_path(&self.root))?;
        let dir = directory(staging.path())?;
        mkdir(&dir, OsStr::new("data"), 0o700)?;
        let data = at(
            &dir,
            OsStr::new("data"),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        copy(source, &data, 0, &mut Usage::new(self.limits), cancelled)?;
        write_json(
            &dir,
            "owner.json",
            &EntryOwner {
                version: 1,
                store: identity(&self.root.metadata()?),
                entry: identity(&dir.metadata()?),
                payload: identity(&data.metadata()?),
                key: key.into(),
            },
        )?;
        check(cancelled)?;
        rename(
            &self.root,
            staging.path().file_name().unwrap(),
            &self.root,
            OsStr::new(key),
            if old.is_some() {
                libc::RENAME_EXCHANGE
            } else {
                libc::RENAME_NOREPLACE
            },
        )?;
        if old.is_none() {
            let _ = staging.keep();
        }
        // An exchange leaves only the previously validated, engine-owned entry in staging.
        Ok(())
    }
}

struct Usage {
    limits: Limits,
    bytes: u64,
    entries: usize,
    metadata: usize,
}
impl Usage {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            bytes: 0,
            entries: 0,
            metadata: 0,
        }
    }
    fn charge_metadata(&mut self, bytes: usize) -> io::Result<()> {
        self.metadata = self
            .metadata
            .checked_add(bytes)
            .ok_or_else(|| invalid("RUN cache metadata overflow"))?;
        if self.metadata as u64 > self.limits.max_metadata_bytes {
            return Err(invalid(&format!(
                "RUN cache metadata exceeds {} bytes; increase --metadata-budget",
                self.limits.max_metadata_bytes
            )));
        }
        Ok(())
    }
    fn allocation(&self) -> io::Result<u64> {
        self.bytes
            .checked_add((self.entries as u64).saturating_mul(4096))
            .ok_or_else(|| invalid("RUN cache allocation overflow"))
    }
    fn add(&mut self, bytes: u64, entries: usize) -> io::Result<()> {
        self.charge_metadata(entries.saturating_mul(256))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("RUN cache byte overflow"))?;
        self.entries = self
            .entries
            .checked_add(entries)
            .ok_or_else(|| invalid("RUN cache entry overflow"))?;
        if self.bytes > self.limits.max_bytes || self.entries > self.limits.max_entries {
            return Err(invalid(&format!(
                "RUN cache limit exceeded: {} bytes / {} entries allowed; observed {} bytes / {} entries. Increase --max-rootfs-bytes/--max-entries or use another --cache-mount-dir",
                self.limits.max_bytes, self.limits.max_entries, self.bytes, self.entries
            )));
        }
        Ok(())
    }
}
fn scan(
    dir: &File,
    depth: usize,
    usage: &mut Usage,
    cancelled: &impl Fn() -> bool,
) -> io::Result<()> {
    scan_tree(dir, depth, usage, cancelled, false)
}
fn scan_tree(
    dir: &File,
    depth: usize,
    usage: &mut Usage,
    cancelled: &impl Fn() -> bool,
    live: bool,
) -> io::Result<()> {
    if depth > MAX_CACHE_DEPTH {
        return Err(invalid("RUN cache depth exceeds 32"));
    }
    usage.add(0, 1)?;
    for entry in fs::read_dir(fd_path(dir))? {
        check(cancelled)?;
        let entry = entry?;
        // Includes a conservative maximum ancestor spelling without retaining a tree inventory.
        usage.charge_metadata(entry.file_name().len() + depth * 256)?;
        let file = match at(
            dir,
            &entry.file_name(),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(e) if live && e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        if live && meta.nlink() == 0 {
            continue;
        }
        if meta.is_dir() {
            scan_tree(&file, depth + 1, usage, cancelled, live)?;
        } else if meta.is_file() && meta.nlink() == 1 {
            usage.add(meta.len(), 1)?;
        } else {
            return Err(invalid(
                "RUN caches support only real directories and single-link regular files",
            ));
        }
    }
    Ok(())
}
fn set_metadata(file: &File, mode: u32, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: fd is owned and live. IDs come from the parser or source metadata.
    cvt(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) })?;
    // chown can clear special bits: restore the full copied mode afterward.
    // The parser separately restricts initialization modes to 0777.
    file.set_permissions(fs::Permissions::from_mode(mode & 0o7777))
}
fn copy(
    source: &File,
    target: &File,
    depth: usize,
    usage: &mut Usage,
    cancelled: &impl Fn() -> bool,
) -> io::Result<()> {
    if depth > MAX_CACHE_DEPTH {
        return Err(invalid("RUN cache depth exceeds 32"));
    }
    usage.add(0, 1)?;
    for entry in fs::read_dir(fd_path(source))? {
        check(cancelled)?;
        let entry = entry?;
        // Includes a conservative maximum ancestor spelling without retaining a tree inventory.
        usage.charge_metadata(entry.file_name().len() + depth * 256)?;
        let file = at(
            source,
            &entry.file_name(),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        let meta = file.metadata()?;
        if meta.is_dir() {
            mkdir(target, &entry.file_name(), 0o700)?;
            let dest = at(
                target,
                &entry.file_name(),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            copy(&file, &dest, depth + 1, usage, cancelled)?;
        } else if meta.is_file() && meta.nlink() == 1 {
            usage.add(meta.len(), 1)?;
            let mut dest = at(
                target,
                &entry.file_name(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            let mut reader = file.take(meta.len().saturating_add(1));
            let mut bytes = 0;
            let mut buf = [0u8; 65536];
            loop {
                check(cancelled)?;
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                bytes += n as u64;
                if bytes > meta.len() {
                    return Err(invalid("RUN cache changed during copy"));
                }
                dest.write_all(&buf[..n])?;
            }
            if bytes != meta.len() {
                return Err(invalid("RUN cache changed during copy"));
            }
            set_metadata(&dest, meta.mode(), meta.uid(), meta.gid())?;
        } else {
            return Err(invalid(
                "RUN caches support only real directories and single-link regular files",
            ));
        }
    }
    let meta = source.metadata()?;
    set_metadata(target, meta.mode(), meta.uid(), meta.gid())
}

struct Parent {
    dir: File,
    name: std::ffi::OsString,
    before: Metadata,
}
struct Installed {
    parent: Parent,
    backup: Option<std::ffi::OsString>,
    cache_key: Option<String>,
    detached: bool,
    restored: bool,
    parent_image_path: PathBuf,
    secret_file: Option<File>,
}

/// Owns temporary paths. Finish only after all RUN descendants have been reaped.
pub struct MountGuard {
    root: File,
    state: File,
    installed: Vec<Installed>,
    created: Vec<Parent>,
    cache: Option<Cache>,
    finished: bool,
    discard: Vec<std::ffi::OsString>,
    cleanup_entries: usize,
}

impl MountGuard {
    pub fn prepare(
        root: &Path,
        state: &Path,
        mounts: &[Mount],
        options: &Options,
        admission: Admission<'_>,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        validate_targets(root, mounts, options)?;
        let root_path = fs::canonicalize(root)?;
        let state_path = fs::canonicalize(state)?;
        let outer = fs::metadata("/")?;
        if identity(&fs::metadata(&root_path)?) == identity(&outer)
            || root_path.starts_with(&state_path)
            || state_path.starts_with(&root_path)
        {
            return Err(invalid(
                "RUN mount root/state must be disjoint and cannot alias host root",
            ));
        }
        if let Some(cache) = &options.cache_dir {
            let cache = crate::store_access::resolved(cache)?;
            if [&root_path, &state_path]
                .iter()
                .any(|p| cache.starts_with(p) || p.starts_with(&cache))
            {
                return Err(invalid(
                    "RUN cache root must be disjoint from materialization and state",
                ));
            }
        }
        if (mounts.len() as u64).saturating_mul(16384) > options.limits.max_metadata_bytes {
            return Err(invalid(
                "RUN mount metadata exceeds configured --metadata-budget",
            ));
        }
        if mounts.iter().any(|m| !m.is_secret())
            && let Some(admit) = admission
        {
            admit(options.cache_dir.as_ref().unwrap(), 16384, 4)?;
        }
        let cache = mounts
            .iter()
            .any(|m| !m.is_secret())
            .then(|| {
                Cache::open(
                    options.cache_dir.as_ref().unwrap(),
                    options.limits,
                    cancelled,
                )
            })
            .transpose()?;
        let root_dir = directory(root)?;
        let mut guard = Self {
            root: root_dir.try_clone()?,
            state: directory(state)?,
            installed: Vec::new(),
            created: Vec::new(),
            cache,
            finished: false,
            discard: Vec::new(),
            cleanup_entries: options
                .limits
                .max_entries
                .saturating_mul(2)
                .saturating_add(MAX_MOUNTS),
        };
        for mount in mounts {
            check(cancelled)?;
            if let Mount::Secret { id, .. } = mount
                && !options.secrets.contains_key(id)
            {
                continue;
            }
            let mut parent = root_dir.try_clone()?;
            let parts: Vec<_> = mount.target()[1..].split('/').collect();
            for component in &parts[..parts.len() - 1] {
                let component = OsStr::new(component);
                if metadata(&parent, component)?.is_none() {
                    let before = parent.metadata()?;
                    if let Some(admit) = admission {
                        admit(root, 4096, 1)?;
                    }
                    mkdir(&parent, component, 0o755)?;
                    guard.created.push(Parent {
                        dir: parent.try_clone()?,
                        name: component.into(),
                        before,
                    });
                }
                parent = at(&parent, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            }
            let leaf = OsStr::new(parts.last().unwrap());
            let before = parent.metadata()?;
            let backup = if metadata(&parent, leaf)?.is_some() {
                let saved =
                    std::ffi::OsString::from(format!("mount-backup-{}", guard.installed.len()));
                rename(&parent, leaf, &guard.state, &saved, libc::RENAME_NOREPLACE)?;
                Some(saved)
            } else {
                None
            };
            guard.installed.push(Installed {
                parent: Parent {
                    dir: parent,
                    name: leaf.into(),
                    before,
                },
                backup,
                cache_key: None,
                detached: false,
                restored: false,
                parent_image_path: Path::new(&mount.target()[1..]).parent().unwrap().to_owned(),
                secret_file: None,
            });
            let installed = guard.installed.last_mut().unwrap();
            match mount {
                Mount::Secret {
                    id, mode, uid, gid, ..
                } => {
                    let mut input = secret(&options.secrets[id])?.take(MAX_SECRET_BYTES + 1);
                    let mut bytes = Vec::new();
                    input.read_to_end(&mut bytes)?;
                    if bytes.len() as u64 > MAX_SECRET_BYTES {
                        return Err(invalid("secret source exceeds 65536 bytes"));
                    }
                    if let Some(admit) = admission {
                        admit(root, bytes.len() as u64 + 4096, 1)?;
                    }
                    let mut output = at(
                        &installed.parent.dir,
                        leaf,
                        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
                        0o600,
                    )?;
                    output.write_all(&bytes)?;
                    set_metadata(&output, *mode, *uid, *gid)?;
                    installed.secret_file = Some(output);
                }
                Mount::Cache {
                    id, mode, uid, gid, ..
                } => {
                    let key = format!("{:x}", Sha256::digest(id.as_bytes()));
                    let input = guard.cache.as_ref().unwrap().entry(&key)?;
                    let mut usage = Usage::new(options.limits);
                    if let Some(input) = &input {
                        scan(input, 0, &mut usage, cancelled)?;
                    } else {
                        usage.add(0, 1)?;
                    }
                    if let Some(admit) = admission {
                        admit(root, usage.allocation()?, usage.entries as u64)?;
                    }
                    mkdir(&installed.parent.dir, leaf, 0o700)?;
                    let output = at(
                        &installed.parent.dir,
                        leaf,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                        0,
                    )?;
                    if let Some(input) = input {
                        copy(
                            &input,
                            &output,
                            0,
                            &mut Usage::new(options.limits),
                            cancelled,
                        )?;
                    } else {
                        set_metadata(&output, *mode, *uid, *gid)?;
                    }
                    installed.cache_key = Some(key);
                }
            }
        }
        Ok(guard)
    }
    /// Enforce cooperative growth ceilings; pass failure into RUN cancellation.
    pub fn check_limits(&self) -> io::Result<()> {
        let mut usage = Usage::new(self.cache.as_ref().map_or(Limits::default(), |c| c.limits));
        for installed in &self.installed {
            if installed.cache_key.is_some() {
                let file = at(
                    &installed.parent.dir,
                    &installed.parent.name,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                scan_tree(&file, 0, &mut usage, &|| false, true)?;
            }
        }
        Ok(())
    }
    /// Cleanup ignores cancellation. The previous cache survives failed/cancelled copies.
    pub fn finish(
        mut self,
        success: bool,
        admission: Admission<'_>,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<()> {
        let sources = (|| -> io::Result<Vec<(String, File)>> {
            let mut sources = Vec::new();
            if success {
                for installed in &self.installed {
                    let parent = if installed.parent_image_path.as_os_str().is_empty() {
                        self.root.try_clone()?
                    } else {
                        at(
                            &self.root,
                            installed.parent_image_path.as_os_str(),
                            libc::O_RDONLY | libc::O_DIRECTORY,
                            0,
                        )?
                    };
                    if identity(&parent.metadata()?) != identity(&installed.parent.dir.metadata()?)
                    {
                        return Err(invalid(
                            "RUN renamed a mount ancestor; no checkpoint may be published",
                        ));
                    }
                    if let Some(file) = &installed.secret_file {
                        let original = file.metadata()?;
                        let current = metadata(&parent, &installed.parent.name)?;
                        if original.nlink() > 1
                            || (original.nlink() != 0
                                && current.is_none_or(|m| identity(&m) != identity(&original)))
                        {
                            return Err(invalid(
                                "RUN relocated or hardlinked a secret; no checkpoint may be published",
                            ));
                        }
                    }
                    if let Some(key) = &installed.cache_key {
                        sources.push((
                            key.clone(),
                            at(
                                &installed.parent.dir,
                                &installed.parent.name,
                                libc::O_RDONLY | libc::O_DIRECTORY,
                                0,
                            )?,
                        ));
                    }
                }
            }
            Ok(sources)
        })();
        // Restore the image first, keeping only private detached data for publication.
        let restored = self.restore();
        let publication = match (sources, restored) {
            (Ok(sources), Ok(())) => sources.into_iter().try_for_each(|(key, source)| {
                self.cache
                    .as_ref()
                    .unwrap()
                    .publish(&key, &source, admission, cancelled)
            }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        let cleanup = self.remove_discard();
        self.finished =
            self.installed.is_empty() && self.created.is_empty() && self.discard.is_empty();
        match (publication, cleanup) {
            (Err(error), Err(cleanup)) => Err(invalid(&format!(
                "{error}; RUN mount cleanup also failed: {cleanup}"
            ))),
            (Err(error), _) | (_, Err(error)) => Err(error),
            _ => Ok(()),
        }
    }
    fn remove_discard(&mut self) -> io::Result<()> {
        while let Some(leaf) = self.discard.last() {
            remove(&self.state, leaf, 0, &mut 0, self.cleanup_entries)?;
            self.discard.pop();
        }
        Ok(())
    }
    fn restore(&mut self) -> io::Result<()> {
        let mut failure = None;
        while let Some(installed) = self.installed.last_mut() {
            let result = (|| {
                if !installed.detached
                    && metadata(&installed.parent.dir, &installed.parent.name)?.is_some()
                {
                    let leaf =
                        std::ffi::OsString::from(format!("mount-discard-{}", self.discard.len()));
                    rename(
                        &installed.parent.dir,
                        &installed.parent.name,
                        &self.state,
                        &leaf,
                        libc::RENAME_NOREPLACE,
                    )?;
                    self.discard.push(leaf);
                }
                installed.detached = true;
                if !installed.restored
                    && let Some(backup) = &installed.backup
                {
                    rename(
                        &self.state,
                        backup,
                        &installed.parent.dir,
                        &installed.parent.name,
                        libc::RENAME_NOREPLACE,
                    )?;
                }
                installed.restored = true;
                times(&installed.parent.dir, &installed.parent.before)
            })();
            if let Err(e) = result {
                failure = Some(e);
                break;
            }
            self.installed.pop();
        }
        if failure.is_none() {
            while let Some(parent) = self.created.last() {
                let leaf = name(&parent.name)?;
                // SAFETY: pinned parent, one path component; never recursive here.
                let removed = unsafe {
                    libc::unlinkat(parent.dir.as_raw_fd(), leaf.as_ptr(), libc::AT_REMOVEDIR)
                };
                if removed != 0
                    && !matches!(
                        io::Error::last_os_error().raw_os_error(),
                        Some(libc::ENOENT | libc::ENOTEMPTY)
                    )
                {
                    failure = Some(io::Error::last_os_error());
                    break;
                }
                if removed == 0 {
                    times(&parent.dir, &parent.before)?;
                }
                self.created.pop();
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
impl Drop for MountGuard {
    fn drop(&mut self) {
        if !self.finished && (self.restore().is_err() || self.remove_discard().is_err()) {
            crate::progress::diagnostic(format_args!(
                "rpweld: RUN mount restoration failed; no checkpoint may be published"
            ));
        }
    }
}
fn times(file: &File, m: &Metadata) -> io::Result<()> {
    let times = [
        libc::timespec {
            tv_sec: m.atime(),
            tv_nsec: m.atime_nsec(),
        },
        libc::timespec {
            tv_sec: m.mtime(),
            tv_nsec: m.mtime_nsec(),
        },
    ];
    // SAFETY: live fd and exactly two initialized timespec values.
    cvt(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) })
}
fn remove(
    parent: &File,
    leaf: &OsStr,
    depth: usize,
    entries: &mut usize,
    limit: usize,
) -> io::Result<()> {
    if depth > MAX_CACHE_DEPTH + 1 || *entries > limit {
        return Err(invalid(
            "RUN mount cleanup budget exceeded; retained paths require inspection",
        ));
    }
    let Some(meta) = metadata(parent, leaf)? else {
        return Ok(());
    };
    *entries += 1;
    if meta.is_dir() {
        let dir = at(parent, leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        // Only materialized content is removed, never the renamed inherited tree.
        for entry in fs::read_dir(fd_path(&dir))? {
            remove(&dir, &entry?.file_name(), depth + 1, entries, limit)?;
        }
    }
    let leaf = name(leaf)?;
    // SAFETY: pinned parent and single component, symlinks are unlinked, never followed.
    cvt(unsafe {
        libc::unlinkat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            if meta.is_dir() { libc::AT_REMOVEDIR } else { 0 },
        )
    })
}
