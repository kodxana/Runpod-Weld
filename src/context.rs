//! Bounded local COPY subset. Both roots must be stable, disjoint trees without
//! concurrent writers; the disposable image must have no external hardlinks.
//! On ANY error discard the image: copying is not transactional. Linux openat2
//! is required; nested mounts and magic links are refused. Roots themselves are
//! trusted caller paths. No host-path destination resolution is performed.
//!
//! Sources are literal context-relative paths (`.` allowed); no `..`, absolute
//! paths, glob/variable syntax, or symlink ancestors. Explicit source symlinks
//! are rejected; symlinks encountered inside directories are copied verbatim.
//! Directory contents merge into destination. Multiple sources require a
//! trailing slash. A single file uses its basename when destination is a
//! directory (including an image-root symlink to one). Type collisions fail.
//! Ordered .dockerignore rules filter local sources before payload/xattr reads.
//!
//! Preserves permission bits, assigns uid/gid 0, and copies hardlinks as separate
//! files. Nanosecond atime/mtime and user.* / security.capability xattrs are
//! preserved. Other xattrs (including ACLs) fail preflight. Existing selected
//! directory roots retain ownership/mode/xattrs; nested directories take source
//! metadata. Sparse layout and COPY flags are unsupported.
//! Cancellation is cooperative, not an I/O timeout. Metadata accounting includes
//! xattr payloads and per-attribute overhead, not allocator bookkeeping/capacity.
//! Temporary overhead: 128 traversal frames/FDs, 64 KiB xattr names, up to 64 KiB
//! captured values before budget charging plus one 64 KiB value buffer, a 64 KiB
//! streaming buffer, and O(entries) manifest/index allocation slack.
use crate::dockerignore::Policy;
use std::{fmt, io, path::Path};

pub(crate) fn load_policy(
    context: &Path,
    dockerfile: Option<&Path>,
    cancelled: &impl Fn() -> bool,
) -> Result<Policy, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::load_policy(context, dockerfile, cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (context, dockerfile, cancelled);
        Err(Error::Unsupported("context requires Linux"))
    }
}

pub(crate) fn validate_sources(
    context: &Path,
    sources: &[&str],
    policy: &Policy,
    cancelled: &impl Fn() -> bool,
) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        linux::validate_sources(context, sources, policy, cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (context, sources, policy, cancelled);
        Err(Error::Unsupported("context requires Linux"))
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::fingerprint;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Sum of regular file sizes, including repeated sources/hardlinks.
    pub max_bytes: u64,
    /// Source entries visited, including each selected directory itself.
    pub max_entries: usize,
    /// Cumulative accounting: 512 + source path + destination path + link target
    /// bytes per entry, plus xattr names/values and 64 bytes per attribute.
    /// Also bounds the retained manifest; paths are <=4096 bytes.
    pub max_metadata_bytes: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub entries: usize,
    pub bytes_written: u64,
    pub metadata_bytes: u64,
    pub(crate) targets: Vec<Vec<u8>>,
}

// Reuse execution's resolved destination roots, which may depend on earlier RUNs
// or image symlinks. Rewalk sources so ignored entries still consume budgets.
pub(crate) fn validate_copy_budget(
    context: &Path,
    sources: &[&str],
    targets: &[Vec<u8>],
    limits: Limits,
    policy: Option<&Policy>,
    cancelled: &impl Fn() -> bool,
) -> Result<Summary, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::validate_copy_budget(context, sources, targets, limits, policy, cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (context, sources, targets, limits, policy, cancelled);
        Err(Error::Unsupported("context requires Linux"))
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid(&'static str),
    Unsupported(&'static str),
    Limit(&'static str),
    Cancelled,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local COPY failed ({self:?}); discard partial image")
    }
}
impl std::error::Error for Error {}

/// `destination` must be an absolute image path, with WORKDIR already resolved
/// by the caller. Preserve its trailing slash. All budgets are mandatory.
pub fn copy_local(
    context_root: &Path,
    image_root: &Path,
    sources: &[&str],
    destination: &str,
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> Result<Summary, Error> {
    let policy = load_policy(context_root, None, &cancelled)?;
    copy_filtered(
        context_root,
        image_root,
        sources,
        destination,
        limits,
        Some(&policy),
        cancelled,
    )
}

/// Copy a completed stage root; .dockerignore applies only to the build context.
pub fn copy_stage(
    context_root: &Path,
    image_root: &Path,
    sources: &[&str],
    destination: &str,
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> Result<Summary, Error> {
    copy_filtered(
        context_root,
        image_root,
        sources,
        destination,
        limits,
        None,
        cancelled,
    )
}

pub(crate) fn copy_filtered(
    context_root: &Path,
    image_root: &Path,
    sources: &[&str],
    destination: &str,
    limits: Limits,
    policy: Option<&Policy>,
    cancelled: impl Fn() -> bool,
) -> Result<Summary, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::copy(
            context_root,
            image_root,
            sources,
            destination,
            limits,
            policy,
            &cancelled,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            context_root,
            image_root,
            sources,
            destination,
            limits,
            policy,
            cancelled,
        );
        Err(Error::Unsupported("local COPY requires Linux"))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::{CStr, CString},
        fs::File,
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd, IntoRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
    };

    fn check(c: &impl Fn() -> bool) -> Result<(), Error> {
        if c() { Err(Error::Cancelled) } else { Ok(()) }
    }
    fn cs(p: &[u8]) -> Result<CString, Error> {
        CString::new(p).map_err(|_| Error::Invalid("NUL in path"))
    }
    fn cv(n: i32) -> Result<i32, Error> {
        if n < 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(n)
        }
    }
    fn missing(e: &Error) -> bool {
        matches!(e, Error::Io(e) if e.raw_os_error() == Some(libc::ENOENT))
    }
    // rootfs's resolver is private. This narrowly scoped kernel resolver avoids
    // duplicating its userspace symlink walk or changing its public API.
    fn open(root: &File, p: &[u8], flags: i32, source: bool) -> Result<File, Error> {
        #[repr(C)]
        struct How {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let how = How {
            flags: (flags | libc::O_CLOEXEC) as u64,
            mode: if flags & libc::O_CREAT != 0 { 0o600 } else { 0 },
            // NO_XDEV | NO_MAGICLINKS | (BENEATH | NO_SYMLINKS or IN_ROOT)
            resolve: 1 | 2 | if source { 8 | 4 } else { 16 },
        };
        let p = cs(if p.is_empty() { b"." } else { p })?;
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                p.as_ptr(),
                &how,
                std::mem::size_of::<How>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(fd as i32) })
    }
    fn root(p: &Path) -> Result<File, Error> {
        let p = cs(p.as_os_str().as_bytes())?;
        let fd = cv(unsafe {
            libc::open(
                p.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn load_policy(
        ctx: &Path,
        dockerfile: Option<&Path>,
        c: &impl Fn() -> bool,
    ) -> Result<Policy, Error> {
        fn read(
            parent: &File,
            name: &[u8],
            c: &impl Fn() -> bool,
        ) -> Result<Option<Policy>, Error> {
            check(c)?;
            let pin = match open(parent, name, libc::O_PATH | libc::O_NOFOLLOW, true) {
                Ok(pin) => pin,
                Err(e) if missing(&e) => return Ok(None),
                Err(e) => return Err(e),
            };
            let m = pin.metadata()?;
            if !m.is_file() {
                return Err(Error::Invalid(
                    "dockerignore must be a regular non-symlink file",
                ));
            }
            if m.len() > crate::dockerignore::MAX_BYTES as u64 {
                return Err(Error::Limit("dockerignore bytes"));
            }
            let mut f = open(
                parent,
                name,
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOATIME,
                true,
            )?;
            let mut bytes = Vec::new();
            let mut buf = [0; 65536];
            loop {
                check(c)?;
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                if bytes.len() + n > crate::dockerignore::MAX_BYTES {
                    return Err(Error::Limit("dockerignore bytes"));
                }
                bytes.extend_from_slice(&buf[..n]);
            }
            Ok(Some(Policy::parse(&bytes)?))
        }
        check(c)?;
        if let Some(file) = dockerfile {
            let parent = file
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut name = file
                .file_name()
                .ok_or(Error::Invalid("Dockerfile path"))?
                .as_bytes()
                .to_vec();
            name.extend_from_slice(b".dockerignore");
            if let Some(policy) = read(&root(parent)?, &name, c)? {
                return Ok(policy);
            }
        }
        Ok(read(&root(ctx)?, b".dockerignore", c)?.unwrap_or_default())
    }

    pub(super) fn validate_sources(
        ctx: &Path,
        sources: &[&str],
        policy: &Policy,
        c: &impl Fn() -> bool,
    ) -> Result<(), Error> {
        let ctx = root(ctx)?;
        let mut work = crate::dockerignore::WORK;
        for source in sources {
            check(c)?;
            let src = path(source, false)?;
            let m = open(&ctx, &src, libc::O_PATH | libc::O_NOFOLLOW, true)?.metadata()?;
            if policy.excluded_cancellable(&src, &mut work, c)? {
                return Err(Error::Invalid(
                    "explicit COPY source excluded by dockerignore",
                ));
            }
            if !(m.is_file() || m.is_dir()) {
                return Err(Error::Unsupported("explicit source type"));
            }
        }
        Ok(())
    }

    pub(crate) fn fingerprint(
        ctx: &Path,
        policy: &Policy,
        limits: Limits,
        c: &impl Fn() -> bool,
    ) -> Result<Vec<u8>, Error> {
        use sha2::{Digest, Sha256};
        fn field(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        let ctx = root(ctx)?;
        let mut plan = Plan {
            policy: Some(policy),
            work: crate::dockerignore::WORK,
            visited: 0,
            entries: Vec::new(),
            used: Summary::default(),
            limits,
        };
        plan.visit(&ctx, Vec::new(), Vec::new(), true, 0, c)?;
        plan.entries.sort_by(|a, b| a.src.cmp(&b.src));
        let mut hash = Sha256::new();
        field(&mut hash, &policy.identity());
        for e in &mut plan.entries {
            check(c)?;
            field(&mut hash, &e.src);
            field(&mut hash, &e.kind.to_le_bytes());
            field(&mut hash, &e.mode.to_le_bytes());
            field(&mut hash, &e.size.to_le_bytes());
            field(&mut hash, &e.link);
            e.attrs.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, value) in &e.attrs {
                field(&mut hash, name.as_bytes());
                field(&mut hash, value);
            }
            field(&mut hash, b"end-xattrs");
            if e.kind == libc::S_IFREG {
                let mut f = open(
                    &ctx,
                    &e.src,
                    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOATIME,
                    true,
                )?;
                if !f.metadata()?.is_file() {
                    return Err(Error::Invalid("source changed"));
                }
                let mut remaining = e.size;
                let mut buf = [0; 65536];
                while remaining > 0 {
                    check(c)?;
                    let n = remaining.min(buf.len() as u64) as usize;
                    f.read_exact(&mut buf[..n])?;
                    hash.update(&buf[..n]);
                    remaining -= n as u64;
                }
                if f.read(&mut buf[..1])? != 0 {
                    return Err(Error::Invalid("source grew"));
                }
            }
            // readlink can change atime; include what subsequent COPY observes.
            let m = open(&ctx, &e.src, libc::O_PATH | libc::O_NOFOLLOW, true)?.metadata()?;
            for time in times(&m) {
                field(&mut hash, &time.tv_sec.to_le_bytes());
                field(&mut hash, &time.tv_nsec.to_le_bytes());
            }
        }
        Ok(hash.finalize().to_vec())
    }

    pub(super) fn validate_copy_budget(
        ctx: &Path,
        sources: &[&str],
        targets: &[Vec<u8>],
        limits: Limits,
        policy: Option<&Policy>,
        c: &impl Fn() -> bool,
    ) -> Result<Summary, Error> {
        if sources.len() != targets.len() || sources.is_empty() {
            return Err(Error::Invalid("cached COPY targets"));
        }
        let ctx = root(ctx)?;
        let mut plan = Plan {
            policy,
            work: crate::dockerignore::WORK,
            visited: 0,
            entries: Vec::new(),
            used: Summary::default(),
            limits,
        };
        for (source, target) in sources.iter().zip(targets) {
            if target.len() > 4096 || target.contains(&0) {
                return Err(Error::Invalid("cached COPY target"));
            }
            plan.visit(&ctx, path(source, false)?, target.clone(), true, 0, c)?;
        }
        Ok(plan.used)
    }
    fn path(p: &str, absolute: bool) -> Result<Vec<u8>, Error> {
        if p.is_empty()
            || p.len() > 4096
            || p.starts_with('/') != absolute
            || p.bytes().any(|b| b"\0*?[$\\".contains(&b))
            || p.split('/').any(|s| s == "..")
            || p.split('/').count() > 128
        {
            return Err(Error::Invalid("expected literal canonical COPY path"));
        }
        Ok(p.split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect::<Vec<_>>()
            .join("/")
            .into_bytes())
    }
    fn join(a: &[u8], b: &[u8]) -> Result<Vec<u8>, Error> {
        let mut p = a.to_vec();
        if !p.is_empty() && !b.is_empty() {
            p.push(b'/');
        }
        p.extend_from_slice(b);
        if p.len() > 4096 {
            return Err(Error::Limit("path length"));
        }
        Ok(p)
    }
    fn split(p: &[u8]) -> (&[u8], &[u8]) {
        match p.iter().rposition(|b| *b == b'/') {
            Some(i) => (&p[..i], &p[i + 1..]),
            None => (b"", p),
        }
    }
    struct Entry {
        src: Vec<u8>,
        dst: Vec<u8>,
        mode: u32,
        size: u64,
        kind: u32,
        link: Vec<u8>,
        times: [libc::timespec; 2],
        attrs: Vec<(CString, Vec<u8>)>,
        explicit: bool,
    }
    struct Plan<'a> {
        policy: Option<&'a Policy>,
        work: u64,
        visited: usize,
        entries: Vec<Entry>,
        used: Summary,
        limits: Limits,
    }
    impl Plan<'_> {
        fn visit(
            &mut self,
            ctx: &File,
            src: Vec<u8>,
            dst: Vec<u8>,
            explicit: bool,
            depth: usize,
            c: &impl Fn() -> bool,
        ) -> Result<(), Error> {
            check(c)?;
            if depth > 128 {
                return Err(Error::Limit("directory depth"));
            }
            if self.visited >= self.limits.max_entries {
                return Err(Error::Limit("entries"));
            }
            self.visited += 1;
            self.used.entries += 1;
            self.used.metadata_bytes = self
                .used
                .metadata_bytes
                .checked_add(512 + src.len() as u64 + dst.len() as u64)
                .filter(|n| *n <= self.limits.max_metadata_bytes)
                .ok_or(Error::Limit("metadata"))?;
            let excluded = match self.policy {
                Some(p) => p.excluded_cancellable(&src, &mut self.work, c)?,
                None => false,
            };
            if excluded && explicit {
                return Err(Error::Invalid(
                    "explicit COPY source excluded by dockerignore",
                ));
            }
            let pin = open(ctx, &src, libc::O_PATH | libc::O_NOFOLLOW, true)?;
            let m = pin.metadata()?;
            let kind = m.mode() & libc::S_IFMT;
            if excluded && kind != libc::S_IFDIR {
                if explicit {
                    return Err(Error::Invalid(
                        "explicit COPY source excluded by dockerignore",
                    ));
                }
                return Ok(());
            }
            if excluded && !self.policy.is_some_and(|p| p.negations) {
                if explicit {
                    return Err(Error::Invalid(
                        "explicit COPY source excluded by dockerignore",
                    ));
                }
                return Ok(());
            }
            let insertion = self.entries.len();
            if ![libc::S_IFREG, libc::S_IFDIR, libc::S_IFLNK].contains(&kind) {
                return Err(Error::Unsupported("special source file"));
            }
            if explicit && kind == libc::S_IFLNK {
                return Err(Error::Unsupported("explicit source symlink dereference"));
            }
            if kind == libc::S_IFDIR {
                let fd = open(
                    ctx,
                    &src,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOATIME,
                    true,
                )?
                .into_raw_fd();
                let dp = unsafe { libc::fdopendir(fd) };
                if dp.is_null() {
                    let e = io::Error::last_os_error();
                    unsafe {
                        libc::close(fd);
                    }
                    return Err(e.into());
                }
                struct Dir(*mut libc::DIR);
                impl Drop for Dir {
                    fn drop(&mut self) {
                        unsafe {
                            libc::closedir(self.0);
                        }
                    }
                }
                let dp = Dir(dp);
                loop {
                    check(c)?;
                    unsafe {
                        *libc::__errno_location() = 0;
                    }
                    let ent = unsafe { libc::readdir(dp.0) };
                    if ent.is_null() {
                        let e = io::Error::last_os_error();
                        if e.raw_os_error() != Some(0) {
                            return Err(e.into());
                        }
                        break;
                    }
                    let n = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
                    if n == b"." || n == b".." {
                        continue;
                    }
                    self.visit(ctx, join(&src, n)?, join(&dst, n)?, false, depth + 1, c)?;
                }
            }
            if excluded && self.entries.len() == insertion {
                if explicit {
                    return Err(Error::Invalid(
                        "explicit COPY source excluded by dockerignore",
                    ));
                }
                return Ok(());
            }
            let mut link = Vec::new();
            if kind == libc::S_IFLNK {
                let mut b = [0u8; 4096];
                let n = unsafe {
                    libc::readlinkat(
                        pin.as_raw_fd(),
                        c"".as_ptr(),
                        b.as_mut_ptr().cast(),
                        b.len(),
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                if n as usize == b.len() {
                    return Err(Error::Limit("symlink target"));
                }
                link.extend_from_slice(&b[..n as usize]);
            }
            let attrs = attrs(ctx, &src, true, c)?;
            let metadata = link.len() as u64
                + attrs
                    .iter()
                    .map(|(n, v)| 64 + n.as_bytes_with_nul().len() as u64 + v.len() as u64)
                    .sum::<u64>();
            self.used.metadata_bytes = self
                .used
                .metadata_bytes
                .checked_add(metadata)
                .filter(|v| *v <= self.limits.max_metadata_bytes)
                .ok_or(Error::Limit("metadata"))?;
            let size = if kind == libc::S_IFREG { m.len() } else { 0 };
            self.used.bytes_written = self
                .used
                .bytes_written
                .checked_add(size)
                .filter(|v| *v <= self.limits.max_bytes)
                .ok_or(Error::Limit("bytes"))?;
            self.entries.insert(
                insertion,
                Entry {
                    src: src.clone(),
                    dst: dst.clone(),
                    mode: m.mode() & 0o7777,
                    size,
                    kind,
                    link,
                    times: times(&m),
                    attrs,
                    explicit,
                },
            );
            Ok(())
        }
    }
    fn times(m: &std::fs::Metadata) -> [libc::timespec; 2] {
        [
            libc::timespec {
                tv_sec: m.atime(),
                tv_nsec: m.atime_nsec(),
            },
            libc::timespec {
                tv_sec: m.mtime(),
                tv_nsec: m.mtime_nsec(),
            },
        ]
    }
    // Linux has no lgetxattrat on our minimum kernel. Only the trusted procfs FD
    // bridge is followed; the parent was already confined by openat2, and l* calls
    // never follow the final component. Stable trees are required throughout.
    fn attr_path(root: &File, p: &[u8], source: bool) -> Result<(File, CString), Error> {
        if p.is_empty() {
            let d = root.try_clone()?;
            let path = cs(format!("/proc/self/fd/{}", d.as_raw_fd()).as_bytes())?;
            return Ok((d, path));
        }
        let (parent, name) = split(p);
        let d = open(root, parent, libc::O_PATH | libc::O_DIRECTORY, source)?;
        let prefix = format!("/proc/self/fd/{}/", d.as_raw_fd());
        let mut path = prefix.into_bytes();
        path.extend_from_slice(if name.is_empty() { b"." } else { name });
        Ok((d, cs(&path)?))
    }
    fn attrs(
        root: &File,
        p: &[u8],
        source: bool,
        c: &impl Fn() -> bool,
    ) -> Result<Vec<(CString, Vec<u8>)>, Error> {
        let follow = p.is_empty();
        let (_d, p) = attr_path(root, p, source)?;
        let mut names = vec![0u8; 65536];
        let n = unsafe {
            if follow {
                libc::listxattr(p.as_ptr(), names.as_mut_ptr().cast(), names.len())
            } else {
                libc::llistxattr(p.as_ptr(), names.as_mut_ptr().cast(), names.len())
            }
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EOPNOTSUPP) {
                return Ok(Vec::new());
            }
            return Err(e.into());
        }
        let mut result = Vec::new();
        let mut total = 0;
        for name in names[..n as usize]
            .split(|b| *b == 0)
            .filter(|n| !n.is_empty())
        {
            check(c)?;
            if result.len() == 256 {
                return Err(Error::Limit("xattr count"));
            }
            if !(name.starts_with(b"user.") || name == b"security.capability") {
                return Err(Error::Unsupported("xattr namespace or ACL"));
            }
            let name = cs(name)?;
            let mut value = vec![0; 65536 - total];
            let n = unsafe {
                if follow {
                    libc::getxattr(
                        p.as_ptr(),
                        name.as_ptr(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                    )
                } else {
                    libc::lgetxattr(
                        p.as_ptr(),
                        name.as_ptr(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                    )
                }
            };
            if n < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if n as usize > value.len() {
                return Err(Error::Limit("xattr bytes"));
            }
            value.truncate(n as usize);
            total += value.len();
            if total == 65536 {
                return Err(Error::Limit("xattr bytes"));
            }
            result.push((name, value.into_boxed_slice().into_vec()));
        }
        Ok(result)
    }
    fn restore(f: &File, e: &Entry, c: &impl Fn() -> bool) -> Result<(), Error> {
        // chown and payload writes clear capabilities: install xattrs last.
        metadata(f, e.mode)?;
        for (name, _) in attrs(f, b"", false, c)? {
            cv(unsafe { libc::fremovexattr(f.as_raw_fd(), name.as_ptr()) })?;
        }
        for (name, value) in &e.attrs {
            check(c)?;
            cv(unsafe {
                libc::fsetxattr(
                    f.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            })?;
        }
        cv(unsafe { libc::futimens(f.as_raw_fd(), e.times.as_ptr()) })?;
        Ok(())
    }
    // Resolve only the requested destination, including its leaf. Recursive
    // source entries use no-follow leaf replacement instead.
    fn destination_path(image: &File, p: &[u8], c: &impl Fn() -> bool) -> Result<Vec<u8>, Error> {
        let mut pending = p.to_vec();
        let mut resolved = Vec::new();
        let mut links = 0;
        while !pending.is_empty() {
            check(c)?;
            let end = pending
                .iter()
                .position(|b| *b == b'/')
                .unwrap_or(pending.len());
            let part = pending[..end].to_vec();
            pending = pending[end..].strip_prefix(b"/").unwrap_or(&[]).to_vec();
            if part == b"." || part.is_empty() {
                continue;
            }
            if part == b".." {
                resolved = split(&resolved).0.to_vec();
                continue;
            }
            let next = join(&resolved, &part)?;
            if next.split(|b| *b == b'/').count() > 128 {
                return Err(Error::Limit("destination depth"));
            }
            match open(image, &next, libc::O_PATH | libc::O_NOFOLLOW, false) {
                Ok(f) if f.metadata()?.file_type().is_symlink() => {
                    links += 1;
                    if links > 40 {
                        return Err(Error::Limit("destination symlinks"));
                    }
                    let mut buf = [0u8; 4096];
                    let n = unsafe {
                        libc::readlinkat(
                            f.as_raw_fd(),
                            c"".as_ptr(),
                            buf.as_mut_ptr().cast(),
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        return Err(io::Error::last_os_error().into());
                    }
                    if n as usize == buf.len() {
                        return Err(Error::Limit("symlink target"));
                    }
                    let target = &buf[..n as usize];
                    if target.starts_with(b"/") {
                        resolved.clear();
                    }
                    pending = join(target, &pending)?;
                }
                Ok(_) => resolved = next,
                Err(e) if missing(&e) => resolved = next,
                Err(e) => return Err(e),
            }
        }
        Ok(resolved)
    }
    fn mkdirs(image: &File, p: &[u8], c: &impl Fn() -> bool) -> Result<File, Error> {
        check(c)?;
        match open(image, p, libc::O_RDONLY | libc::O_DIRECTORY, false) {
            Ok(f) => return Ok(f),
            Err(e) if missing(&e) => (),
            Err(e) => return Err(e),
        }
        let (parent, name) = split(p);
        if name.is_empty() {
            return Err(Error::Invalid("missing root"));
        }
        let d = mkdirs(image, parent, c)?;
        cv(unsafe { libc::mkdirat(d.as_raw_fd(), cs(name)?.as_ptr(), 0o755) })?;
        let f = open(image, p, libc::O_RDONLY | libc::O_DIRECTORY, false)?;
        metadata(&f, 0o755)?;
        Ok(f)
    }
    fn metadata(f: &File, mode: u32) -> Result<(), Error> {
        cv(unsafe { libc::fchown(f.as_raw_fd(), 0, 0) })?;
        cv(unsafe { libc::fchmod(f.as_raw_fd(), mode) })?;
        let m = f.metadata()?;
        if m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != mode {
            return Err(Error::Unsupported(
                "filesystem did not preserve uid/gid/mode",
            ));
        }
        Ok(())
    }
    pub(super) fn copy(
        ctx: &Path,
        image: &Path,
        sources: &[&str],
        destination: &str,
        limits: Limits,
        policy: Option<&Policy>,
        c: &impl Fn() -> bool,
    ) -> Result<Summary, Error> {
        check(c)?;
        if sources.is_empty() {
            return Err(Error::Invalid("empty sources"));
        }
        if sources.len() > limits.max_entries {
            return Err(Error::Limit("entries"));
        }
        let dst = path(destination, true)?;
        if sources.len() > 1 && !destination.ends_with('/') {
            return Err(Error::Invalid("multiple sources require trailing slash"));
        }
        let ctx = root(ctx)?;
        let image = root(image)?;
        let dst = destination_path(&image, &dst, c)?;
        let dest_dir = match open(&image, &dst, libc::O_PATH, false) {
            Ok(f) => f.metadata()?.is_dir(),
            Err(e) if missing(&e) => false,
            Err(e) => return Err(e),
        };
        let mut plan = Plan {
            policy,
            work: crate::dockerignore::WORK,
            visited: 0,
            entries: Vec::new(),
            used: Summary::default(),
            limits,
        };
        for s in sources {
            check(c)?;
            let src = path(s, false)?;
            let m = open(&ctx, &src, libc::O_PATH | libc::O_NOFOLLOW, true)?.metadata()?;
            let target = if !m.is_dir() && (dest_dir || destination.ends_with('/')) {
                join(&dst, split(&src).1)?
            } else {
                dst.clone()
            };
            plan.used.targets.push(target.clone());
            plan.visit(&ctx, src, target, true, 0, c)?;
        }
        // Inspect destination metadata too, before any mutation. Do not silently
        // retain unsupported ACLs on merged directories.
        for e in &plan.entries {
            check(c)?;
            let mut ancestor = split(&e.dst).0;
            loop {
                match open(&image, ancestor, libc::O_PATH | libc::O_DIRECTORY, false) {
                    Ok(_) => {
                        attrs(&image, ancestor, false, c)?;
                    }
                    Err(e) if missing(&e) => (),
                    Err(e) => return Err(e),
                }
                if ancestor.is_empty() {
                    break;
                }
                ancestor = split(ancestor).0;
            }
            match open(&image, &e.dst, libc::O_PATH | libc::O_NOFOLLOW, false) {
                Ok(f) => {
                    attrs(&image, &e.dst, false, c)?;
                    if e.kind == libc::S_IFDIR && !f.metadata()?.is_dir() {
                        return Err(Error::Invalid("directory destination collision"));
                    }
                }
                Err(e) if missing(&e) => (),
                Err(e) => return Err(e),
            }
        }
        // Preflight completes before creating any destination. File payloads are
        // reread only under the caller's stable-context contract.
        let mut directory_metadata = std::collections::BTreeMap::new();
        for e in &plan.entries {
            check(c)?;
            if e.kind == libc::S_IFDIR {
                // Earlier selected sources may have introduced this leaf since
                // preflight. Never descend through a recursively visited link.
                match open(&image, &e.dst, libc::O_PATH | libc::O_NOFOLLOW, false) {
                    Ok(f) if !f.metadata()?.is_dir() => {
                        return Err(Error::Invalid("directory destination collision"));
                    }
                    Ok(_) => (),
                    Err(e) if missing(&e) => (),
                    Err(e) => return Err(e),
                }
                let existed = open(&image, &e.dst, libc::O_PATH | libc::O_DIRECTORY, false).is_ok();
                let f = mkdirs(&image, &e.dst, c)?;
                if !e.explicit || !existed {
                    let m = f.metadata()?;
                    directory_metadata.insert((m.dev(), m.ino()), e);
                }
                continue;
            }
            let (parent, name) = split(&e.dst);
            if name.is_empty() {
                return Err(Error::Invalid("non-directory image root"));
            }
            let d = mkdirs(&image, parent, c)?;
            if e.kind == libc::S_IFLNK {
                let n = cs(name)?;
                let rc = unsafe { libc::unlinkat(d.as_raw_fd(), n.as_ptr(), 0) };
                if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    return Err(io::Error::last_os_error().into());
                }
                cv(unsafe { libc::symlinkat(cs(&e.link)?.as_ptr(), d.as_raw_fd(), n.as_ptr()) })?;
                cv(unsafe {
                    libc::fchownat(d.as_raw_fd(), n.as_ptr(), 0, 0, libc::AT_SYMLINK_NOFOLLOW)
                })?;
                let (_parent, p) = attr_path(&image, &e.dst, false)?;
                for (name, value) in &e.attrs {
                    cv(unsafe {
                        libc::lsetxattr(
                            p.as_ptr(),
                            name.as_ptr(),
                            value.as_ptr().cast(),
                            value.len(),
                            0,
                        )
                    })?;
                }
                cv(unsafe {
                    libc::utimensat(
                        d.as_raw_fd(),
                        n.as_ptr(),
                        e.times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                })?;
            } else {
                let mut input = open(
                    &ctx,
                    &e.src,
                    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOATIME,
                    true,
                )?;
                if !input.metadata()?.is_file() {
                    return Err(Error::Invalid("source changed"));
                }
                // Inspect without opening devices/FIFOs for I/O. The stable
                // image contract excludes swaps between this check and open.
                match open(&image, &e.dst, libc::O_PATH | libc::O_NOFOLLOW, false) {
                    Ok(pin)
                        if !(pin.metadata()?.is_file()
                            || pin.metadata()?.file_type().is_symlink()) =>
                    {
                        return Err(Error::Invalid("destination is not regular"));
                    }
                    Ok(_) => (),
                    Err(e) if missing(&e) => (),
                    Err(e) => return Err(e),
                }
                let rc = unsafe { libc::unlinkat(d.as_raw_fd(), cs(name)?.as_ptr(), 0) };
                if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    return Err(io::Error::last_os_error().into());
                }
                let mut out = open(
                    &image,
                    &e.dst,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    false,
                )?;
                if !out.metadata()?.is_file() {
                    return Err(Error::Invalid("destination is not regular"));
                }
                out.set_len(0)?;
                let mut left = e.size;
                let mut buffer = [0; 65536];
                while left > 0 {
                    check(c)?;
                    let n = left.min(buffer.len() as u64) as usize;
                    input.read_exact(&mut buffer[..n])?;
                    out.write_all(&buffer[..n])?;
                    left -= n as u64;
                }
                check(c)?;
                if input.read(&mut buffer[..1])? != 0 {
                    return Err(Error::Invalid("source grew"));
                }
                restore(&out, e, c)?;
            }
        }
        // Postorder lets children be created before restrictive directory modes.
        let mut finished = std::collections::BTreeSet::new();
        for e in plan
            .entries
            .iter()
            .rev()
            .filter(|e| e.kind == libc::S_IFDIR)
        {
            check(c)?;
            let f = open(&image, &e.dst, libc::O_RDONLY | libc::O_DIRECTORY, false)?;
            let m = f.metadata()?;
            if !finished.insert((m.dev(), m.ino())) {
                continue;
            }
            if let Some(metadata_entry) = directory_metadata.get(&(m.dev(), m.ino())) {
                restore(&f, metadata_entry, c)?;
            }
            cv(unsafe { libc::futimens(f.as_raw_fd(), e.times.as_ptr()) })?;
        }
        Ok(plan.used)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };
    fn limits() -> Limits {
        Limits {
            max_bytes: 1_000_000,
            max_entries: 100,
            max_metadata_bytes: 100_000,
        }
    }
    fn run(ctx: &Path, image: &Path, src: &[&str], dst: &str) -> Result<Summary, Error> {
        copy_local(ctx, image, src, dst, limits(), || false)
    }

    #[test]
    fn cached_budget_uses_resolved_targets_and_execution_planner() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("tree")).unwrap();
        fs::write(ctx.path().join("tree/keep"), b"keep").unwrap();
        fs::write(ctx.path().join("tree/ignored"), b"ignored").unwrap();
        fs::write(ctx.path().join(".dockerignore"), b"tree/ignored\n").unwrap();
        fs::create_dir(image.path().join("long-destination")).unwrap();
        symlink("/long-destination", image.path().join("link")).unwrap();
        let policy = load_policy(ctx.path(), None, &|| false).unwrap();
        for sources in [&["tree"][..], &["tree/keep", "tree"][..]] {
            let copied = run(ctx.path(), image.path(), sources, "/link/").unwrap();
            assert!(
                copied
                    .targets
                    .iter()
                    .all(|p| p.starts_with(b"long-destination"))
            );
            let exact = Limits {
                max_bytes: copied.bytes_written,
                max_entries: copied.entries,
                max_metadata_bytes: copied.metadata_bytes,
            };
            let checked = validate_copy_budget(
                ctx.path(),
                sources,
                &copied.targets,
                exact,
                Some(&policy),
                &|| false,
            )
            .unwrap();
            assert_eq!(
                (
                    checked.entries,
                    checked.bytes_written,
                    checked.metadata_bytes
                ),
                (copied.entries, copied.bytes_written, copied.metadata_bytes)
            );
            for lower in [
                Limits {
                    max_bytes: exact.max_bytes - 1,
                    ..exact
                },
                Limits {
                    max_entries: exact.max_entries - 1,
                    ..exact
                },
                Limits {
                    max_metadata_bytes: exact.max_metadata_bytes - 1,
                    ..exact
                },
            ] {
                assert!(matches!(
                    validate_copy_budget(
                        ctx.path(),
                        sources,
                        &copied.targets,
                        lower,
                        Some(&policy),
                        &|| false
                    ),
                    Err(Error::Limit(_))
                ));
            }
            assert!(matches!(
                validate_copy_budget(
                    ctx.path(),
                    sources,
                    &copied.targets,
                    exact,
                    Some(&policy),
                    &|| true
                ),
                Err(Error::Cancelled)
            ));
        }
    }

    #[test]
    fn excluded_directories_require_descendants_and_count_as_visited() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir_all(ctx.path().join("excluded/needed")).unwrap();
        fs::create_dir_all(ctx.path().join("excluded/empty")).unwrap();
        fs::write(ctx.path().join("excluded/needed/keep"), b"keep").unwrap();
        fs::write(
            ctx.path().join(".dockerignore"),
            b"excluded\n!excluded/needed/keep\n",
        )
        .unwrap();
        let policy = load_policy(ctx.path(), None, &|| false).unwrap();
        assert!(validate_sources(ctx.path(), &["excluded"], &policy, &|| false).is_err());
        assert!(run(ctx.path(), image.path(), &["excluded"], "/out").is_err());
        let result = run(ctx.path(), image.path(), &["."], "/out").unwrap();
        assert_eq!(result.entries, 6);
        assert!(image.path().join("out/excluded/needed/keep").is_file());
        assert!(!image.path().join("out/excluded/empty").exists());
        let image = tempfile::tempdir().unwrap();
        assert!(matches!(
            copy_local(
                ctx.path(),
                image.path(),
                &["."],
                "/out",
                Limits {
                    max_entries: 5,
                    ..limits()
                },
                || false
            ),
            Err(Error::Limit(_))
        ));
        assert_eq!(fs::read_dir(image.path()).unwrap().count(), 0);
    }
    fn set_attr(p: &Path, name: &str, value: &[u8]) {
        use std::os::unix::ffi::OsStrExt;
        let p = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        let name = std::ffi::CString::new(name).unwrap();
        assert_eq!(
            unsafe {
                libc::lsetxattr(
                    p.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
    }
    fn get_attr(p: &Path, name: &str) -> Option<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;
        let p = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        let name = std::ffi::CString::new(name).unwrap();
        let mut b = vec![0; 65536];
        let n =
            unsafe { libc::lgetxattr(p.as_ptr(), name.as_ptr(), b.as_mut_ptr().cast(), b.len()) };
        if n < 0 {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODATA)
            );
            return None;
        }
        b.truncate(n as usize);
        Some(b)
    }
    #[test]
    fn overwrite_breaks_internal_hardlinks_and_clears_old_xattrs() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("new"), b"new").unwrap();
        fs::write(image.path().join("a"), b"old").unwrap();
        fs::hard_link(image.path().join("a"), image.path().join("b")).unwrap();
        set_attr(&image.path().join("a"), "user.old", b"old");
        run(ctx.path(), image.path(), &["new"], "/a").unwrap();
        assert_eq!(fs::read(image.path().join("b")).unwrap(), b"old");
        assert_ne!(
            fs::metadata(image.path().join("a")).unwrap().ino(),
            fs::metadata(image.path().join("b")).unwrap().ino()
        );
        assert_eq!(get_attr(&image.path().join("a"), "user.old"), None);
        assert_eq!(
            get_attr(&image.path().join("b"), "user.old"),
            Some(b"old".to_vec())
        );
    }
    #[test]
    fn recursive_leaf_replaces_symlink_but_explicit_destination_follows() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("dir")).unwrap();
        fs::write(ctx.path().join("dir/a"), b"new").unwrap();
        fs::create_dir(image.path().join("out")).unwrap();
        fs::write(image.path().join("victim"), b"keep").unwrap();
        symlink("/victim", image.path().join("out/a")).unwrap();
        run(ctx.path(), image.path(), &["dir"], "/out/").unwrap();
        assert_eq!(fs::read(image.path().join("victim")).unwrap(), b"keep");
        assert!(
            fs::symlink_metadata(image.path().join("out/a"))
                .unwrap()
                .is_file()
        );
        symlink("/victim", image.path().join("explicit")).unwrap();
        run(ctx.path(), image.path(), &["dir/a"], "/explicit").unwrap();
        assert!(
            fs::symlink_metadata(image.path().join("explicit"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(image.path().join("victim")).unwrap(), b"new");
    }
    #[test]
    fn selected_root_preserved_nested_metadata_replaced_and_alias_last_wins() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        for name in ["one", "two"] {
            fs::create_dir_all(ctx.path().join(name).join("nested")).unwrap();
        }
        fs::set_permissions(
            ctx.path().join("one/nested"),
            fs::Permissions::from_mode(0o711),
        )
        .unwrap();
        fs::set_permissions(
            ctx.path().join("two/nested"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        fs::create_dir_all(image.path().join("tmp/nested")).unwrap();
        fs::set_permissions(image.path().join("tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
        std::os::unix::fs::chown(image.path().join("tmp"), Some(123), Some(456)).unwrap();
        set_attr(&image.path().join("tmp"), "user.keep", b"yes");
        set_attr(&image.path().join("tmp/nested"), "user.old", b"no");
        symlink("/tmp", image.path().join("alias")).unwrap();
        run(ctx.path(), image.path(), &["one", "two"], "/alias/").unwrap();
        let m = fs::metadata(image.path().join("tmp")).unwrap();
        assert_eq!((m.mode() & 0o7777, m.uid(), m.gid()), (0o1777, 123, 456));
        assert_eq!(
            get_attr(&image.path().join("tmp"), "user.keep"),
            Some(b"yes".to_vec())
        );
        assert_eq!(get_attr(&image.path().join("tmp/nested"), "user.old"), None);
        assert_eq!(
            fs::metadata(image.path().join("tmp/nested"))
                .unwrap()
                .mode()
                & 0o7777,
            0o750
        );
    }
    #[test]
    fn nanosecond_times_and_capabilities_survive_ownership() {
        use std::os::unix::ffi::OsStrExt;
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("dir")).unwrap();
        fs::write(ctx.path().join("dir/file"), b"new").unwrap();
        symlink("file", ctx.path().join("dir/link")).unwrap();
        std::os::unix::fs::chown(ctx.path().join("dir/file"), Some(123), Some(456)).unwrap();
        let cap = [1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        set_attr(&ctx.path().join("dir/file"), "security.capability", &cap);
        set_attr(&ctx.path().join("dir"), "user.dir", b"directory");
        set_attr(&ctx.path().join("dir/file"), "user.file", b"payload");
        let ts = [
            libc::timespec {
                tv_sec: 123456789,
                tv_nsec: 123456789,
            },
            libc::timespec {
                tv_sec: 123456790,
                tv_nsec: 987654321,
            },
        ];
        for name in ["dir", "dir/file", "dir/link"] {
            let p = std::ffi::CString::new(ctx.path().join(name).as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        p.as_ptr(),
                        ts.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                },
                0
            );
        }
        run(ctx.path(), image.path(), &["dir"], "/out").unwrap();
        for name in ["out", "out/file", "out/link"] {
            let m = fs::symlink_metadata(image.path().join(name)).unwrap();
            assert_eq!(
                (m.atime(), m.atime_nsec(), m.mtime(), m.mtime_nsec()),
                (123456789, 123456789, 123456790, 987654321),
                "{name}"
            );
        }
        assert_eq!(
            get_attr(&image.path().join("out/file"), "security.capability"),
            Some(cap.to_vec())
        );
        assert_eq!(
            get_attr(&image.path().join("out/file"), "user.file"),
            Some(b"payload".to_vec())
        );
        assert_eq!(
            get_attr(&image.path().join("out"), "user.dir"),
            Some(b"directory".to_vec())
        );
    }
    #[test]
    fn unsupported_acl_and_xattr_budget_fail_before_any_mutation() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("first"), b"new").unwrap();
        fs::write(ctx.path().join("second"), b"new").unwrap();
        fs::write(image.path().join("canary"), b"keep").unwrap();
        // Linux POSIX ACL v2: owner, named user, group, mask, other.
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, 7u16, u32::MAX),
            (2, 4, 123),
            (4, 5, u32::MAX),
            (16, 5, u32::MAX),
            (32, 5, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(perm.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        set_attr(&ctx.path().join("second"), "system.posix_acl_access", &acl);
        assert!(matches!(
            run(ctx.path(), image.path(), &["first", "second"], "/out/"),
            Err(Error::Unsupported(_))
        ));
        assert!(!image.path().join("out").exists());
        set_attr(&ctx.path().join("first"), "user.large", &[7; 2048]);
        assert!(matches!(
            copy_local(
                ctx.path(),
                image.path(),
                &["first"],
                "/out",
                Limits {
                    max_metadata_bytes: 1024,
                    ..limits()
                },
                || false
            ),
            Err(Error::Limit(_))
        ));
        assert!(!image.path().join("out").exists());
        assert_eq!(fs::read(image.path().join("canary")).unwrap(), b"keep");
        fs::create_dir(image.path().join("parent")).unwrap();
        set_attr(
            &image.path().join("parent"),
            "system.posix_acl_default",
            &acl,
        );
        assert!(matches!(
            run(ctx.path(), image.path(), &["first"], "/parent/new/out"),
            Err(Error::Unsupported(_))
        ));
        assert!(!image.path().join("parent/new").exists());
    }
    #[test]
    fn repeated_selected_roots_keep_first_created_metadata() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("first")).unwrap();
        fs::create_dir(ctx.path().join("second")).unwrap();
        fs::set_permissions(ctx.path().join("first"), fs::Permissions::from_mode(0o710)).unwrap();
        fs::set_permissions(ctx.path().join("second"), fs::Permissions::from_mode(0o777)).unwrap();
        set_attr(&ctx.path().join("first"), "user.first", b"keep");
        set_attr(&ctx.path().join("second"), "user.second", b"skip");
        run(ctx.path(), image.path(), &["first", "second"], "/new/").unwrap();
        assert_eq!(
            fs::metadata(image.path().join("new")).unwrap().mode() & 0o7777,
            0o710
        );
        assert_eq!(
            get_attr(&image.path().join("new"), "user.first"),
            Some(b"keep".to_vec())
        );
        assert_eq!(get_attr(&image.path().join("new"), "user.second"), None);
    }
    #[test]
    fn earlier_source_symlink_cannot_redirect_later_directory_merge() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("first")).unwrap();
        symlink("/victim", ctx.path().join("first/a")).unwrap();
        fs::create_dir_all(ctx.path().join("second/a")).unwrap();
        fs::write(ctx.path().join("second/a/new"), b"new").unwrap();
        fs::create_dir(image.path().join("victim")).unwrap();
        assert!(run(ctx.path(), image.path(), &["first", "second"], "/out/").is_err());
        assert!(!image.path().join("victim/new").exists());
    }
    #[test]
    fn contents_merge_files_permissions_and_root_ownership() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("dir")).unwrap();
        fs::write(ctx.path().join("dir/a"), b"abc").unwrap();
        fs::write(ctx.path().join("b"), b"def").unwrap();
        fs::set_permissions(ctx.path().join("dir/a"), fs::Permissions::from_mode(0o751)).unwrap();
        fs::create_dir(image.path().join("out")).unwrap();
        fs::write(image.path().join("out/old"), b"keep").unwrap();
        let s = run(ctx.path(), image.path(), &["dir", "b"], "/out/").unwrap();
        assert_eq!(s.bytes_written, 6);
        assert_eq!(fs::read(image.path().join("out/a")).unwrap(), b"abc");
        assert_eq!(fs::read(image.path().join("out/b")).unwrap(), b"def");
        assert!(image.path().join("out/old").exists());
        assert!(!image.path().join("out/dir").exists());
        let m = fs::metadata(image.path().join("out/a")).unwrap();
        assert_eq!((m.mode() & 0o7777, m.uid(), m.gid()), (0o751, 0, 0));
        run(ctx.path(), image.path(), &["b"], "/renamed").unwrap();
        assert_eq!(fs::read(image.path().join("renamed")).unwrap(), b"def");
    }
    #[test]
    fn source_escape_canary_and_preserved_nested_symlinks() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"secret").unwrap();
        symlink(outside.path(), ctx.path().join("escape")).unwrap();
        for src in [
            "escape/secret",
            "escape",
            "../secret",
            "a/../../secret",
            "/secret",
            "*",
            "$SECRET",
        ] {
            assert!(
                run(ctx.path(), image.path(), &[src], "/out").is_err(),
                "{src}"
            );
        }
        assert_eq!(fs::read_dir(image.path()).unwrap().count(), 0);
        fs::create_dir(ctx.path().join("dir")).unwrap();
        symlink(outside.path().join("secret"), ctx.path().join("dir/link")).unwrap();
        run(ctx.path(), image.path(), &["dir"], "/out").unwrap();
        assert_eq!(
            fs::read_link(image.path().join("out/link")).unwrap(),
            outside.path().join("secret")
        );
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"secret");
    }
    #[test]
    fn destination_absolute_and_dotdot_links_stay_in_image() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("payload"), b"new").unwrap();
        fs::write(outside.path().join("payload"), b"canary").unwrap();
        let absolute = outside.path().to_str().unwrap();
        fs::create_dir_all(image.path().join(absolute.trim_start_matches('/'))).unwrap();
        symlink(absolute, image.path().join("link")).unwrap();
        run(ctx.path(), image.path(), &["payload"], "/link/").unwrap();
        assert_eq!(fs::read(outside.path().join("payload")).unwrap(), b"canary");
        assert_eq!(
            fs::read(
                image
                    .path()
                    .join(absolute.trim_start_matches('/'))
                    .join("payload")
            )
            .unwrap(),
            b"new"
        );
        symlink("../../target", image.path().join("relative")).unwrap();
        fs::create_dir(image.path().join("target")).unwrap();
        run(ctx.path(), image.path(), &["payload"], "/relative/").unwrap();
        assert!(image.path().join("target/payload").exists());
        symlink("/target/payload", image.path().join("filelink")).unwrap();
        run(ctx.path(), image.path(), &["payload"], "/filelink").unwrap();
    }
    #[test]
    fn collisions_and_multiple_source_rules() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("file"), b"new").unwrap();
        fs::create_dir(ctx.path().join("dir")).unwrap();
        fs::write(image.path().join("existing"), b"old").unwrap();
        assert!(run(ctx.path(), image.path(), &["dir"], "/existing").is_err());
        assert!(run(ctx.path(), image.path(), &["file", "dir"], "/out").is_err());
        fs::create_dir_all(image.path().join("out/file")).unwrap();
        assert!(run(ctx.path(), image.path(), &["file"], "/out/").is_err());
        run(ctx.path(), image.path(), &["file"], "/existing").unwrap();
        assert_eq!(fs::read(image.path().join("existing")).unwrap(), b"new");
    }
    #[test]
    fn budgets_ignore_and_preflight_cancellation_do_not_mutate() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("file"), b"payload").unwrap();
        for l in [
            Limits {
                max_bytes: 6,
                ..limits()
            },
            Limits {
                max_entries: 0,
                ..limits()
            },
            Limits {
                max_metadata_bytes: 1,
                ..limits()
            },
        ] {
            assert!(matches!(
                copy_local(ctx.path(), image.path(), &["file"], "/out", l, || false),
                Err(Error::Limit(_))
            ));
        }
        assert!(matches!(
            copy_local(
                ctx.path(),
                image.path(),
                &["file"],
                "/out",
                limits(),
                || true
            ),
            Err(Error::Cancelled)
        ));
        fs::write(ctx.path().join(".dockerignore"), b"file\n").unwrap();
        assert!(matches!(
            run(ctx.path(), image.path(), &["file"], "/out"),
            Err(Error::Invalid(_))
        ));
        fs::remove_file(ctx.path().join(".dockerignore")).unwrap();
        symlink("file", ctx.path().join(".dockerignore")).unwrap();
        assert!(run(ctx.path(), image.path(), &["file"], "/out").is_err());
        assert_eq!(fs::read_dir(image.path()).unwrap().count(), 0);
    }
    #[test]
    fn cancellation_between_stream_chunks() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("large"), vec![7; 200_000]).unwrap();
        let observed = Cell::new(false);
        let result = copy_local(
            ctx.path(),
            image.path(),
            &["large"],
            "/large",
            limits(),
            || {
                let stop = fs::metadata(image.path().join("large")).is_ok_and(|m| m.len() >= 65536);
                observed.set(observed.get() || stop);
                stop
            },
        );
        assert!(matches!(result, Err(Error::Cancelled)));
        assert!(observed.get());
        assert_eq!(
            fs::metadata(image.path().join("large")).unwrap().len(),
            65536
        );
    }
}
