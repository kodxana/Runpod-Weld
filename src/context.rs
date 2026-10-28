//! Bounded local COPY subset. Both roots must be stable, disjoint trees without
//! concurrent writers; the disposable image must have no external hardlinks.
//! On ANY execution error discard the image: copying is not transactional. Linux openat2
//! is required; nested mounts and magic links are refused. Roots themselves are
//! trusted caller paths. No host-path destination resolution is performed.
//!
//! Sources are context-relative paths or Go filepath.Match wildcards (`.` allowed);
//! no `..`, absolute paths, or symlink ancestors. `**` is not recursive. Explicit source symlinks
//! are rejected; symlinks encountered inside directories are copied verbatim.
//! Directory contents merge into destination. Multiple sources require a
//! trailing slash; matches from one wildcard overwrite in sorted order without it.
//! Empty wildcard matches are no-ops; missing literals fail. A single file uses
//! its basename when destination is a
//! directory (including an image-root symlink to one). Type collisions fail.
//! Ordered .dockerignore rules filter local sources before payload/xattr reads.
//!
//! Preserves permission bits except new selected directory roots default to 0755;
//! local sources default to uid/gid 0, stage sources
//! preserve ownership. Octal chmod and image-local chown override copied metadata.
//! Copies hardlinks as separate
//! files. Nanosecond atime/mtime and user.* / security.capability xattrs are
//! preserved. Other xattrs (including ACLs) fail preflight. Existing selected
//! directory roots retain ownership/mode/xattrs; nested directories take source
//! metadata, including with overrides. Sparse layout is unsupported.
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
pub(crate) use linux::{fingerprint, fingerprint_copy};

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

#[derive(Clone, Copy, Debug, Default)]
pub struct CopyOptions<'a> {
    pub chmod: Option<u32>,
    pub chown: Option<&'a str>,
}

pub fn parse_chmod(value: &str) -> Result<u32, Error> {
    if value.is_empty() || value.len() > 4 || !value.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(Error::Unsupported(
            "COPY --chmod requires an octal mode (0000..7777); symbolic modes are unsupported",
        ));
    }
    u32::from_str_radix(value, 8).map_err(|_| Error::Invalid("COPY chmod"))
}

pub fn validate_chown(value: &str) -> Result<(), Error> {
    if value.len() > 1024 {
        return Err(Error::Limit("COPY chown length"));
    }
    let parts: Vec<_> = value.split(':').collect();
    if value.len() > 1024
        || parts.len() > 2
        || parts[0].is_empty()
        || parts.iter().any(|s| {
            s.bytes()
                .any(|b| b.is_ascii_whitespace() || b == 0 || b == b'/')
        })
    {
        return Err(Error::Invalid("COPY --chown requires user[:group]"));
    }
    for part in parts {
        if !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && part
                .parse::<u32>()
                .ok()
                .filter(|n| *n != u32::MAX)
                .is_none()
        {
            return Err(Error::Invalid("COPY ownership ID out of range"));
        }
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub entries: usize,
    pub bytes_written: u64,
    pub metadata_bytes: u64,
    pub(crate) targets: Vec<Vec<u8>>,
}

/// Records physical payload writes, not a filesystem inventory. Metadata and
/// hardlink topology must still be observed after COPY. Only the closed managed
/// engine may use this across an otherwise mutation-free checkpoint boundary.
#[cfg(target_os = "linux")]
pub(crate) struct CopyWrites<'baseline> {
    baseline: &'baseline crate::export::Baseline,
    files: std::collections::BTreeSet<(u64, u64)>,
}

#[cfg(target_os = "linux")]
impl CopyWrites<'_> {
    pub(crate) fn validate_root(
        &self,
        baseline: &crate::export::Baseline,
        root: &std::fs::Metadata,
    ) -> io::Result<()> {
        if !std::ptr::eq(self.baseline, baseline) {
            return Err(io::Error::other("COPY checkpoint baseline changed"));
        }
        baseline.validate_copy_root(root)
    }

    pub(crate) fn contains(&self, file: &std::fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        self.files.contains(&(file.dev(), file.ino()))
    }
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
    /// Image symlink traversal cannot be fingerprinted without changing atime.
    /// No image metadata changed; execute COPY uncached instead.
    FingerprintUnavailable(&'static str),
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
        if let Self::FingerprintUnavailable(reason) = self {
            return write!(
                f,
                "COPY fingerprint unavailable ({reason}); execute uncached"
            );
        }
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
    copy_local_with_options(
        context_root,
        image_root,
        sources,
        destination,
        limits,
        CopyOptions::default(),
        cancelled,
    )
}

pub fn copy_local_with_options(
    context_root: &Path,
    image_root: &Path,
    sources: &[&str],
    destination: &str,
    limits: Limits,
    options: CopyOptions<'_>,
    cancelled: impl Fn() -> bool,
) -> Result<Summary, Error> {
    let policy = load_policy(context_root, None, &cancelled)?;
    copy_filtered_with_options(
        context_root,
        image_root,
        sources,
        destination,
        limits,
        Some(&policy),
        options,
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

pub fn copy_stage_with_options(
    context_root: &Path,
    image_root: &Path,
    sources: &[&str],
    destination: &str,
    limits: Limits,
    options: CopyOptions<'_>,
    cancelled: impl Fn() -> bool,
) -> Result<Summary, Error> {
    copy_filtered_with_options(
        context_root,
        image_root,
        sources,
        destination,
        limits,
        None,
        options,
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
    copy_filtered_with_options(
        context_root,
        image_root,
        sources,
        destination,
        limits,
        policy,
        CopyOptions::default(),
        cancelled,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn copy_filtered_with_options(
    context_root: &Path,
    image_root: &Path,
    sources: &[&str],
    destination: &str,
    limits: Limits,
    policy: Option<&Policy>,
    options: CopyOptions<'_>,
    cancelled: impl Fn() -> bool,
) -> Result<Summary, Error> {
    copy_filtered_checked(
        context_root,
        image_root,
        sources,
        destination,
        limits,
        policy,
        options,
        None,
        cancelled,
    )
}

/// Admission observes the prepared allocation before any destination mutation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn copy_filtered_checked(
    context_root: &Path,
    image_root: &Path,
    sources: &[&str],
    destination: &str,
    limits: Limits,
    policy: Option<&Policy>,
    options: CopyOptions<'_>,
    admission: Option<&dyn Fn(u64, u64) -> Result<(), Error>>,
    cancelled: impl Fn() -> bool,
) -> Result<Summary, Error> {
    #[cfg(target_os = "linux")]
    {
        // Share execution code with the managed path without changing its callback.
        let stop: &dyn Fn() -> bool = &cancelled;
        linux::copy(
            context_root,
            image_root,
            sources,
            destination,
            limits,
            policy,
            options,
            admission,
            None,
            &stop,
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
            options,
            admission,
            cancelled,
        );
        Err(Error::Unsupported("local COPY requires Linux"))
    }
}

/// Record one closed COPY interval against a continuously pinned baseline.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn copy_managed<'baseline>(
    context_root: &Path,
    image_root: &Path,
    sources: &[&str],
    destination: &str,
    limits: Limits,
    policy: Option<&Policy>,
    options: CopyOptions<'_>,
    baseline: &'baseline crate::export::Baseline,
    resources: Option<&crate::build_resources::Policy>,
    control: &crate::managed_control::ManagedControl<'_>,
) -> Result<(Summary, Option<CopyWrites<'baseline>>), Error> {
    let mut writes = baseline.has_copy_root().then(|| CopyWrites {
        baseline,
        files: std::collections::BTreeSet::new(),
    });
    let admission = |bytes, inodes| {
        resources.map_or(Ok(()), |policy| {
            policy
                .recheck(
                    "COPY prepared allocation",
                    &[crate::build_resources::Requirement {
                        path: image_root.to_owned(),
                        bytes,
                        inodes,
                    }],
                )
                .map_err(|e| Error::Io(io::Error::other(e)))
        })
    };
    let stop: &dyn Fn() -> bool = &|| control.poll();
    let summary = linux::copy(
        context_root,
        image_root,
        sources,
        destination,
        limits,
        policy,
        options,
        resources.map(|_| &admission as &dyn Fn(u64, u64) -> _),
        writes.as_mut(),
        &stop,
    )?;
    Ok((summary, writes))
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

    fn ownership_error(e: Error, uid: u32, gid: u32) -> Error {
        match e {
            Error::Io(e) => Error::Io(io::Error::new(
                e.kind(),
                format!(
                    "COPY cannot set inode ownership to {uid}:{gid}: {e}; the Pod must permit this ownership change"
                ),
            )),
            e => e,
        }
    }
    fn resolve_owner(
        image: &File,
        value: &str,
        fingerprinting: bool,
        c: &impl Fn() -> bool,
    ) -> Result<(u32, u32), Error> {
        validate_chown(value)?;
        fn lookup(
            image: &File,
            name: &str,
            group: bool,
            fingerprinting: bool,
            c: &impl Fn() -> bool,
        ) -> Result<Option<(u32, u32)>, Error> {
            let path: &[u8] = if group { b"etc/group" } else { b"etc/passwd" };
            let resolved;
            let path = if fingerprinting {
                resolved = match destination_path(image, path, true, c) {
                    Ok(path) => path,
                    Err(Error::Io(e))
                        if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) =>
                    {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                };
                resolved.as_slice()
            } else {
                path
            };
            let pin = match open(image, path, libc::O_PATH | libc::O_NOFOLLOW, fingerprinting) {
                Ok(pin) => pin,
                Err(Error::Io(e))
                    if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            let pin = if pin.metadata()?.file_type().is_symlink() {
                open(image, path, libc::O_PATH, false)?
            } else {
                pin
            };
            if !pin.metadata()?.is_file() {
                return Err(Error::Invalid("COPY account database must be regular"));
            }
            let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOATIME;
            // EPERM means we cannot promise restoration of explicit timestamps
            // either. Fingerprinting fails before reading instead of falling back.
            let mut f = match open(image, path, flags, false) {
                Err(Error::Io(e)) if !fingerprinting && e.raw_os_error() == Some(libc::EPERM) => {
                    open(image, path, flags & !libc::O_NOATIME, false)?
                }
                result => result?,
            };
            let mut data = Vec::new();
            let mut buf = [0; 8192];
            loop {
                check(c)?;
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                if data.len() + n > 1024 * 1024 {
                    return Err(Error::Limit("COPY account database bytes"));
                }
                data.extend_from_slice(&buf[..n]);
            }
            let text = std::str::from_utf8(&data)
                .map_err(|_| Error::Invalid("COPY account database UTF-8"))?;
            for line in text.lines() {
                check(c)?;
                let fields: Vec<_> = line.split(':').collect();
                if fields.first() != Some(&name) {
                    continue;
                }
                let id = |i: usize| {
                    fields
                        .get(i)
                        .and_then(|v| v.parse::<u32>().ok())
                        .filter(|n| *n != u32::MAX)
                        .ok_or(Error::Invalid("COPY malformed account ID"))
                };
                return Ok(Some((id(2)?, if group { id(2)? } else { id(3)? })));
            }
            Ok(None)
        }
        let (user, group) = value.split_once(':').unwrap_or((value, ""));
        let user = if user == "root" { "0" } else { user };
        let group = if group == "root" { "0" } else { group };
        let (uid, primary) = match user.parse::<u32>() {
            Ok(id) => (id, id),
            Err(_) => lookup(image, user, false, fingerprinting, c)?.unwrap_or((0, 0)),
        };
        let gid = if group.is_empty() {
            primary
        } else {
            match group.parse::<u32>() {
                Ok(id) => id,
                Err(_) => {
                    lookup(image, group, true, fingerprinting, c)?.map_or(primary, |ids| ids.0)
                }
            }
        };
        Ok((uid, gid))
    }

    #[derive(Debug)]
    enum Glob {
        Literal(char),
        Any,
        Star,
        Class(bool, Vec<(char, char)>),
    }
    fn pattern(s: &str) -> Result<Vec<Glob>, Error> {
        let mut it = s.chars().peekable();
        let mut tokens = Vec::new();
        fn character(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<char, Error> {
            match it.next() {
                Some('\\') => it
                    .next()
                    .ok_or(Error::Invalid("COPY malformed wildcard escape")),
                Some(']' | '-') | None => Err(Error::Invalid("COPY malformed wildcard class")),
                Some(c) => Ok(c),
            }
        }
        while let Some(c) = it.next() {
            tokens.push(match c {
                '*' => Glob::Star,
                '?' => Glob::Any,
                '\\' => Glob::Literal(
                    it.next()
                        .ok_or(Error::Invalid("COPY malformed wildcard escape"))?,
                ),
                '[' => {
                    let neg = it.peek() == Some(&'^');
                    if neg {
                        it.next();
                    }
                    let mut ranges = Vec::new();
                    loop {
                        let lo = character(&mut it)?;
                        let hi = if it.peek() == Some(&'-') {
                            it.next();
                            character(&mut it)?
                        } else {
                            lo
                        };
                        ranges.push((lo, hi));
                        if it.peek() == Some(&']') {
                            it.next();
                            break;
                        }
                    }
                    Glob::Class(neg, ranges)
                }
                c => Glob::Literal(c),
            });
        }
        Ok(tokens)
    }
    fn matches(tokens: &[Glob], name: &[u8], work: &mut u64) -> Result<bool, Error> {
        fn rune(bytes: &[u8]) -> (char, usize) {
            let n = match bytes[0] {
                0..=127 => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => 0,
            };
            if n > 0
                && bytes.len() >= n
                && let Ok(s) = std::str::from_utf8(&bytes[..n])
            {
                return (s.chars().next().unwrap(), n);
            }
            ('\u{fffd}', 1)
        }
        let mut state = vec![false; name.len() + 1];
        state[0] = true;
        for token in tokens {
            *work = work
                .checked_sub(name.len() as u64 + 1)
                .ok_or(Error::Limit("COPY wildcard work"))?;
            let mut next = vec![false; state.len()];
            for i in 0..state.len() {
                if matches!(token, Glob::Star) {
                    next[i] = state[i] || (i > 0 && next[i - 1]);
                } else if state[i] && i < name.len() {
                    let (ch, n) = rune(&name[i..]);
                    let yes = match token {
                        Glob::Literal(c) => {
                            let mut bytes = [0; 4];
                            let literal = c.encode_utf8(&mut bytes).as_bytes();
                            if name[i..].starts_with(literal) {
                                next[i + literal.len()] = true;
                            }
                            false
                        }
                        Glob::Any => true,
                        Glob::Class(neg, ranges) => {
                            ranges.iter().any(|(lo, hi)| *lo <= ch && ch <= *hi) != *neg
                        }
                        Glob::Star => unreachable!(),
                    };
                    if yes {
                        next[i + n] = true;
                    }
                }
            }
            state = next;
        }
        Ok(state[name.len()])
    }

    fn names(dir: File, mut visit: impl FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        let fd = dir.into_raw_fd();
        let raw = unsafe { libc::fdopendir(fd) };
        if raw.is_null() {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::last_os_error().into());
        }
        struct Dir(*mut libc::DIR);
        impl Drop for Dir {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let dir = Dir(raw);
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let ent = unsafe { libc::readdir(dir.0) };
            if ent.is_null() {
                let e = io::Error::last_os_error();
                return if e.raw_os_error() == Some(0) {
                    Ok(())
                } else {
                    Err(e.into())
                };
            }
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                visit(name)?;
            }
        }
    }
    fn select(
        ctx: &File,
        sources: &[&str],
        plan: &mut Plan<'_>,
        c: &impl Fn() -> bool,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if sources.len() > plan.limits.max_entries {
            return Err(Error::Limit("COPY selected sources"));
        }
        let mut selected = Vec::new();
        for source in sources {
            check(c)?;
            if source.is_empty()
                || source.len() > 4096
                || source.starts_with('/')
                || source.contains('\0')
                || source.split('/').any(|p| p == "..")
                || source.split('/').count() > 128
            {
                return Err(Error::Invalid("COPY source path"));
            }
            let parts: Vec<_> = source
                .split('/')
                .filter(|p| !p.is_empty() && *p != ".")
                .collect();
            let wildcard = source.contains(['*', '?', '[', '\\']);
            if !wildcard {
                selected.push(path(source, false)?);
                continue;
            }
            let patterns = parts
                .iter()
                .map(|p| pattern(p))
                .collect::<Result<Vec<_>, _>>()?;
            let mut pending = vec![Vec::new()];
            for (index, tokens) in patterns.iter().enumerate() {
                let mut next = Vec::new();
                for parent in pending {
                    let dir = open(
                        ctx,
                        &parent,
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOATIME,
                        true,
                    )?;
                    names(dir, |name| {
                        check(c)?;
                        let child = join(&parent, name)?;
                        if plan.visited >= plan.limits.max_entries {
                            return Err(Error::Limit("wildcard entries"));
                        }
                        plan.visited += 1;
                        plan.used.entries += 1;
                        plan.used.metadata_bytes = plan
                            .used
                            .metadata_bytes
                            .checked_add(512 + child.len() as u64)
                            .filter(|n| *n <= plan.limits.max_metadata_bytes)
                            .ok_or(Error::Limit("wildcard metadata"))?;
                        if !matches(tokens, name, &mut plan.work)? {
                            return Ok(());
                        }
                        let excluded = match plan.policy {
                            Some(p) => p.excluded_cancellable(&child, &mut plan.work, c)?,
                            None => false,
                        };
                        if excluded
                            && (index + 1 == patterns.len()
                                || !plan.policy.is_some_and(|p| p.negations))
                        {
                            return Ok(());
                        }
                        let m =
                            open(ctx, &child, libc::O_PATH | libc::O_NOFOLLOW, true)?.metadata()?;
                        if index + 1 < patterns.len() {
                            if m.file_type().is_symlink() {
                                return Err(Error::Unsupported(
                                    "wildcard source symlink traversal",
                                ));
                            }
                            if m.is_dir() {
                                next.push(child);
                            }
                        } else if m.is_file() || m.is_dir() {
                            next.push(child);
                        } else {
                            return Err(Error::Unsupported("explicit wildcard source type"));
                        }
                        Ok(())
                    })?;
                }
                pending = next;
            }
            pending.sort();
            selected.extend(pending);
        }
        if sources.is_empty() {
            return Err(Error::Invalid("empty COPY sources"));
        }
        if selected.len() > plan.limits.max_entries {
            return Err(Error::Limit("COPY selected sources"));
        }
        Ok(selected)
    }
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
            let error = io::Error::last_os_error();
            // O_NOATIME needs ownership or CAP_FOWNER; readable sources must not.
            if source && flags & libc::O_NOATIME != 0 && error.raw_os_error() == Some(libc::EPERM) {
                return open(root, p.as_bytes(), flags & !libc::O_NOATIME, source);
            }
            return Err(error.into());
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
        let mut plan = Plan {
            policy: Some(policy),
            work: crate::dockerignore::WORK,
            visited: 0,
            entries: Vec::new(),
            xattr_scratch: XattrScratch::default(),
            used: Summary::default(),
            limits: Limits {
                max_entries: 1_000_000,
                max_bytes: u64::MAX,
                max_metadata_bytes: 256 * 1024 * 1024,
            },
        };
        for src in select(&ctx, sources, &mut plan, c)? {
            let m = open(&ctx, &src, libc::O_PATH | libc::O_NOFOLLOW, true)?.metadata()?;
            if policy.excluded_cancellable(&src, &mut plan.work, c)? {
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
            xattr_scratch: XattrScratch::default(),
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

    /// Fingerprint the source effects of one COPY against its pre-instruction image.
    /// `Some(policy)` means local COPY (default root ownership); `None` means a
    /// stage COPY (source ownership). The caller keys the parent image/config and
    /// options, enforces cumulative receipts, and still checks execution permissions.
    /// Both trees must remain stable and obey the same confinement contract as COPY.
    /// Account reads require O_NOATIME permission. Image symlink traversal returns
    /// FingerprintUnavailable before reading: execute COPY uncached instead.
    /// Restoring atime would change RUN-observable ctime, so no restoration is used.
    /// Source atime changes remain legitimate strict-metadata cache misses.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fingerprint_copy(
        ctx: &Path,
        image: &Path,
        sources: &[&str],
        destination: &str,
        limits: Limits,
        policy: Option<&Policy>,
        options: CopyOptions<'_>,
        c: &impl Fn() -> bool,
    ) -> Result<(Vec<u8>, Summary), Error> {
        use sha2::{Digest, Sha256};
        fn field(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        check(c)?;
        let ctx = root(ctx)?;
        let image = root(image)?;
        let (mut plan, owner) = prepare_copy(
            &ctx,
            &image,
            sources,
            destination,
            limits,
            policy,
            options,
            true,
            c,
        )?;
        let mut hash = Sha256::new();
        field(&mut hash, b"selected-copy-v2");
        // mkdirs creates ancestors before entries in source order. Any ancestor
        // never visited as a directory receives these defaults at COPY completion.
        let mut implicit = std::collections::BTreeSet::new();
        for e in &plan.entries {
            let mut parent = split(&e.dst).0;
            while !parent.is_empty() {
                check(c)?;
                match open(&image, parent, libc::O_PATH | libc::O_DIRECTORY, true) {
                    Ok(_) => break,
                    Err(err) if missing(&err) => {
                        implicit.insert(parent.to_vec());
                    }
                    Err(err) => return Err(err),
                }
                parent = split(parent).0;
            }
        }
        for e in &plan.entries {
            if e.kind == libc::S_IFDIR {
                implicit.remove(&e.dst);
            }
        }
        field(&mut hash, &(implicit.len() as u64).to_le_bytes());
        let (uid, gid) = owner.unwrap_or((0, 0));
        for parent in implicit {
            field(&mut hash, &parent);
            field(&mut hash, &uid.to_le_bytes());
            field(&mut hash, &gid.to_le_bytes());
            field(&mut hash, &options.chmod.unwrap_or(0o755).to_le_bytes());
        }
        field(&mut hash, destination.as_bytes());
        field(&mut hash, &(sources.len() as u64).to_le_bytes());
        for source in sources {
            field(&mut hash, source.as_bytes());
        }
        field(&mut hash, &(plan.entries.len() as u64).to_le_bytes());
        let mut directories = std::collections::BTreeSet::<Vec<u8>>::new();
        for e in &mut plan.entries {
            check(c)?;
            field(&mut hash, &e.src);
            field(&mut hash, &e.dst);
            field(&mut hash, &e.kind.to_le_bytes());
            // Existing selected roots retain destination metadata. Account for
            // roots introduced by earlier sources and implicit parent creation too.
            let mut prefix = e.dst.clone();
            prefix.push(b'/');
            let introduced = directories.contains(&e.dst)
                || directories
                    .range(prefix.clone()..)
                    .next()
                    .is_some_and(|p| p.starts_with(&prefix));
            let retained = e.explicit
                && e.kind == libc::S_IFDIR
                && (introduced
                    || match open(&image, &e.dst, libc::O_PATH | libc::O_DIRECTORY, false) {
                        Ok(_) => true,
                        Err(err) if missing(&err) => false,
                        Err(err) => return Err(err),
                    });
            // Store only immediate parents; prefix lookup also finds ancestors,
            // without allocating every ancestor path for each manifest entry.
            directories.insert(if e.kind == libc::S_IFDIR {
                e.dst.clone()
            } else {
                split(&e.dst).0.to_vec()
            });
            field(&mut hash, &[u8::from(retained)]);
            if retained {
                // COPY retains mode/owner/xattrs, but always applies the last
                // selected directory's source timestamps after its children.
                let m = open(&ctx, &e.src, libc::O_PATH | libc::O_NOFOLLOW, true)?.metadata()?;
                for time in times(&m) {
                    field(&mut hash, &time.tv_sec.to_le_bytes());
                    field(&mut hash, &time.tv_nsec.to_le_bytes());
                }
                continue;
            }
            // Symlink permission bits are not applied by COPY.
            if e.kind != libc::S_IFLNK {
                field(&mut hash, &e.mode.to_le_bytes());
            }
            field(&mut hash, &e.uid.to_le_bytes());
            field(&mut hash, &e.gid.to_le_bytes());
            field(&mut hash, &e.size.to_le_bytes());
            field(&mut hash, &e.link);
            e.attrs.sort_by(|a, b| a.0.cmp(&b.0));
            field(&mut hash, &(e.attrs.len() as u64).to_le_bytes());
            for (name, value) in &e.attrs {
                field(&mut hash, name.as_bytes());
                field(&mut hash, value);
            }
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
            // readlink and O_NOATIME's EPERM fallback can update atime. Hash the
            // metadata the subsequent COPY will observe, never discard timestamps.
            let m = open(&ctx, &e.src, libc::O_PATH | libc::O_NOFOLLOW, true)?.metadata()?;
            for time in times(&m) {
                field(&mut hash, &time.tv_sec.to_le_bytes());
                field(&mut hash, &time.tv_nsec.to_le_bytes());
            }
        }
        Ok((hash.finalize().to_vec(), plan.used))
    }

    pub(super) fn validate_copy_budget(
        ctx: &Path,
        sources: &[&str],
        targets: &[Vec<u8>],
        limits: Limits,
        policy: Option<&Policy>,
        c: &impl Fn() -> bool,
    ) -> Result<Summary, Error> {
        if sources.is_empty() {
            return Err(Error::Invalid("cached COPY targets"));
        }
        let ctx = root(ctx)?;
        let mut plan = Plan {
            policy,
            work: crate::dockerignore::WORK,
            visited: 0,
            entries: Vec::new(),
            xattr_scratch: XattrScratch::default(),
            used: Summary::default(),
            limits,
        };
        let selected = select(&ctx, sources, &mut plan, c)?;
        if selected.len() != targets.len() {
            return Err(Error::Invalid("cached COPY targets"));
        }
        for (source, target) in selected.into_iter().zip(targets) {
            if target.len() > 4096
                || target.contains(&0)
                || target.starts_with(b"/")
                || target
                    .split(|b| *b == b'/')
                    .any(|p| p == b".." || p == b".")
            {
                return Err(Error::Invalid("cached COPY target"));
            }
            plan.visit(&ctx, source, target.clone(), true, 0, c)?;
        }
        Ok(plan.used)
    }
    fn path(p: &str, absolute: bool) -> Result<Vec<u8>, Error> {
        if p.is_empty()
            || p.len() > 4096
            || p.starts_with('/') != absolute
            || p.bytes().any(|b| b"\0".contains(&b))
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
        uid: u32,
        gid: u32,
        size: u64,
        kind: u32,
        link: Vec<u8>,
        times: [libc::timespec; 2],
        attrs: Vec<(CString, Vec<u8>)>,
        explicit: bool,
    }
    #[derive(Default)]
    struct XattrScratch {
        names: Vec<u8>,
        value: Vec<u8>,
    }
    struct Plan<'a> {
        policy: Option<&'a Policy>,
        work: u64,
        visited: usize,
        entries: Vec<Entry>,
        xattr_scratch: XattrScratch,
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
            let attrs = attrs(ctx, &src, true, &mut self.xattr_scratch, c)?;
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
                    uid: m.uid(),
                    gid: m.gid(),
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
        scratch: &mut XattrScratch,
        c: &impl Fn() -> bool,
    ) -> Result<Vec<(CString, Vec<u8>)>, Error> {
        let follow = p.is_empty();
        let (_d, p) = attr_path(root, p, source)?;
        let XattrScratch { names, value } = scratch;
        if names.is_empty() {
            names.resize(65536, 0);
        }
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
            if value.is_empty() {
                value.resize(65536, 0);
            }
            let remaining = 65536 - total;
            let n = unsafe {
                if follow {
                    libc::getxattr(
                        p.as_ptr(),
                        name.as_ptr(),
                        value.as_mut_ptr().cast(),
                        remaining,
                    )
                } else {
                    libc::lgetxattr(
                        p.as_ptr(),
                        name.as_ptr(),
                        value.as_mut_ptr().cast(),
                        remaining,
                    )
                }
            };
            if n < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if n as usize > remaining {
                return Err(Error::Limit("xattr bytes"));
            }
            total += n as usize;
            if total == 65536 {
                return Err(Error::Limit("xattr bytes"));
            }
            result.push((name, value[..n as usize].to_vec()));
        }
        Ok(result)
    }
    fn restore(
        f: &File,
        e: &Entry,
        scratch: &mut XattrScratch,
        c: &impl Fn() -> bool,
    ) -> Result<(), Error> {
        // user.* requires inode write permission, even through an open writable FD.
        metadata(f, e.mode | 0o600, e.uid, e.gid)?;
        for (name, _) in attrs(f, b"", false, scratch, c)? {
            cv(unsafe { libc::fremovexattr(f.as_raw_fd(), name.as_ptr()) })?;
        }
        for capability in [false, true] {
            if capability {
                // Install capabilities only after payload, ownership and final mode.
                metadata(f, e.mode, e.uid, e.gid)?;
            }
            for (name, value) in &e.attrs {
                if (name.as_bytes() == b"security.capability") != capability {
                    continue;
                }
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
        }
        cv(unsafe { libc::futimens(f.as_raw_fd(), e.times.as_ptr()) })?;
        Ok(())
    }
    // Resolve only the requested destination, including its leaf. Recursive
    // source entries use no-follow leaf replacement instead.
    fn destination_path(
        image: &File,
        p: &[u8],
        fingerprinting: bool,
        c: &impl Fn() -> bool,
    ) -> Result<Vec<u8>, Error> {
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
                    if fingerprinting {
                        return Err(Error::FingerprintUnavailable("image symlink traversal"));
                    }
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
    fn mkdirs(
        image: &File,
        p: &[u8],
        created: &mut std::collections::BTreeSet<Vec<u8>>,
        c: &impl Fn() -> bool,
    ) -> Result<File, Error> {
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
        let d = mkdirs(image, parent, created, c)?;
        cv(unsafe { libc::mkdirat(d.as_raw_fd(), cs(name)?.as_ptr(), 0o755) })?;
        let f = open(image, p, libc::O_RDONLY | libc::O_DIRECTORY, false)?;
        cv(unsafe { libc::fchmod(f.as_raw_fd(), 0o755) })?;
        created.insert(p.to_vec());
        Ok(f)
    }
    fn metadata(f: &File, mode: u32, uid: u32, gid: u32) -> Result<(), Error> {
        let current = f.metadata()?;
        if current.uid() != uid || current.gid() != gid {
            cv(unsafe { libc::fchown(f.as_raw_fd(), uid, gid) })
                .map_err(|e| ownership_error(e, uid, gid))?;
        }
        cv(unsafe { libc::fchmod(f.as_raw_fd(), mode) })?;
        let m = f.metadata()?;
        if m.uid() != uid || m.gid() != gid || m.mode() & 0o7777 != mode {
            return Err(Error::Unsupported(
                "filesystem did not preserve uid/gid/mode",
            ));
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_copy<'a>(
        ctx: &File,
        image: &File,
        sources: &[&str],
        destination: &str,
        limits: Limits,
        policy: Option<&'a Policy>,
        options: CopyOptions<'_>,
        fingerprinting: bool,
        c: &impl Fn() -> bool,
    ) -> Result<(Plan<'a>, Option<(u32, u32)>), Error> {
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
        if options.chmod.is_some_and(|m| m > 0o7777) {
            return Err(Error::Invalid("COPY chmod exceeds 7777"));
        }
        let owner = options
            .chown
            .map(|v| resolve_owner(image, v, fingerprinting, c))
            .transpose()?;
        let dst = destination_path(image, &dst, fingerprinting, c)?;
        let dest_dir = match open(image, &dst, libc::O_PATH, false) {
            Ok(f) => f.metadata()?.is_dir(),
            Err(e) if missing(&e) => false,
            Err(e) => return Err(e),
        };
        let mut plan = Plan {
            policy,
            work: crate::dockerignore::WORK,
            visited: 0,
            entries: Vec::new(),
            xattr_scratch: XattrScratch::default(),
            used: Summary::default(),
            limits,
        };
        let selected = select(ctx, sources, &mut plan, c)?;
        for src in selected {
            check(c)?;
            let m = open(ctx, &src, libc::O_PATH | libc::O_NOFOLLOW, true)?.metadata()?;
            let target = if !m.is_dir() && (dest_dir || destination.ends_with('/')) {
                join(&dst, split(&src).1)?
            } else {
                dst.clone()
            };
            plan.used.targets.push(target.clone());
            let start = plan.entries.len();
            plan.visit(ctx, src, target, true, 0, c)?;
            // Canonical native-byte order within each source, preserving source overwrites.
            plan.entries[start..].sort_by(|a, b| a.src.cmp(&b.src));
        }
        for e in &mut plan.entries {
            if let Some(mode) = options.chmod {
                e.mode = mode;
            } else if e.explicit && e.kind == libc::S_IFDIR {
                e.mode = 0o755;
            }
            let (uid, gid) = owner.unwrap_or(if policy.is_some() {
                (0, 0)
            } else {
                (e.uid, e.gid)
            });
            e.uid = uid;
            e.gid = gid;
        }
        // Inspect destination metadata too, before any mutation. Do not silently
        // retain unsupported ACLs on merged directories.
        for e in &plan.entries {
            check(c)?;
            let mut ancestor = split(&e.dst).0;
            loop {
                match open(
                    image,
                    ancestor,
                    libc::O_PATH | libc::O_DIRECTORY,
                    fingerprinting,
                ) {
                    Ok(_) => {
                        attrs(image, ancestor, false, &mut plan.xattr_scratch, c)?;
                    }
                    Err(e) if missing(&e) => (),
                    Err(e) => return Err(e),
                }
                if ancestor.is_empty() {
                    break;
                }
                ancestor = split(ancestor).0;
            }
            match open(image, &e.dst, libc::O_PATH | libc::O_NOFOLLOW, false) {
                Ok(f) => {
                    attrs(image, &e.dst, false, &mut plan.xattr_scratch, c)?;
                    if e.kind == libc::S_IFDIR && !f.metadata()?.is_dir() {
                        return Err(Error::Invalid("directory destination collision"));
                    }
                }
                Err(e) if missing(&e) => (),
                Err(e) => return Err(e),
            }
        }
        Ok((plan, owner))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn copy(
        ctx: &Path,
        image: &Path,
        sources: &[&str],
        destination: &str,
        limits: Limits,
        policy: Option<&Policy>,
        options: CopyOptions<'_>,
        admission: Option<&dyn Fn(u64, u64) -> Result<(), Error>>,
        mut record: Option<&mut CopyWrites<'_>>,
        c: &impl Fn() -> bool,
    ) -> Result<Summary, Error> {
        let ctx = root(ctx)?;
        let image = root(image)?;
        if let Some(record) = record.as_ref() {
            record.validate_root(record.baseline, &image.metadata()?)?;
        }
        let (mut plan, owner) = prepare_copy(
            &ctx,
            &image,
            sources,
            destination,
            limits,
            policy,
            options,
            false,
            c,
        )?;
        if let Some(admission) = admission {
            let mut bytes = 0u64;
            let mut inodes = 0u64;
            // Borrowed prefixes are bounded by the already-budgeted plan paths.
            let mut directories = std::collections::BTreeSet::new();
            for e in &plan.entries {
                check(c)?;
                let attrs = e.attrs.iter().try_fold(0u64, |size, (name, value)| {
                    size.checked_add(name.as_bytes().len() as u64)
                        .and_then(|n| n.checked_add(value.len() as u64))
                        .ok_or(Error::Limit("COPY allocation"))
                })?;
                let attrs = attrs
                    .checked_add(4095)
                    .ok_or(Error::Limit("COPY allocation"))?
                    / 4096
                    * 4096;
                bytes = bytes
                    .checked_add(attrs)
                    .ok_or(Error::Limit("COPY allocation"))?;
                if e.kind != libc::S_IFDIR {
                    let payload = e
                        .size
                        .checked_add(4095)
                        .ok_or(Error::Limit("COPY allocation"))?
                        / 4096
                        * 4096;
                    bytes = bytes
                        .checked_add(payload)
                        .and_then(|n| n.checked_add(4096))
                        .ok_or(Error::Limit("COPY allocation"))?;
                    inodes = inodes.checked_add(1).ok_or(Error::Limit("COPY inodes"))?;
                }
                let mut parent = if e.kind == libc::S_IFDIR {
                    e.dst.as_slice()
                } else {
                    split(&e.dst).0
                };
                while !parent.is_empty() && directories.insert(parent) {
                    check(c)?;
                    match open(&image, parent, libc::O_PATH | libc::O_DIRECTORY, false) {
                        Ok(_) => (),
                        Err(e) if missing(&e) => {
                            bytes = bytes
                                .checked_add(4096)
                                .ok_or(Error::Limit("COPY allocation"))?;
                            inodes = inodes.checked_add(1).ok_or(Error::Limit("COPY inodes"))?;
                        }
                        Err(e) => return Err(e),
                    }
                    parent = split(parent).0;
                }
            }
            admission(bytes, inodes)?;
        }
        // Preflight completes before creating any destination. File payloads are
        // reread only under the caller's stable-context contract.
        let mut created = std::collections::BTreeSet::new();
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
                let f = mkdirs(&image, &e.dst, &mut created, c)?;
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
            let d = mkdirs(&image, parent, &mut created, c)?;
            if e.kind == libc::S_IFLNK {
                let n = cs(name)?;
                let rc = unsafe { libc::unlinkat(d.as_raw_fd(), n.as_ptr(), 0) };
                if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    return Err(io::Error::last_os_error().into());
                }
                cv(unsafe { libc::symlinkat(cs(&e.link)?.as_ptr(), d.as_raw_fd(), n.as_ptr()) })?;
                let m = open(&image, &e.dst, libc::O_PATH | libc::O_NOFOLLOW, false)?.metadata()?;
                if m.uid() != e.uid || m.gid() != e.gid {
                    cv(unsafe {
                        libc::fchownat(
                            d.as_raw_fd(),
                            n.as_ptr(),
                            e.uid,
                            e.gid,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    })
                    .map_err(|err| ownership_error(err, e.uid, e.gid))?;
                }
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
                if let Some(record) = record.as_mut() {
                    let metadata = out.metadata()?;
                    // Bounded by prepared entries (already charged 512 bytes each).
                    record.files.insert((metadata.dev(), metadata.ino()));
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
                restore(&out, e, &mut plan.xattr_scratch, c)?;
            }
        }
        for e in plan.entries.iter().filter(|e| e.kind == libc::S_IFDIR) {
            created.remove(&e.dst);
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
                restore(&f, metadata_entry, &mut plan.xattr_scratch, c)?;
            }
            cv(unsafe { libc::futimens(f.as_raw_fd(), e.times.as_ptr()) })?;
        }
        for parent in created.iter().rev() {
            check(c)?;
            let f = open(&image, parent, libc::O_RDONLY | libc::O_DIRECTORY, false)?;
            let (uid, gid) = owner.unwrap_or((0, 0));
            metadata(&f, options.chmod.unwrap_or(0o755), uid, gid)?;
        }
        Ok(plan.used)
    }

    #[cfg(test)]
    mod xattr_tests {
        use super::*;
        use std::{cell::Cell, fs};

        fn set_attr(file: &File, name: &CStr, value: &[u8]) {
            // SAFETY: the FD, NUL-terminated name and value slice remain valid for the call.
            cv(unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            })
            .unwrap();
        }

        fn remove_attr(file: &File, name: &CStr) {
            // SAFETY: the FD and NUL-terminated name remain valid for the call.
            cv(unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) }).unwrap();
        }

        #[test]
        fn owned_values_survive_populated_empty_and_shorter_reads() {
            for follow in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let dir = root(temp.path()).unwrap();
                let populated = File::create(temp.path().join("populated")).unwrap();
                let empty = File::create(temp.path().join("empty")).unwrap();
                let shorter = File::create(temp.path().join("shorter")).unwrap();
                let binary = [0, 255, 1, 0, 128, 42];
                set_attr(&populated, c"user.long-name", &binary);
                set_attr(&shorter, c"user.a", &[255, 0]);
                set_attr(&shorter, c"user.b", &[]);
                let mut scratch = XattrScratch::default();
                let read = |file, path: &[u8], scratch: &mut XattrScratch| {
                    if follow {
                        attrs(file, b"", true, scratch, &|| false).unwrap()
                    } else {
                        attrs(&dir, path, true, scratch, &|| false).unwrap()
                    }
                };
                let first = read(&populated, b"populated", &mut scratch);
                assert!(read(&empty, b"empty", &mut scratch).is_empty());
                let mut last = read(&shorter, b"shorter", &mut scratch);
                last.sort_by(|a, b| a.0.cmp(&b.0));
                assert_eq!(first, vec![(c"user.long-name".to_owned(), binary.to_vec())]);
                assert_eq!(
                    last,
                    vec![
                        (c"user.a".to_owned(), vec![255, 0]),
                        (c"user.b".to_owned(), Vec::new()),
                    ]
                );
            }
        }

        #[test]
        fn scratch_is_lazy_bounded_and_reused() {
            let temp = tempfile::tempdir().unwrap();
            let dir = root(temp.path()).unwrap();
            let file = File::create(temp.path().join("file")).unwrap();
            let mut scratch = XattrScratch::default();
            assert!(attrs(&dir, b"missing/file", true, &mut scratch, &|| false).is_err());
            assert_eq!((scratch.names.capacity(), scratch.value.capacity()), (0, 0));
            assert!(
                attrs(&dir, b"file", true, &mut scratch, &|| false)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                (scratch.names.len(), scratch.names.capacity()),
                (65536, 65536)
            );
            assert_eq!((scratch.value.len(), scratch.value.capacity()), (0, 0));
            let names = scratch.names.as_ptr();
            set_attr(&file, c"user.value", &[7; 128]);
            let first = attrs(&dir, b"file", true, &mut scratch, &|| false).unwrap();
            let value = scratch.value.as_ptr();
            for bytes in [&[0, 255][..], &[][..], &[42][..]] {
                set_attr(&file, c"user.value", bytes);
                assert_eq!(
                    attrs(&dir, b"file", true, &mut scratch, &|| false).unwrap(),
                    vec![(c"user.value".to_owned(), bytes.to_vec())]
                );
                assert_eq!(
                    (scratch.names.as_ptr(), scratch.value.as_ptr()),
                    (names, value)
                );
                assert_eq!((scratch.names.len(), scratch.value.len()), (65536, 65536));
                assert_eq!(
                    (scratch.names.capacity(), scratch.value.capacity()),
                    (65536, 65536)
                );
            }
            remove_attr(&file, c"user.value");
            assert!(
                attrs(&dir, b"file", true, &mut scratch, &|| false)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                (scratch.names.as_ptr(), scratch.value.as_ptr()),
                (names, value)
            );
            assert_eq!(first, vec![(c"user.value".to_owned(), vec![7; 128])]);
        }

        #[test]
        fn false_callback_observes_mutation_and_removal_before_value_read() {
            for follow in [false, true] {
                for remove in [false, true] {
                    let temp = tempfile::tempdir().unwrap();
                    let dir = root(temp.path()).unwrap();
                    let file = File::create(temp.path().join("file")).unwrap();
                    set_attr(&file, c"user.value", b"old value");
                    let calls = Cell::new(0);
                    let result = attrs(
                        if follow { &file } else { &dir },
                        if follow { b"" } else { b"file" },
                        true,
                        &mut XattrScratch::default(),
                        &|| {
                            calls.set(calls.get() + 1);
                            if remove {
                                remove_attr(&file, c"user.value");
                            } else {
                                set_attr(&file, c"user.value", &[0, 255]);
                            }
                            false
                        },
                    );
                    assert_eq!(calls.get(), 1);
                    if remove {
                        assert!(
                            matches!(result, Err(Error::Io(e)) if e.raw_os_error() == Some(libc::ENODATA))
                        );
                    } else {
                        assert_eq!(
                            result.unwrap(),
                            vec![(c"user.value".to_owned(), vec![0, 255])]
                        );
                    }
                }
            }
        }

        #[test]
        fn true_callback_cancels_before_reading_mutated_or_removed_value() {
            for follow in [false, true] {
                for remove in [false, true] {
                    let temp = tempfile::tempdir().unwrap();
                    let dir = root(temp.path()).unwrap();
                    let file = File::create(temp.path().join("file")).unwrap();
                    set_attr(&file, c"user.value", b"old value");
                    let calls = Cell::new(0);
                    let result = attrs(
                        if follow { &file } else { &dir },
                        if follow { b"" } else { b"file" },
                        true,
                        &mut XattrScratch::default(),
                        &|| {
                            calls.set(calls.get() + 1);
                            if remove {
                                remove_attr(&file, c"user.value");
                            } else {
                                set_attr(&file, c"user.value", &[0, 255]);
                            }
                            true
                        },
                    );
                    assert_eq!(calls.get(), 1);
                    assert!(matches!(result, Err(Error::Cancelled)));
                }
            }
        }

        #[test]
        fn per_attr_callback_can_run_an_independent_copy() {
            let outer = tempfile::tempdir().unwrap();
            let file = File::create(outer.path().join("file")).unwrap();
            set_attr(&file, c"user.a", &[0, 255]);
            set_attr(&file, c"user.b", b"outer");
            let inner = tempfile::tempdir().unwrap();
            let image = tempfile::tempdir().unwrap();
            fs::create_dir(inner.path().join("dir")).unwrap();
            let child = File::create(inner.path().join("dir/file")).unwrap();
            set_attr(&child, c"user.inner", &[42; 128]);
            let inner_dir = File::open(inner.path().join("dir")).unwrap();
            set_attr(&inner_dir, c"user.directory", b"nested");
            let calls = Cell::new(0);
            let mut result = attrs(&file, b"", true, &mut XattrScratch::default(), &|| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    copy_stage(
                        inner.path(),
                        image.path(),
                        &["dir"],
                        "/out",
                        Limits {
                            max_bytes: 1024,
                            max_entries: 10,
                            max_metadata_bytes: 8192,
                        },
                        || false,
                    )
                    .unwrap();
                }
                false
            })
            .unwrap();
            result.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(calls.get(), 2);
            assert_eq!(
                result,
                vec![
                    (c"user.a".to_owned(), vec![0, 255]),
                    (c"user.b".to_owned(), b"outer".to_vec()),
                ]
            );
            let mut scratch = XattrScratch::default();
            for (path, name, value) in [
                ("out/file", c"user.inner", &[42; 128][..]),
                ("out", c"user.directory", &b"nested"[..]),
            ] {
                let copied = File::open(image.path().join(path)).unwrap();
                assert_eq!(
                    attrs(&copied, b"", false, &mut scratch, &|| false).unwrap(),
                    vec![(name.to_owned(), value.to_vec())]
                );
            }
        }
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
    fn never_cancel() -> bool {
        false
    }

    #[test]
    fn prepared_copy_admission_precedes_mutation_and_keeps_logical_charges() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("selected")).unwrap();
        fs::write(ctx.path().join("selected/file"), vec![0; 4097]).unwrap();
        fs::hard_link(
            ctx.path().join("selected/file"),
            ctx.path().join("selected/alias"),
        )
        .unwrap();
        fs::write(ctx.path().join("unselected"), vec![0; 100_000]).unwrap();
        fs::create_dir(image.path().join("existing")).unwrap();
        let before = fs::metadata(image.path().join("existing")).unwrap();
        let observed = Cell::new(None);
        let admission = |bytes, inodes| {
            observed.set(Some((bytes, inodes)));
            Err(Error::Invalid("fixture admission refused"))
        };
        let result = copy_filtered_checked(
            ctx.path(),
            image.path(),
            &["selected"],
            "/existing/new/",
            limits(),
            None,
            CopyOptions::default(),
            Some(&admission),
            never_cancel,
        );
        assert!(matches!(
            result,
            Err(Error::Invalid("fixture admission refused"))
        ));
        let (bytes, inodes) = observed.get().unwrap();
        assert!((7 * 4096..100_000).contains(&bytes));
        assert_eq!(inodes, 3);
        assert!(!image.path().join("existing/new").exists());
        let after = fs::metadata(image.path().join("existing")).unwrap();
        assert_eq!(
            (
                before.atime(),
                before.atime_nsec(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.atime(),
                after.atime_nsec(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        observed.set(None);
        let mut budget = limits();
        budget.max_bytes = 8193;
        let result = copy_filtered_checked(
            ctx.path(),
            image.path(),
            &["selected"],
            "/existing/new/",
            budget,
            None,
            CopyOptions::default(),
            Some(&admission),
            never_cancel,
        );
        assert!(matches!(result, Err(Error::Limit("bytes"))));
        assert_eq!(observed.get(), None);
        assert!(!image.path().join("existing/new").exists());
    }

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

    fn selected_hash(
        ctx: &Path,
        image: &Path,
        sources: &[&str],
        policy: Option<&Policy>,
    ) -> Vec<u8> {
        fingerprint_copy(
            ctx,
            image,
            sources,
            "/out/",
            limits(),
            policy,
            CopyOptions::default(),
            &|| false,
        )
        .unwrap()
        .0
    }

    fn fixed_times(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // Future atime avoids relatime changes, without suppressing hashed timestamps.
        let times = [
            libc::timespec {
                tv_sec: 2_000_000_000,
                tv_nsec: 123,
            },
            libc::timespec {
                tv_sec: 1_000_000_000,
                tv_nsec: 456,
            },
        ];
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            },
            0
        );
    }

    #[test]
    fn selected_fingerprint_stage_implicit_owner_matches_copy() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        let file = ctx.path().join("file");
        fs::write(&file, "file").unwrap();
        std::os::unix::fs::chown(&file, Some(123), Some(456)).unwrap();
        fixed_times(&file);
        let default = CopyOptions::default();
        let owned = CopyOptions {
            chown: Some("123:456"),
            ..default
        };
        let hash = |options, sources: &[&str]| {
            fingerprint_copy(
                ctx.path(),
                image.path(),
                sources,
                "/new/",
                limits(),
                None,
                options,
                &|| false,
            )
            .unwrap()
            .0
        };
        assert_ne!(hash(default, &["file"]), hash(owned, &["file"]));
        // Equal file modes still differ in the newly created parent's mode.
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(
            hash(default, &["file"]),
            hash(
                CopyOptions {
                    chmod: Some(0o600),
                    ..default
                },
                &["file"]
            )
        );
        for (options, expected) in [(default, (0, 0)), (owned, (123, 456))] {
            let target = tempfile::tempdir().unwrap();
            copy_stage_with_options(
                ctx.path(),
                target.path(),
                &["file"],
                "/new/",
                limits(),
                options,
                || false,
            )
            .unwrap();
            let parent = fs::metadata(target.path().join("new")).unwrap();
            let copied = fs::metadata(target.path().join("new/file")).unwrap();
            assert_eq!(
                (parent.uid(), parent.gid(), parent.mode() & 0o7777),
                (expected.0, expected.1, 0o755)
            );
            assert_eq!((copied.uid(), copied.gid()), (123, 456));
        }
        fs::create_dir(ctx.path().join("tree")).unwrap();
        std::os::unix::fs::chown(ctx.path().join("tree"), Some(123), Some(456)).unwrap();
        fixed_times(&ctx.path().join("tree"));
        // A directory selected first supplies metadata; selected after a file,
        // it retains the implicit directory's defaults instead.
        assert_eq!(
            hash(default, &["tree", "file"]),
            hash(owned, &["tree", "file"])
        );
        assert_eq!(
            hash(default, &["file", "tree"]),
            hash(owned, &["file", "tree"])
        );
        assert_ne!(
            hash(default, &["tree", "file"]),
            hash(default, &["file", "tree"])
        );
    }

    fn old_times(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [libc::timespec {
            tv_sec: 1,
            tv_nsec: 123,
        }; 2];
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            },
            0
        );
    }

    fn observed_times(path: &Path) -> (i64, i64, i64, i64, i64, i64) {
        let m = fs::symlink_metadata(path).unwrap();
        (
            m.atime(),
            m.atime_nsec(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }

    #[test]
    fn selected_fingerprint_missing_account_parent_matches_copy() {
        let ctx = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("file"), "file").unwrap();
        fixed_times(&ctx.path().join("file"));
        for regular_etc in [false, true] {
            let image = tempfile::tempdir().unwrap();
            if regular_etc {
                fs::write(image.path().join("etc"), "not a directory").unwrap();
                old_times(&image.path().join("etc"));
            }
            let before = regular_etc.then(|| observed_times(&image.path().join("etc")));
            for owner in ["builder", "0:builders", "builder:builders"] {
                let options = CopyOptions {
                    chown: Some(owner),
                    ..CopyOptions::default()
                };
                let hash = |options| {
                    fingerprint_copy(
                        ctx.path(),
                        image.path(),
                        &["file"],
                        "/out",
                        limits(),
                        None,
                        options,
                        &|| false,
                    )
                    .unwrap()
                };
                let selected = hash(options);
                assert_eq!(
                    selected,
                    hash(CopyOptions {
                        chown: Some("0:0"),
                        ..options
                    })
                );
                if unsafe { libc::geteuid() } == 0 {
                    let copied = copy_stage_with_options(
                        ctx.path(),
                        image.path(),
                        &["file"],
                        "/out",
                        limits(),
                        options,
                        || false,
                    )
                    .unwrap();
                    assert_eq!(selected.1, copied);
                    let output = fs::metadata(image.path().join("out")).unwrap();
                    assert_eq!((output.uid(), output.gid()), (0, 0));
                    assert_eq!(fs::read(image.path().join("out")).unwrap(), b"file");
                }
            }
            assert_eq!(
                before,
                regular_etc.then(|| observed_times(&image.path().join("etc")))
            );
        }
    }

    #[test]
    fn selected_fingerprint_named_owner_preserves_image_times() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("file"), "file").unwrap();
        fixed_times(&ctx.path().join("file"));
        fs::create_dir(image.path().join("etc")).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        fs::write(
            image.path().join("etc/passwd"),
            format!("builder:x:{uid}:{gid}::/:/bin/sh\n"),
        )
        .unwrap();
        fs::write(
            image.path().join("etc/group"),
            format!("builders:x:{gid}:\n"),
        )
        .unwrap();
        let paths = [
            image.path().join("etc/passwd"),
            image.path().join("etc/group"),
        ];
        for p in &paths {
            old_times(p);
        }
        let before = paths.each_ref().map(|p| observed_times(p));
        let options = CopyOptions {
            chown: Some("builder:builders"),
            chmod: Some(0o640),
        };
        let hash = || {
            fingerprint_copy(
                ctx.path(),
                image.path(),
                &["file"],
                "/new/file",
                limits(),
                None,
                options,
                &|| false,
            )
            .unwrap()
        };
        let first = hash();
        assert_eq!(first, hash());
        assert_eq!(before, paths.each_ref().map(|p| observed_times(p)));
        let summary = copy_stage_with_options(
            ctx.path(),
            image.path(),
            &["file"],
            "/new/file",
            limits(),
            options,
            || false,
        )
        .unwrap();
        assert_eq!(first.1, summary);
        assert_eq!(before, paths.each_ref().map(|p| observed_times(p)));
        let output = fs::metadata(image.path().join("new/file")).unwrap();
        assert_eq!(
            (output.uid(), output.gid(), output.mode() & 0o7777),
            (uid, gid, 0o640)
        );
        let baseline = tempfile::tempdir().unwrap();
        fs::create_dir(baseline.path().join("etc")).unwrap();
        for name in ["passwd", "group"] {
            fs::copy(
                image.path().join("etc").join(name),
                baseline.path().join("etc").join(name),
            )
            .unwrap();
        }
        copy_stage_with_options(
            ctx.path(),
            baseline.path(),
            &["file"],
            "/new/file",
            limits(),
            options,
            || false,
        )
        .unwrap();
        let direct = fs::metadata(baseline.path().join("new/file")).unwrap();
        assert_eq!(
            (
                output.mode(),
                output.uid(),
                output.gid(),
                output.atime(),
                output.atime_nsec(),
                output.mtime(),
                output.mtime_nsec()
            ),
            (
                direct.mode(),
                direct.uid(),
                direct.gid(),
                direct.atime(),
                direct.atime_nsec(),
                direct.mtime(),
                direct.mtime_nsec()
            )
        );
        assert_eq!(fs::read(image.path().join("new/file")).unwrap(), b"file");
    }

    #[test]
    fn selected_fingerprint_preserves_image_link_atime() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("file"), "file").unwrap();
        fs::create_dir(image.path().join("real")).unwrap();
        symlink("real", image.path().join("link")).unwrap();
        old_times(&image.path().join("link"));
        let before = observed_times(&image.path().join("link"));
        for destination in ["/link/file", "/link/"] {
            assert!(matches!(
                fingerprint_copy(
                    ctx.path(),
                    image.path(),
                    &["file"],
                    destination,
                    limits(),
                    None,
                    CopyOptions::default(),
                    &|| false,
                ),
                Err(Error::FingerprintUnavailable(_))
            ));
            let after = observed_times(&image.path().join("link"));
            assert_eq!(before, after);
        }
        fs::create_dir(image.path().join("etc")).unwrap();
        symlink("../real/passwd", image.path().join("etc/passwd")).unwrap();
        old_times(&image.path().join("etc/passwd"));
        let before = observed_times(&image.path().join("etc/passwd"));
        assert!(matches!(
            fingerprint_copy(
                ctx.path(),
                image.path(),
                &["file"],
                "/file",
                limits(),
                None,
                CopyOptions {
                    chown: Some("builder"),
                    ..CopyOptions::default()
                },
                &|| false,
            ),
            Err(Error::FingerprintUnavailable(_))
        ));
        let after = observed_times(&image.path().join("etc/passwd"));
        assert_eq!(before, after);
        // Ordinary COPY still resolves destination links.
        copy_stage_with_options(
            ctx.path(),
            image.path(),
            &["file"],
            "/link/file",
            limits(),
            CopyOptions {
                chown: Some(&format!("{}:{}", unsafe { libc::geteuid() }, unsafe {
                    libc::getegid()
                })),
                ..CopyOptions::default()
            },
            || false,
        )
        .unwrap();
        assert_eq!(fs::read(image.path().join("real/file")).unwrap(), b"file");
    }

    #[test]
    fn selected_fingerprint_unprivileged_account_and_link_reads() {
        const CHILD: &str = "WELD_FINGERPRINT_IMAGE_CHILD";
        if let Some(image) = std::env::var_os(CHILD) {
            let image = std::path::PathBuf::from(image);
            let ctx = tempfile::tempdir().unwrap();
            fs::write(ctx.path().join("file"), "file").unwrap();
            let options = CopyOptions {
                chown: Some("builder:builders"),
                ..CopyOptions::default()
            };
            let account = image.join("etc/passwd");
            let before = observed_times(&account);
            assert!(
                matches!(fingerprint_copy(ctx.path(), &image, &["file"], "/file", limits(), None, options, &|| false), Err(Error::Io(e)) if e.raw_os_error() == Some(libc::EPERM))
            );
            assert_eq!(before, observed_times(&account));
            assert!(!image.join("file").exists());
            // Execution may read accounts without O_NOATIME; fingerprint may not.
            copy_stage_with_options(
                ctx.path(),
                &image,
                &["file"],
                "/file",
                limits(),
                options,
                || false,
            )
            .unwrap();
            assert_eq!(fs::read(image.join("file")).unwrap(), b"file");
            // No link read or restoration, even without ownership privileges.
            let before = observed_times(&image.join("link"));
            assert!(matches!(
                fingerprint_copy(
                    ctx.path(),
                    &image,
                    &["file"],
                    "/link/file",
                    limits(),
                    None,
                    CopyOptions::default(),
                    &|| false
                ),
                Err(Error::FingerprintUnavailable(_))
            ));
            assert_eq!(before, observed_times(&image.join("link")));
            assert!(!image.join("real/file").exists());
            return;
        }
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::os::unix::process::CommandExt;
        let image = tempfile::tempdir().unwrap();
        fs::set_permissions(image.path(), fs::Permissions::from_mode(0o777)).unwrap();
        fs::create_dir(image.path().join("etc")).unwrap();
        fs::create_dir(image.path().join("real")).unwrap();
        fs::write(
            image.path().join("etc/passwd"),
            "builder:x:65534:65534::/:/bin/sh\n",
        )
        .unwrap();
        fs::write(image.path().join("etc/group"), "builders:x:65534:\n").unwrap();
        old_times(&image.path().join("etc/passwd"));
        old_times(&image.path().join("etc/group"));
        symlink("real", image.path().join("link")).unwrap();
        old_times(&image.path().join("link"));
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "context::tests::selected_fingerprint_unprivileged_account_and_link_reads",
                    "--nocapture"
                ])
                .env(CHILD, image.path())
                .gid(65534)
                .uid(65534)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn selected_fingerprint_manifest_ignores_unrelated_files() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("requirements.txt"), "dependency==1").unwrap();
        fs::write(ctx.path().join("app.py"), "old application").unwrap();
        let policy = Policy::default();
        let before = selected_hash(
            ctx.path(),
            image.path(),
            &["requirements.txt"],
            Some(&policy),
        );
        fs::write(ctx.path().join("app.py"), "new application").unwrap();
        fs::write(ctx.path().join("unrelated"), "new file").unwrap();
        assert_eq!(
            before,
            selected_hash(
                ctx.path(),
                image.path(),
                &["requirements.txt"],
                Some(&policy)
            )
        );
        fs::write(ctx.path().join("requirements.txt"), "dependency==2").unwrap();
        assert_ne!(
            before,
            selected_hash(
                ctx.path(),
                image.path(),
                &["requirements.txt"],
                Some(&policy)
            )
        );
    }

    #[test]
    fn selected_fingerprint_content_metadata_and_ownership() {
        use std::os::unix::ffi::OsStrExt;
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        let file = ctx.path().join("file");
        fs::write(&file, "aaa").unwrap();
        fixed_times(&file);
        let policy = Policy::default();
        let hash = || selected_hash(ctx.path(), image.path(), &["file"], Some(&policy));
        let first = hash();
        fs::write(&file, "bbb").unwrap();
        fixed_times(&file);
        let content = hash();
        assert_ne!(first, content);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let mode = hash();
        assert_ne!(content, mode);
        let path = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    c"user.fingerprint".as_ptr(),
                    b"one".as_ptr().cast(),
                    3,
                    0,
                )
            },
            0
        );
        let attr = hash();
        assert_ne!(mode, attr);
        assert_eq!(
            unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    c"user.fingerprint".as_ptr(),
                    b"two".as_ptr().cast(),
                    3,
                    0,
                )
            },
            0
        );
        assert_ne!(attr, hash());
        let before_time = hash();
        fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1234))
            .unwrap();
        assert_ne!(before_time, hash());
        if unsafe { libc::geteuid() } == 0 {
            let local = hash();
            let stage = selected_hash(ctx.path(), image.path(), &["file"], None);
            assert_eq!(unsafe { libc::chown(path.as_ptr(), 1234, 2345) }, 0);
            assert_eq!(local, hash());
            assert_ne!(
                stage,
                selected_hash(ctx.path(), image.path(), &["file"], None)
            );
        }
    }

    #[test]
    fn selected_fingerprint_options_and_implicit_parent_metadata() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("file"), "file").unwrap();
        fs::create_dir(ctx.path().join("tree")).unwrap();
        let policy = Policy::default();
        let opts = CopyOptions {
            chmod: Some(0o640),
            chown: Some("0:0"),
        };
        let hash = |options| {
            fingerprint_copy(
                ctx.path(),
                image.path(),
                &["file"],
                "/out/",
                limits(),
                Some(&policy),
                options,
                &|| false,
            )
            .unwrap()
            .0
        };
        let overridden = hash(opts);
        fs::set_permissions(ctx.path().join("file"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(overridden, hash(opts));
        assert_ne!(
            overridden,
            hash(CopyOptions {
                chmod: Some(0o600),
                ..opts
            })
        );
        assert_ne!(
            overridden,
            hash(CopyOptions {
                chown: Some("1:2"),
                ..opts
            })
        );
        // A preceding file creates /out; a later selected directory retains its
        // mode/owner/xattrs, but still applies source timestamps.
        fixed_times(&ctx.path().join("tree"));
        let before = selected_hash(ctx.path(), image.path(), &["file", "tree"], Some(&policy));
        fixed_times(&ctx.path().join("tree"));
        set_attr(&ctx.path().join("tree"), "user.ignored-root", b"changed");
        assert_eq!(
            before,
            selected_hash(ctx.path(), image.path(), &["file", "tree"], Some(&policy))
        );
    }

    #[test]
    fn selected_fingerprint_wildcard_noop_and_budgets() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        let policy = Policy::default();
        fs::write(ctx.path().join("app.py"), "app").unwrap();
        let before = selected_hash(ctx.path(), image.path(), &["*.txt"], Some(&policy));
        fs::write(ctx.path().join("another.py"), "other").unwrap();
        assert_eq!(
            before,
            selected_hash(ctx.path(), image.path(), &["*.txt"], Some(&policy))
        );
        let small = Limits {
            max_entries: 1,
            ..limits()
        };
        assert!(matches!(
            fingerprint_copy(
                ctx.path(),
                image.path(),
                &["*.txt"],
                "/out/",
                small,
                Some(&policy),
                CopyOptions::default(),
                &|| false
            ),
            Err(Error::Limit(_))
        ));
        fs::write(ctx.path().join("new.txt"), "selected").unwrap();
        assert_ne!(
            before,
            selected_hash(ctx.path(), image.path(), &["*.txt"], Some(&policy))
        );
        let (_, budget) = fingerprint_copy(
            ctx.path(),
            image.path(),
            &["*.txt"],
            "/out/",
            limits(),
            Some(&policy),
            CopyOptions::default(),
            &|| false,
        )
        .unwrap();
        let copied = copy_local(
            ctx.path(),
            image.path(),
            &["*.txt"],
            "/out/",
            limits(),
            || false,
        )
        .unwrap();
        assert_eq!(budget, copied);
        assert!(matches!(
            fingerprint_copy(
                ctx.path(),
                image.path(),
                &["*.txt"],
                "/out/",
                limits(),
                Some(&policy),
                CopyOptions::default(),
                &|| true
            ),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn selected_fingerprint_ignored_and_retained_root_metadata() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("tree")).unwrap();
        fs::create_dir(image.path().join("out")).unwrap();
        fs::write(ctx.path().join(".dockerignore"), "tree/ignored*\n").unwrap();
        fs::write(ctx.path().join("tree/keep"), "keep").unwrap();
        fs::write(ctx.path().join("tree/ignored"), "ignore").unwrap();
        let policy = load_policy(ctx.path(), None, &|| false).unwrap();
        let hash = || selected_hash(ctx.path(), image.path(), &["tree"], Some(&policy));
        fixed_times(&ctx.path().join("tree"));
        let before = hash();
        fs::write(ctx.path().join("tree/ignored"), "changed").unwrap();
        fs::write(ctx.path().join("tree/ignored-new"), "new").unwrap();
        fs::set_permissions(ctx.path().join("tree"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(before, hash()); // Creating an ignored child changed copied parent mtime.
        fixed_times(&ctx.path().join("tree"));
        assert_eq!(before, hash());
        // The source root xattrs matter when COPY creates it too.
        fs::remove_dir(image.path().join("out")).unwrap();
        let new_root = hash();
        set_attr(&ctx.path().join("tree"), "user.root", b"new");
        assert_ne!(new_root, hash());
        let small = Limits {
            max_entries: 3,
            ..limits()
        };
        assert!(matches!(
            fingerprint_copy(
                ctx.path(),
                image.path(),
                &["tree"],
                "/out/",
                small,
                Some(&policy),
                CopyOptions::default(),
                &|| false
            ),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn selected_fingerprint_raw_names_links_and_overwrite_order() {
        use std::os::unix::ffi::OsStrExt;
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir(ctx.path().join("tree")).unwrap();
        fs::create_dir(image.path().join("out")).unwrap();
        let raw = ctx
            .path()
            .join("tree")
            .join(std::ffi::OsStr::from_bytes(b"raw-\xff"));
        fs::write(&raw, "raw").unwrap();
        symlink(
            std::ffi::OsStr::from_bytes(b"target-\xfe"),
            ctx.path().join("tree/link"),
        )
        .unwrap();
        fixed_times(&raw);
        fixed_times(&ctx.path().join("tree/link"));
        let policy = Policy::default();
        let hash = || {
            fixed_times(&ctx.path().join("tree"));
            selected_hash(ctx.path(), image.path(), &["tree"], Some(&policy))
        };
        let first = hash();
        assert_eq!(first, hash());
        fs::write(&raw, "new").unwrap();
        fixed_times(&raw);
        assert_ne!(first, hash());
        let before_link = hash();
        fs::remove_file(ctx.path().join("tree/link")).unwrap();
        symlink(
            std::ffi::OsStr::from_bytes(b"target-\xff"),
            ctx.path().join("tree/link"),
        )
        .unwrap();
        fixed_times(&ctx.path().join("tree/link"));
        assert_ne!(before_link, hash());
        fs::create_dir(ctx.path().join("second")).unwrap();
        fs::write(ctx.path().join("second/link"), "overwrites").unwrap();
        assert_ne!(
            selected_hash(ctx.path(), image.path(), &["tree", "second"], Some(&policy)),
            selected_hash(ctx.path(), image.path(), &["second", "tree"], Some(&policy))
        );
    }

    #[test]
    fn wildcard_options_receipts_and_filtering() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir_all(ctx.path().join("tree/deep")).unwrap();
        for name in [
            "a.txt",
            "b.txt",
            "skip.txt",
            "arr[0]",
            "?.txt",
            "tree/c.txt",
            "tree/deep/d.txt",
        ] {
            fs::write(ctx.path().join(name), name).unwrap();
        }
        fs::write(ctx.path().join(".dockerignore"), "skip.txt\n").unwrap();
        let policy = load_policy(ctx.path(), None, &|| false).unwrap();
        validate_sources(ctx.path(), &["[ab].txt"], &policy, &|| false).unwrap();
        let options = CopyOptions {
            chmod: Some(0o640),
            chown: Some("0:0"),
        };
        let result = copy_local_with_options(
            ctx.path(),
            image.path(),
            &["*.txt"],
            "/out/",
            limits(),
            options,
            || false,
        )
        .unwrap();
        assert_eq!(result.targets.len(), 3);
        assert!(!image.path().join("out/skip.txt").exists());
        assert_eq!(
            fs::metadata(image.path().join("out/a.txt")).unwrap().mode() & 0o7777,
            0o640
        );
        let cached = validate_copy_budget(
            ctx.path(),
            &["*.txt"],
            &result.targets,
            limits(),
            Some(&policy),
            &|| false,
        )
        .unwrap();
        assert_eq!(
            (result.entries, result.bytes_written, result.metadata_bytes),
            (cached.entries, cached.bytes_written, cached.metadata_bytes)
        );
        assert!(
            validate_copy_budget(
                ctx.path(),
                &["*.txt"],
                &result.targets[..1],
                limits(),
                Some(&policy),
                &|| false
            )
            .is_err()
        );
        run(ctx.path(), image.path(), &[r"arr\[0\]"], "/escaped").unwrap();
        run(ctx.path(), image.path(), &["**/*.txt"], "/one-level/").unwrap();
        assert!(image.path().join("one-level/c.txt").exists());
        assert!(!image.path().join("one-level/d.txt").exists());
        run(ctx.path(), image.path(), &["?.txt"], "/unicode/").unwrap();
        assert!(image.path().join("unicode/?.txt").exists());
        let overwritten = run(ctx.path(), image.path(), &["[ab].txt"], "/file").unwrap();
        assert_eq!(fs::read(image.path().join("file")).unwrap(), b"b.txt");
        assert_eq!(overwritten.targets, vec![b"file".to_vec(); 2]);
        let cached = validate_copy_budget(
            ctx.path(),
            &["[ab].txt"],
            &overwritten.targets,
            limits(),
            Some(&policy),
            &|| false,
        )
        .unwrap();
        assert_eq!(
            (cached.entries, cached.bytes_written, cached.metadata_bytes),
            (
                overwritten.entries,
                overwritten.bytes_written,
                overwritten.metadata_bytes
            )
        );
        for pattern in ["missing*", "skip.*"] {
            let empty = run(ctx.path(), image.path(), &[pattern], "/none/").unwrap();
            assert!(empty.targets.is_empty());
            assert!(empty.entries > 0);
            assert_eq!(empty.bytes_written, 0);
            assert!(!image.path().join("none").exists());
            assert_eq!(
                empty,
                validate_copy_budget(
                    ctx.path(),
                    &[pattern],
                    &[],
                    limits(),
                    Some(&policy),
                    &|| false
                )
                .unwrap()
            );
            assert!(matches!(
                validate_copy_budget(
                    ctx.path(),
                    &[pattern],
                    &[],
                    Limits {
                        max_entries: 1,
                        ..limits()
                    },
                    Some(&policy),
                    &|| false
                ),
                Err(Error::Limit(_))
            ));
        }
        assert!(run(ctx.path(), image.path(), &["missing"], "/none/").is_err());
        assert!(run(ctx.path(), image.path(), &["skip.txt"], "/none/").is_err());
        assert!(run(ctx.path(), image.path(), &["[a-]"], "/bad/").is_err());
        let tiny = Limits {
            max_entries: 1,
            ..limits()
        };
        assert!(matches!(
            copy_local(
                ctx.path(),
                image.path(),
                &["*.txt"],
                "/limited/",
                tiny,
                || false
            ),
            Err(Error::Limit(_))
        ));
        assert!(!image.path().join("limited").exists());
    }

    #[test]
    fn wildcard_raw_names_keep_distinct_receipts() {
        use std::os::unix::ffi::OsStrExt;
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        for name in [b"\xff.txt", b"\xfe.txt"] {
            fs::write(ctx.path().join(std::ffi::OsStr::from_bytes(name)), name).unwrap();
        }
        let copied = run(ctx.path(), image.path(), &["?.txt"], "/out/").unwrap();
        assert_eq!(
            copied.targets,
            vec![b"out/\xfe.txt".to_vec(), b"out/\xff.txt".to_vec()]
        );
        for name in [b"\xff.txt", b"\xfe.txt"] {
            assert_eq!(
                fs::read(
                    image
                        .path()
                        .join("out")
                        .join(std::ffi::OsStr::from_bytes(name))
                )
                .unwrap(),
                name
            );
        }
        let policy = load_policy(ctx.path(), None, &|| false).unwrap();
        let cached = validate_copy_budget(
            ctx.path(),
            &["?.txt"],
            &copied.targets,
            limits(),
            Some(&policy),
            &|| false,
        )
        .unwrap();
        assert_eq!(cached.bytes_written, copied.bytes_written);
        assert!(
            validate_copy_budget(
                ctx.path(),
                &["?.txt"],
                &[b"../escape".to_vec(), b"safe".to_vec()],
                limits(),
                Some(&policy),
                &|| false
            )
            .is_err()
        );
    }

    #[test]
    fn copy_options_root_aliases_ignore_account_databases() {
        let ctx = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("file"), "payload").unwrap();
        std::os::unix::fs::chown(ctx.path().join("file"), Some(123), Some(456)).unwrap();
        for accounts in [false, true] {
            for stage in [false, true] {
                for (owner, expected) in [
                    ("root", (0, 0)),
                    ("root:", (0, 0)),
                    ("root:root", (0, 0)),
                    ("root:789", (0, 789)),
                    ("123:root", (123, 0)),
                ] {
                    let image = tempfile::tempdir().unwrap();
                    if accounts {
                        fs::create_dir(image.path().join("etc")).unwrap();
                        fs::write(
                            image.path().join("etc/passwd"),
                            "root:x:111:222::/:/bin/sh\n",
                        )
                        .unwrap();
                        fs::write(image.path().join("etc/group"), "root:x:333:\n").unwrap();
                    }
                    let copy = if stage {
                        copy_stage_with_options
                    } else {
                        copy_local_with_options
                    };
                    copy(
                        ctx.path(),
                        image.path(),
                        &["file"],
                        "/file",
                        limits(),
                        CopyOptions {
                            chown: Some(owner),
                            ..CopyOptions::default()
                        },
                        || false,
                    )
                    .unwrap();
                    let m = fs::metadata(image.path().join("file")).unwrap();
                    assert_eq!(
                        (m.uid(), m.gid()),
                        expected,
                        "{owner}, accounts={accounts}, stage={stage}"
                    );
                }
            }
        }
    }

    #[test]
    fn copy_options_names_stage_ownership_and_roots() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::create_dir_all(ctx.path().join("dir/nested")).unwrap();
        fs::write(ctx.path().join("dir/nested/file"), "payload").unwrap();
        fs::create_dir(image.path().join("etc")).unwrap();
        fs::write(
            image.path().join("etc/passwd"),
            "builder:x:123:456::/:/bin/sh\n",
        )
        .unwrap();
        fs::write(image.path().join("etc/group"), "team:x:789:\n").unwrap();
        fs::set_permissions(image.path(), fs::Permissions::from_mode(0o711)).unwrap();
        let options = CopyOptions {
            chmod: Some(0o750),
            chown: Some("builder"),
        };
        copy_local_with_options(
            ctx.path(),
            image.path(),
            &["dir"],
            "/",
            limits(),
            options,
            || false,
        )
        .unwrap();
        let m = fs::metadata(image.path().join("nested/file")).unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (123, 456, 0o750));
        assert_eq!(fs::metadata(image.path()).unwrap().mode() & 0o7777, 0o711);
        let options = CopyOptions {
            chmod: Some(0o4750),
            chown: Some("builder:team"),
        };
        copy_local_with_options(
            ctx.path(),
            image.path(),
            &["dir"],
            "/new",
            limits(),
            options,
            || false,
        )
        .unwrap();
        let m = fs::metadata(image.path().join("new")).unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (123, 789, 0o4750));
        let stage = tempfile::tempdir().unwrap();
        copy_stage(
            image.path(),
            stage.path(),
            &["new/nested/file"],
            "/file",
            limits(),
            || false,
        )
        .unwrap();
        let m = fs::metadata(stage.path().join("file")).unwrap();
        assert_eq!((m.uid(), m.gid()), (123, 789));
        copy_local_with_options(
            ctx.path(),
            stage.path(),
            &["dir"],
            "/default",
            limits(),
            CopyOptions {
                chown: Some("builder"),
                ..CopyOptions::default()
            },
            || false,
        )
        .unwrap();
        let m = fs::metadata(stage.path().join("default")).unwrap();
        assert_eq!((m.uid(), m.gid()), (0, 0));
        assert_eq!(parse_chmod("0755").unwrap(), 0o755);
        assert!(parse_chmod("u+x").is_err());
        assert!(parse_chmod("888").is_err());
        assert!(validate_chown("4294967295").is_err());
    }

    #[test]
    fn options_preserve_canary_hardlinks_and_confine_account_lookup() {
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("payload"), "new").unwrap();
        fs::hard_link(ctx.path().join("payload"), ctx.path().join("payload2")).unwrap();
        fs::write(outside.path().join("canary"), "outside").unwrap();
        fs::hard_link(outside.path().join("canary"), image.path().join("payload")).unwrap();
        let options = CopyOptions {
            chmod: Some(0o600),
            chown: Some("12:34"),
        };
        copy_local_with_options(
            ctx.path(),
            image.path(),
            &["payload*"],
            "/",
            limits(),
            options,
            || false,
        )
        .unwrap();
        assert_eq!(fs::read(outside.path().join("canary")).unwrap(), b"outside");
        assert_ne!(
            fs::metadata(image.path().join("payload")).unwrap().ino(),
            fs::metadata(image.path().join("payload2")).unwrap().ino()
        );
        symlink(outside.path(), ctx.path().join("escape")).unwrap();
        assert!(run(ctx.path(), image.path(), &["escape/*"], "/escape/").is_err());
        assert!(!image.path().join("escape").exists());
        fs::create_dir(image.path().join("etc")).unwrap();
        fs::write(outside.path().join("passwd"), "evil:x:12:34::/:/bin/sh\n").unwrap();
        symlink(
            outside.path().join("passwd"),
            image.path().join("etc/passwd"),
        )
        .unwrap();
        assert!(
            copy_local_with_options(
                ctx.path(),
                image.path(),
                &["payload"],
                "/bad",
                limits(),
                CopyOptions {
                    chown: Some("evil"),
                    ..CopyOptions::default()
                },
                || false
            )
            .is_err()
        );
        fs::remove_file(image.path().join("etc/passwd")).unwrap();
        fs::write(image.path().join("etc/passwd"), vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(matches!(
            copy_local_with_options(
                ctx.path(),
                image.path(),
                &["payload"],
                "/bad",
                limits(),
                CopyOptions {
                    chown: Some("evil"),
                    ..CopyOptions::default()
                },
                || false
            ),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn wildcard_nested_mount_is_refused() {
        let image = tempfile::tempdir().unwrap();
        fs::write(image.path().join("canary"), b"unchanged").unwrap();
        assert!(
            copy_stage(
                Path::new("/"),
                image.path(),
                &["proc/[v]ersion"],
                "/out/",
                limits(),
                || false
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(image.path()).unwrap().count(), 1);
        assert_eq!(fs::read(image.path().join("canary")).unwrap(), b"unchanged");
    }

    #[test]
    fn copy_options_unprivileged_subprocess() {
        const CHILD: &str = "WELD_COPY_UNPRIVILEGED_CHILD";
        if std::env::var_os(CHILD).is_none() {
            use std::os::unix::process::CommandExt;
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "context::tests::copy_options_unprivileged_subprocess",
                "--nocapture",
            ])
            .env(CHILD, "1");
            let readable = tempfile::tempdir().unwrap();
            fs::set_permissions(readable.path(), fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(readable.path().join("file"), "readable without CAP_FOWNER").unwrap();
            fs::set_permissions(
                readable.path().join("file"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            cmd.env("WELD_COPY_READABLE_SOURCE", readable.path());
            if unsafe { libc::geteuid() } == 0 {
                cmd.gid(65534).uid(65534);
            }
            assert!(cmd.status().unwrap().success());
            return;
        }
        assert_ne!(unsafe { libc::geteuid() }, 0);
        let ctx = tempfile::tempdir().unwrap();
        let image = tempfile::tempdir().unwrap();
        fs::write(ctx.path().join("file"), "payload").unwrap();
        fs::create_dir(ctx.path().join("dir")).unwrap();
        symlink("../file", ctx.path().join("dir/link")).unwrap();
        let owner = format!("{}:{}", unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        });
        let options = CopyOptions {
            chmod: Some(0o750),
            chown: Some(&owner),
        };
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let caps = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:\t"))
            .unwrap();
        assert_eq!(u64::from_str_radix(caps, 16).unwrap(), 0);
        fs::set_permissions(ctx.path().join("file"), fs::Permissions::from_mode(0o644)).unwrap();
        set_attr(&ctx.path().join("file"), "user.test", b"value");
        fs::create_dir_all(ctx.path().join("attrs/nested")).unwrap();
        set_attr(&ctx.path().join("attrs/nested"), "user.test", b"value");
        for stage in [false, true] {
            let copy = if stage {
                copy_stage_with_options
            } else {
                copy_local_with_options
            };
            for existing in [false, true] {
                let target = tempfile::tempdir().unwrap();
                if existing {
                    fs::write(target.path().join("file"), "old").unwrap();
                    fs::set_permissions(
                        target.path().join("file"),
                        fs::Permissions::from_mode(0o444),
                    )
                    .unwrap();
                    fs::create_dir(target.path().join("nested")).unwrap();
                    set_attr(&target.path().join("nested"), "user.old", b"stale");
                    fs::set_permissions(
                        target.path().join("nested"),
                        fs::Permissions::from_mode(0o555),
                    )
                    .unwrap();
                }
                for (source, dest, mode) in [("file", "/file", 0o444), ("attrs", "/", 0o555)] {
                    copy(
                        ctx.path(),
                        target.path(),
                        &[source],
                        dest,
                        limits(),
                        CopyOptions {
                            chmod: Some(mode),
                            chown: Some(&owner),
                        },
                        || false,
                    )
                    .unwrap();
                }
                for (path, mode) in [("file", 0o444), ("nested", 0o555)] {
                    let path = target.path().join(path);
                    assert_eq!(get_attr(&path, "user.test"), Some(b"value".to_vec()));
                    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, mode);
                    assert_eq!(get_attr(&path, "user.old"), None);
                }
            }
        }
        let readable =
            std::path::PathBuf::from(std::env::var_os("WELD_COPY_READABLE_SOURCE").unwrap());
        let policy = Policy::default();
        let fingerprint = || {
            fingerprint_copy(
                &readable,
                image.path(),
                &["file"],
                "/readable",
                limits(),
                Some(&policy),
                options,
                &|| false,
            )
            .unwrap()
            .0
        };
        let before = fingerprint();
        assert_eq!(before, fingerprint());
        copy_local_with_options(
            &readable,
            image.path(),
            &["file"],
            "/readable",
            limits(),
            options,
            || false,
        )
        .unwrap();

        copy_local_with_options(
            ctx.path(),
            image.path(),
            &["file"],
            "/new/parents/file",
            limits(),
            options,
            || false,
        )
        .unwrap();
        copy_local_with_options(
            ctx.path(),
            image.path(),
            &["dir"],
            "/links",
            limits(),
            options,
            || false,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(image.path().join("new/parents/file"))
                .unwrap()
                .mode()
                & 0o7777,
            0o750
        );
        let denied = copy_local_with_options(
            ctx.path(),
            image.path(),
            &["file"],
            "/denied",
            limits(),
            CopyOptions {
                chown: Some("123:456"),
                ..CopyOptions::default()
            },
            || false,
        )
        .unwrap_err();
        assert!(denied.to_string().contains("Pod must permit"), "{denied}");
        assert_eq!(
            fs::metadata(image.path().join("denied")).unwrap().uid(),
            unsafe { libc::geteuid() }
        );
        assert!(
            copy_local(
                ctx.path(),
                image.path(),
                &["file"],
                "/root-owner",
                limits(),
                || false
            )
            .is_err()
        );
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
        copy_local_with_options(
            ctx.path(),
            image.path(),
            &["dir/file"],
            "/fingerprinting",
            limits(),
            CopyOptions {
                chmod: Some(0o444),
                chown: Some("root"),
            },
            || false,
        )
        .unwrap();
        let m = fs::metadata(image.path().join("fingerprinting")).unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (0, 0, 0o444));
        assert_eq!(
            get_attr(&image.path().join("fingerprinting"), "security.capability"),
            Some(cap.to_vec())
        );
        assert_eq!(
            get_attr(&image.path().join("fingerprinting"), "user.file"),
            Some(b"payload".to_vec())
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
            0o755
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
