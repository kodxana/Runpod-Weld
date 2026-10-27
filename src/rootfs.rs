//! Linux OCI changeset application. Failure (including cancellation) leaves a
//! partial root: the caller MUST discard it. There is no rollback/atomicity claim.
//! The caller owns a stable disposable tree, with no concurrent writers, mounts,
//! or hardlinks to files outside it. Keep engine state and verified spools outside
//! this tree. This is a trusted image-build filesystem, not a process sandbox.
//! Archive paths are resolved through pinned directory descriptors; absolute
//! symlinks and `..` in their targets have image-root semantics.
//! Requires Linux statx mount IDs; refuses nested mounts. Resolution is limited
//! to 40 symlinks and 256 directories. Metadata and pinned descriptors scale with
//! the verified entry count; payloads use a fixed 64 KiB buffer. ctime, sub-ns
//! timestamps, symlink xattrs/non-0777 modes and special hardlink targets are
//! explicitly unsupported. Kernel ownership/xattr failures propagate.
//! Before mutation, descriptor budgeting may raise the process-wide soft NOFILE
//! limit within its existing hard limit, leaving it raised. Callers must serialize
//! limit changes and avoid concurrent descriptor growth; this is no FD reservation.
use crate::layer::VerifiedLayer;
use std::{fmt, io, path::Path};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid(&'static str),
    Unsupported(&'static str),
    Cancelled,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "rootfs I/O: {e}; discard partial root"),
            Self::Invalid(s) => write!(f, "invalid rootfs operation: {s}; discard partial root"),
            Self::Unsupported(s) => {
                write!(f, "unsupported rootfs operation: {s}; discard partial root")
            }
            Self::Cancelled => f.write_str("rootfs application cancelled; discard partial root"),
        }
    }
}
impl std::error::Error for Error {}
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub entries: usize,
    pub whiteouts: usize,
    pub bytes_written: u64,
}

/// Apply verified offsets without reparsing tar. Cancellation is cooperative
/// between syscalls and 64 KiB content chunks, not a timeout for blocking I/O.
pub fn apply_layer(
    root: &Path,
    layer: &mut VerifiedLayer,
    cancelled: impl Fn() -> bool,
) -> Result<Summary, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(root, layer, None, &cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, layer, cancelled);
        Err(Error::Unsupported("layer application requires Linux"))
    }
}

/// Build-private evidence from verified replay or an engine export of an owned root.
/// Symlink targets come from creation or the export inventory, without rereading links.
pub(crate) struct ReplayReceipt {
    #[cfg(target_os = "linux")]
    root: std::fs::File,
    #[cfg(target_os = "linux")]
    targets: std::collections::BTreeMap<(u64, u64), std::path::PathBuf>,
    diff_ids: Vec<crate::oci::Sha256Digest>,
    remaining: u64,
    charged: u64,
    valid: bool,
}

impl ReplayReceipt {
    /// Export-private evidence for a stable root whose complete layered snapshot
    /// was just written. Targets come from that snapshot, never a second readlink.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_export<'a>(
        root: &Path,
        diff_ids: &[crate::oci::Sha256Digest],
        targets: impl IntoIterator<Item = ((u64, u64), &'a Path)>,
        metadata_limit: u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Self, Error> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)?;
        let mut receipt = Self {
            root: file,
            targets: Default::default(),
            diff_ids: Vec::new(),
            remaining: metadata_limit,
            charged: 0,
            valid: true,
        };
        for diff in diff_ids {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            receipt.charge(128)?;
            receipt.diff_ids.push(diff.clone());
        }
        for (identity, target) in targets {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            receipt.charge(target.as_os_str().len() as u64 + 128)?;
            if receipt
                .targets
                .insert(identity, target.to_owned())
                .is_some()
            {
                return Err(Error::Invalid("duplicate exported symlink identity"));
            }
        }
        Ok(receipt)
    }

    pub(crate) fn new(root: &Path, metadata_limit: u64) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(root)?;
            if std::fs::read_dir(root)?.next().transpose()?.is_some() {
                return Err(Error::Invalid("recorded replay requires an empty root"));
            }
            Ok(Self {
                root: file,
                targets: Default::default(),
                diff_ids: Vec::new(),
                remaining: metadata_limit,
                charged: 0,
                valid: true,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, metadata_limit);
            Err(Error::Unsupported("recorded replay requires Linux"))
        }
    }

    fn charge(&mut self, bytes: u64) -> Result<(), Error> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(Error::Invalid("replay receipt metadata budget exceeded"))?;
        self.charged += bytes;
        Ok(())
    }

    /// Check optional recording before replay mutates the root. Historical symlink
    /// targets consume receipt space even when later layers replace those links.
    pub(crate) fn can_record(
        &self,
        root: &Path,
        layer: &VerifiedLayer,
        cancelled: impl Fn() -> bool,
    ) -> Result<bool, Error> {
        self.validate(root, &self.diff_ids)?;
        if cancelled() {
            return Err(Error::Cancelled);
        }
        let Some(mut remaining) = self.remaining.checked_sub(128) else {
            return Ok(false);
        };
        for entry in layer.entries() {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            if entry.kind == crate::layer::EntryKind::Symlink {
                let target = entry
                    .link_target
                    .as_ref()
                    .ok_or(Error::Invalid("verified symlink has no target"))?;
                let Some(left) = remaining
                    .checked_sub(128)
                    .and_then(|left| left.checked_sub(target.len() as u64))
                else {
                    return Ok(false);
                };
                remaining = left;
            }
        }
        Ok(true)
    }

    pub(crate) fn apply(
        &mut self,
        root: &Path,
        layer: &mut VerifiedLayer,
        cancelled: impl Fn() -> bool,
    ) -> Result<Summary, Error> {
        self.validate(root, &self.diff_ids)?;
        self.valid = false;
        self.charge(128)?;
        #[cfg(target_os = "linux")]
        {
            let summary = linux::apply(root, layer, Some(self), &cancelled)?;
            self.diff_ids.push(layer.diff_id().clone());
            self.valid = true;
            Ok(summary)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (layer, cancelled);
            Err(Error::Unsupported("recorded replay requires Linux"))
        }
    }

    pub(crate) fn validate(
        &self,
        root: &Path,
        diff_ids: &[crate::oci::Sha256Digest],
    ) -> Result<(), Error> {
        if !self.valid || self.diff_ids != diff_ids {
            return Err(Error::Invalid("incomplete or mismatched replay receipt"));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let actual = std::fs::symlink_metadata(root)?;
            let pinned = self.root.metadata()?;
            if !actual.is_dir() || (actual.dev(), actual.ino()) != (pinned.dev(), pinned.ino()) {
                return Err(Error::Invalid("replay receipt root identity changed"));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = root;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn target(&self, identity: (u64, u64)) -> Option<&Path> {
        self.targets.get(&identity).map(std::path::PathBuf::as_path)
    }

    pub(crate) fn metadata_bytes(&self) -> u64 {
        self.charged
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::layer::{Entry, EntryKind, Timestamp};
    use std::{
        collections::VecDeque,
        ffi::{CStr, CString},
        fs::File,
        io::{Read, Seek, SeekFrom, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
            unix::ffi::OsStrExt,
        },
        path::Component,
    };
    fn check(c: &impl Fn() -> bool) -> Result<(), Error> {
        if c() { Err(Error::Cancelled) } else { Ok(()) }
    }
    fn descriptor_budget(entries: &[Entry], c: &impl Fn() -> bool) -> Result<(), Error> {
        // shortcut: pins still scale with entries; images exceeding the hard limit
        // need a different identity-preserving replay design, not dropped pins.
        // 256 resolution FDs OR 257 recursive deletion FDs + readdir, with
        // headroom for source/destination, target pins and temporary duplicates.
        let mut whiteout_pins: libc::rlim_t = 0;
        let mut replay_pins: libc::rlim_t = 0;
        let overflow = || Error::Unsupported("rootfs descriptor budget overflow");
        for e in entries {
            check(c)?;
            if split(&e.path).1.starts_with(b".wh.") {
                whiteout_pins = whiteout_pins.checked_add(1).ok_or_else(overflow)?;
            } else {
                let pins = match e.kind {
                    EntryKind::Directory => 1,
                    EntryKind::Symlink | EntryKind::Hardlink => 2,
                    EntryKind::File => 0,
                };
                replay_pins = replay_pins.checked_add(pins).ok_or_else(overflow)?;
            }
        }
        // Whiteout pins are all dropped before replay pins are retained.
        let mut required = whiteout_pins
            .max(replay_pins)
            .checked_add(272)
            .ok_or_else(overflow)?;
        // Includes root, host and the verified spool, plus the enumeration FD.
        // Counting all open FDs also safely overestimates those above soft NOFILE.
        for fd in std::fs::read_dir("/proc/self/fd")? {
            check(c)?;
            fd?;
            required = required.checked_add(1).ok_or_else(overflow)?;
        }
        let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        cv(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) })?;
        let mut limits = unsafe { limits.assume_init() };
        if required > limits.rlim_max {
            return Err(io::Error::other(format!(
                "descriptor budget requires {required} FDs, exceeding RLIMIT_NOFILE hard limit {} (soft {}); root unchanged; this process cannot raise the hard limit automatically. Use a runtime with a higher hard NOFILE limit or a layer requiring fewer pinned descriptors; GPU/CPU/RAM size does not determine this limit",
                limits.rlim_max, limits.rlim_cur
            )).into());
        }
        check(c)?;
        if required > limits.rlim_cur {
            limits.rlim_cur = required;
            // Keep the hard limit exactly as observed; never request privileges.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0 {
                return Err(io::Error::other(format!(
                    "cannot raise RLIMIT_NOFILE soft limit to descriptor budget {required} (hard {}); root unchanged: {}",
                    limits.rlim_max, io::Error::last_os_error()
                )).into());
            }
        }
        Ok(())
    }
    fn cs(b: &[u8]) -> Result<CString, Error> {
        CString::new(b).map_err(|_| Error::Invalid("NUL in path or xattr"))
    }
    fn cv(n: libc::c_int) -> Result<libc::c_int, Error> {
        if n < 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(n)
        }
    }
    fn open(d: RawFd, n: &[u8], flags: i32) -> Result<OwnedFd, Error> {
        let n = cs(n)?;
        let fd = cv(unsafe {
            libc::openat(
                d,
                n.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        })?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn stat(d: RawFd, n: &[u8]) -> Result<libc::stat, Error> {
        let n = cs(n)?;
        let mut s = std::mem::MaybeUninit::uninit();
        cv(unsafe { libc::fstatat(d, n.as_ptr(), s.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
        Ok(unsafe { s.assume_init() })
    }
    fn missing(e: &Error) -> bool {
        matches!(e, Error::Io(e) if e.raw_os_error() == Some(libc::ENOENT))
    }
    fn fstat(fd: RawFd) -> Result<libc::stat, Error> {
        let mut s = std::mem::MaybeUninit::uninit();
        cv(unsafe { libc::fstat(fd, s.as_mut_ptr()) })?;
        Ok(unsafe { s.assume_init() })
    }
    fn isdir(s: &libc::stat) -> bool {
        s.st_mode & libc::S_IFMT == libc::S_IFDIR
    }
    fn mount_id(fd: RawFd) -> Result<u64, Error> {
        let mut s = std::mem::MaybeUninit::<libc::statx>::uninit();
        cv(unsafe {
            libc::statx(
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                libc::STATX_MNT_ID,
                s.as_mut_ptr(),
            )
        })?;
        let s = unsafe { s.assume_init() };
        if s.stx_mask & libc::STATX_MNT_ID == 0 {
            return Err(Error::Unsupported("kernel lacks statx mount IDs"));
        }
        Ok(s.stx_mnt_id)
    }
    fn same_mount(a: RawFd, b: RawFd) -> Result<(), Error> {
        if mount_id(a)? != mount_id(b)? {
            return Err(Error::Invalid("nested mount refused"));
        }
        Ok(())
    }
    fn readlink(d: RawFd, n: &[u8]) -> Result<Vec<u8>, Error> {
        let n = cs(n)?;
        let mut b = vec![0; 65536];
        let len = unsafe { libc::readlinkat(d, n.as_ptr(), b.as_mut_ptr().cast(), b.len()) };
        if len < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if len as usize == b.len() {
            return Err(Error::Invalid("symlink too long"));
        }
        b.truncate(len as usize);
        Ok(b)
    }
    fn parts(p: &[u8]) -> VecDeque<Vec<u8>> {
        p.split(|b| *b == b'/').map(Vec::from).collect()
    }
    // Only parent components are followed. Leaf operations are always NOFOLLOW.
    fn dir(
        root: &OwnedFd,
        path: &[u8],
        create: bool,
        c: &impl Fn() -> bool,
    ) -> Result<OwnedFd, Error> {
        let mut stack = vec![root.try_clone()?];
        let mut queue = parts(path);
        let mut links = 0;
        while let Some(part) = queue.pop_front() {
            check(c)?;
            if part.is_empty() || part == b"." {
                continue;
            }
            if part == b".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let fd = stack.last().unwrap().as_raw_fd();
            let s = match stat(fd, &part) {
                Ok(s) => s,
                Err(e) if missing(&e) && create => {
                    cv(unsafe { libc::mkdirat(fd, cs(&part)?.as_ptr(), 0o755) })?;
                    stat(fd, &part)?
                }
                Err(e) => return Err(e),
            };
            if s.st_mode & libc::S_IFMT == libc::S_IFLNK {
                links += 1;
                if links > 40 {
                    return Err(Error::Invalid("symlink depth exceeded"));
                }
                let target = readlink(fd, &part)?;
                if target.starts_with(b"/") {
                    stack.truncate(1);
                }
                let mut next = parts(&target);
                next.append(&mut queue);
                queue = next;
            } else {
                if stack.len() >= 256 {
                    return Err(Error::Invalid("directory depth exceeded"));
                }
                let child = open(fd, &part, libc::O_RDONLY | libc::O_DIRECTORY)?;
                same_mount(root.as_raw_fd(), child.as_raw_fd())?;
                stack.push(child);
            }
        }
        Ok(stack.pop().unwrap())
    }
    fn split(p: &[u8]) -> (&[u8], &[u8]) {
        match p.iter().rposition(|b| *b == b'/') {
            Some(i) => (&p[..i], &p[i + 1..]),
            None => (b"", p),
        }
    }
    fn names(fd: RawFd, c: &impl Fn() -> bool) -> Result<Vec<Vec<u8>>, Error> {
        let copy = open(fd, b".", libc::O_RDONLY | libc::O_DIRECTORY)?;
        use std::os::fd::IntoRawFd;
        let raw = copy.into_raw_fd();
        let dp = unsafe { libc::fdopendir(raw) };
        if dp.is_null() {
            unsafe {
                libc::close(raw);
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
        let dp = Dir(dp);
        let mut result = Vec::new();
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
            if n != b"." && n != b".." {
                result.push(n.to_vec());
            }
        }
        Ok(result)
    }
    fn remove(d: RawFd, n: &[u8], depth: usize, c: &impl Fn() -> bool) -> Result<(), Error> {
        check(c)?;
        if depth > 256 {
            return Err(Error::Invalid("deletion depth exceeded"));
        }
        let s = match stat(d, n) {
            Ok(s) => s,
            Err(e) if missing(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        let flag = if isdir(&s) {
            let child = open(d, n, libc::O_RDONLY | libc::O_DIRECTORY)?;
            same_mount(d, child.as_raw_fd())?;
            for name in names(child.as_raw_fd(), c)? {
                remove(child.as_raw_fd(), &name, depth + 1, c)?;
            }
            libc::AT_REMOVEDIR
        } else {
            0
        };
        check(c)?;
        cv(unsafe { libc::unlinkat(d, cs(n)?.as_ptr(), flag) })?;
        Ok(())
    }
    fn time(t: &Timestamp) -> Result<libc::timespec, Error> {
        if t.fraction.len() > 9 || !t.fraction.iter().all(u8::is_ascii_digit) {
            return Err(Error::Unsupported("timestamp exceeds nanosecond precision"));
        }
        let mut ns = 0i128;
        for b in &t.fraction {
            ns = ns * 10 + i128::from(b - b'0');
        }
        for _ in t.fraction.len()..9 {
            ns *= 10;
        }
        let total = (i128::from(t.seconds) * 1_000_000_000 + ns) * if t.negative { -1 } else { 1 };
        Ok(libc::timespec {
            tv_sec: total
                .div_euclid(1_000_000_000)
                .try_into()
                .map_err(|_| Error::Unsupported("timestamp out of range"))?,
            tv_nsec: total.rem_euclid(1_000_000_000) as _,
        })
    }
    fn validate(e: &Entry) -> Result<(), Error> {
        if e.path.starts_with(b"/")
            || e.path
                .split(|b| *b == b'/')
                .any(|p| p == b".." || p == b".")
        {
            return Err(Error::Invalid("noncanonical entry path"));
        }
        cs(&e.path)?;
        let (parent, _) = split(&e.path);
        if parent.split(|b| *b == b'/').any(|p| p.starts_with(b".wh.")) {
            return Err(Error::Invalid("whiteout marker used as parent"));
        }
        if e.uid >= u32::MAX as u64 || e.gid >= u32::MAX as u64 {
            return Err(Error::Unsupported("uid/gid out of range"));
        }
        if e.mode & !0o7777 != 0 {
            return Err(Error::Unsupported("mode bits"));
        }
        time(&e.mtime)?;
        if let Some(t) = &e.atime {
            time(t)?;
        }
        if e.ctime.is_some() {
            return Err(Error::Unsupported("ctime cannot be restored on Linux"));
        }
        if e.pax_records.keys().any(|k| k != b"comment") {
            return Err(Error::Unsupported("semantic PAX record"));
        }
        for n in e.xattrs.keys() {
            cs(n)?;
        }
        if e.kind == EntryKind::Symlink && (!e.xattrs.is_empty() || e.mode != 0o777) {
            return Err(Error::Unsupported(
                "symlink xattrs or non-0777 symlink mode",
            ));
        }
        if matches!(e.kind, EntryKind::Symlink | EntryKind::Hardlink) {
            cs(e.link_target
                .as_deref()
                .ok_or(Error::Invalid("missing link target"))?)?;
        }
        if e.path.is_empty() && e.kind != EntryKind::Directory {
            return Err(Error::Invalid("non-directory root entry"));
        }
        if split(&e.path).1.starts_with(b".wh.") && (e.kind != EntryKind::File || e.size != 0) {
            return Err(Error::Invalid("whiteout must be empty regular file"));
        }
        let leaf = split(&e.path).1;
        if leaf.starts_with(b".wh.")
            && leaf != b".wh..wh..opq"
            && matches!(&leaf[4..], b"" | b"." | b"..")
        {
            return Err(Error::Invalid("invalid whiteout target"));
        }
        Ok(())
    }
    fn metadata(fd: RawFd, e: &Entry, c: &impl Fn() -> bool) -> Result<(), Error> {
        check(c)?;
        cv(unsafe { libc::fchown(fd, e.uid as _, e.gid as _) })?;
        cv(unsafe { libc::fchmod(fd, e.mode as _) })?;
        let len = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if len < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut old = vec![0u8; len as usize];
        let len = unsafe { libc::flistxattr(fd, old.as_mut_ptr().cast(), old.len()) };
        if len < 0 {
            return Err(io::Error::last_os_error().into());
        }
        for n in old[..len as usize]
            .split(|b| *b == 0)
            .filter(|n| !n.is_empty())
        {
            check(c)?;
            // Hardlink headers update a shared inode; omitted xattrs are not deletions.
            if e.kind != EntryKind::Hardlink && !e.xattrs.contains_key(n) {
                cv(unsafe { libc::fremovexattr(fd, cs(n)?.as_ptr()) })?;
            }
        }
        // chown/content writes can clear capabilities: restore xattrs last.
        for (n, v) in &e.xattrs {
            check(c)?;
            cv(unsafe { libc::fsetxattr(fd, cs(n)?.as_ptr(), v.as_ptr().cast(), v.len(), 0) })?;
        }
        let times = [
            match &e.atime {
                Some(t) => time(t)?,
                None => time(&e.mtime)?,
            },
            time(&e.mtime)?,
        ];
        cv(unsafe { libc::futimens(fd, times.as_ptr()) })?;
        let mut s = std::mem::MaybeUninit::uninit();
        cv(unsafe { libc::fstat(fd, s.as_mut_ptr()) })?;
        let s = unsafe { s.assume_init() };
        if s.st_uid as u64 != e.uid || s.st_gid as u64 != e.gid || s.st_mode & 0o7777 != e.mode {
            return Err(Error::Unsupported(
                "filesystem did not preserve ownership/mode (possibly conflicting ACL)",
            ));
        }
        confirm_times(&s, &times)
    }
    fn confirm_times(s: &libc::stat, t: &[libc::timespec; 2]) -> Result<(), Error> {
        if s.st_atime != t[0].tv_sec
            || s.st_atime_nsec != t[0].tv_nsec
            || s.st_mtime != t[1].tv_sec
            || s.st_mtime_nsec != t[1].tv_nsec
        {
            return Err(Error::Unsupported(
                "filesystem cannot preserve exact timestamps",
            ));
        }
        Ok(())
    }
    fn symlink_metadata(d: RawFd, n: &[u8], e: &Entry) -> Result<(), Error> {
        let n = cs(n)?;
        cv(unsafe {
            libc::fchownat(
                d,
                n.as_ptr(),
                e.uid as _,
                e.gid as _,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })?;
        let times = [
            match &e.atime {
                Some(t) => time(t)?,
                None => time(&e.mtime)?,
            },
            time(&e.mtime)?,
        ];
        cv(unsafe { libc::utimensat(d, n.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
        confirm_times(&stat(d, n.as_bytes())?, &times)
    }
    type DeferredSymlink = (usize, OwnedFd, Vec<u8>, OwnedFd);

    fn finish_symlinks(
        symlinks: Vec<DeferredSymlink>,
        entries: &[Entry],
        c: &impl Fn() -> bool,
    ) -> Result<(), Error> {
        let mut latest = std::collections::BTreeMap::new();
        for (i, _, _, pin) in &symlinks {
            check(c)?;
            let s = fstat(pin.as_raw_fd())?;
            // Preserve application order, including metadata from replaced aliases.
            latest.insert((s.st_dev, s.st_ino), *i);
        }
        for (_, d, n, pin) in &symlinks {
            check(c)?;
            let saved = fstat(pin.as_raw_fd())?;
            let key = (saved.st_dev, saved.st_ino);
            match stat(d.as_raw_fd(), n) {
                Ok(s)
                    if (s.st_dev, s.st_ino) == key
                        && s.st_mode & libc::S_IFMT == libc::S_IFLNK
                        && saved.st_mode & libc::S_IFMT == libc::S_IFLNK =>
                {
                    if let Some(i) = latest.remove(&key) {
                        // Pins prevent inode reuse; the caller excludes concurrent writers.
                        symlink_metadata(d.as_raw_fd(), n, &entries[i])?;
                    }
                }
                Ok(_) => (),
                Err(e) if missing(&e) => (),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub(super) fn apply(
        path: &Path,
        layer: &mut VerifiedLayer,
        mut receipt: Option<&mut ReplayReceipt>,
        c: &impl Fn() -> bool,
    ) -> Result<Summary, Error> {
        check(c)?;
        if !path.is_absolute()
            || path
                .components()
                .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::Invalid(
                "root must be absolute without dot components",
            ));
        }
        // Refuse symlink ancestors, not just a symlink final component.
        let host = open(libc::AT_FDCWD, b"/", libc::O_RDONLY | libc::O_DIRECTORY)?;
        let mut root = host.try_clone()?;
        for part in path.components() {
            if let Component::Normal(n) = part {
                root = open(
                    root.as_raw_fd(),
                    n.as_bytes(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
            }
        }
        let a = stat(root.as_raw_fd(), b".")?;
        let b = stat(host.as_raw_fd(), b".")?;
        if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) {
            return Err(Error::Invalid("host root refused"));
        }
        for e in layer.entries() {
            check(c)?;
            validate(e)?;
        }
        descriptor_budget(layer.entries(), c)?;
        let mut out = Summary::default();
        // Pin every whiteout parent before any deletion, making marker order inert.
        let mut deletes = Vec::new();
        for e in layer.entries() {
            check(c)?;
            let (parent, name) = split(&e.path);
            if !name.starts_with(b".wh.") {
                continue;
            }
            out.whiteouts += 1;
            let d = match dir(&root, parent, false, c) {
                Ok(d) => d,
                // A lower non-directory has no children for this whiteout to remove.
                Err(e)
                    if missing(&e)
                        || matches!(&e, Error::Io(e) if e.raw_os_error() == Some(libc::ENOTDIR)) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            };
            if name == b".wh..wh..opq" {
                let children = names(d.as_raw_fd(), c)?;
                deletes.push((d, children));
            } else {
                deletes.push((d, vec![name[4..].to_vec()]));
            }
        }
        for (d, children) in deletes {
            for n in children {
                remove(d.as_raw_fd(), &n, 0, c)?;
            }
        }
        let mut dirs = Vec::new();
        let mut symlinks = Vec::new();
        let mut pending: Vec<(usize, OwnedFd, Vec<u8>)> = Vec::new();
        for i in 0..layer.entries().len() {
            check(c)?;
            let e = &layer.entries()[i];
            let (parent, name) = split(&e.path);
            if name.starts_with(b".wh.") {
                continue;
            }
            if e.path.is_empty() {
                dirs.push((i, root.try_clone()?));
                out.entries += 1;
                continue;
            }
            let d = dir(&root, parent, true, c)?;
            let destination = stat(d.as_raw_fd(), b".")?;
            // Later entries supersede deferred links, including through symlink aliases.
            for j in (0..pending.len()).rev() {
                let (_, parent, leaf) = &pending[j];
                let s = stat(parent.as_raw_fd(), b".")?;
                if s.st_nlink == 0
                    || (leaf == name
                        && (s.st_dev, s.st_ino) == (destination.st_dev, destination.st_ino))
                {
                    pending.remove(j);
                }
            }
            if e.kind == EntryKind::Hardlink {
                remove(d.as_raw_fd(), name, 0, c)?;
                pending.push((i, d, name.to_vec()));
                out.entries += 1;
                continue;
            }
            let existing_dir = stat(d.as_raw_fd(), name)
                .map(|s| isdir(&s))
                .unwrap_or(false);
            if e.kind != EntryKind::Directory || !existing_dir {
                remove(d.as_raw_fd(), name, 0, c)?;
            }
            match e.kind {
                EntryKind::Directory => {
                    if !existing_dir {
                        cv(unsafe { libc::mkdirat(d.as_raw_fd(), cs(name)?.as_ptr(), 0o755) })?;
                    }
                    let child = open(d.as_raw_fd(), name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                    same_mount(root.as_raw_fd(), child.as_raw_fd())?;
                    dirs.push((i, child));
                }
                EntryKind::Symlink => {
                    cv(unsafe {
                        libc::symlinkat(
                            cs(e.link_target.as_ref().unwrap())?.as_ptr(),
                            d.as_raw_fd(),
                            cs(name)?.as_ptr(),
                        )
                    })?;
                    symlink_metadata(d.as_raw_fd(), name, e)?;
                    let pin = open(d.as_raw_fd(), name, libc::O_PATH)?;
                    if let Some(receipt) = receipt.as_deref_mut() {
                        use std::os::unix::ffi::OsStringExt;
                        let target = e.link_target.as_ref().unwrap();
                        receipt.charge(target.len() as u64 + 128)?;
                        let s = fstat(pin.as_raw_fd())?;
                        receipt.targets.insert(
                            (s.st_dev, s.st_ino),
                            std::ffi::OsString::from_vec(target.clone()).into(),
                        );
                    }
                    symlinks.push((i, d.try_clone()?, name.to_vec(), pin));
                }
                EntryKind::File => {
                    let fd = open(
                        d.as_raw_fd(),
                        name,
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    )?;
                    let offset = e.data_offset;
                    let mut left = e.size;
                    let mut file = File::from(fd);
                    layer.seek(SeekFrom::Start(offset))?;
                    let mut buffer = [0u8; 65536];
                    while left != 0 {
                        check(c)?;
                        let len = left.min(buffer.len() as u64) as usize;
                        layer.read_exact(&mut buffer[..len])?;
                        file.write_all(&buffer[..len])?;
                        left -= len as u64;
                        out.bytes_written += len as u64;
                    }
                    metadata(file.as_raw_fd(), &layer.entries()[i], c)?;
                }
                EntryKind::Hardlink => unreachable!(),
            }
            out.entries += 1;
        }
        while !pending.is_empty() {
            for j in (0..pending.len()).rev() {
                if stat(pending[j].1.as_raw_fd(), b".")?.st_nlink == 0 {
                    pending.remove(j);
                }
            }
            if pending.is_empty() {
                break;
            }
            let unresolved: Vec<_> = pending
                .iter()
                .map(|(_, d, n)| {
                    let s = stat(d.as_raw_fd(), b".")?;
                    Ok((s.st_dev, s.st_ino, n.clone()))
                })
                .collect::<Result<_, Error>>()?;
            let mut next = Vec::new();
            let before = pending.len();
            for (i, dest, n) in pending {
                check(c)?;
                // An ancestor replacement recursively unlinks even pinned directories.
                if stat(dest.as_raw_fd(), b".")?.st_nlink == 0 {
                    continue;
                }
                let e = &layer.entries()[i];
                let target = e.link_target.as_ref().unwrap();
                let (tp, tn) = split(target);
                if tn.is_empty() || tn == b"." || tn == b".." {
                    return Err(Error::Invalid("hardlink directory target"));
                }
                let source = match dir(&root, tp, false, c) {
                    Ok(d) => d,
                    Err(e) if missing(&e) => {
                        next.push((i, dest, n));
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                // Match chains by directory identity, even after symlink retargeting.
                let parent = stat(source.as_raw_fd(), b".")?;
                if unresolved.iter().any(|(dev, ino, name)| {
                    (*dev, *ino) == (parent.st_dev, parent.st_ino) && name == tn
                }) {
                    next.push((i, dest, n));
                    continue;
                }
                let s = match stat(source.as_raw_fd(), tn) {
                    Ok(s) => s,
                    Err(e) if missing(&e) => {
                        next.push((i, dest, n));
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                if isdir(&s) {
                    return Err(Error::Invalid("hardlink to directory"));
                }
                let symlink = s.st_mode & libc::S_IFMT == libc::S_IFLNK;
                if !symlink && s.st_mode & libc::S_IFMT != libc::S_IFREG {
                    return Err(Error::Unsupported("hardlink to special inode"));
                }
                if symlink && (!e.xattrs.is_empty() || e.mode != 0o777) {
                    return Err(Error::Unsupported("symlink hardlink metadata"));
                }
                // Pin target before replacing destination, including alias paths.
                let file = open(
                    source.as_raw_fd(),
                    tn,
                    if symlink {
                        libc::O_PATH
                    } else {
                        libc::O_RDONLY
                    },
                )?;
                remove(dest.as_raw_fd(), &n, 0, c)?;
                // linkat from stable source names; reject source/destination alias removal.
                cv(unsafe {
                    libc::linkat(
                        source.as_raw_fd(),
                        cs(tn)?.as_ptr(),
                        dest.as_raw_fd(),
                        cs(&n)?.as_ptr(),
                        0,
                    )
                })?;
                if !symlink {
                    metadata(file.as_raw_fd(), e, c)?;
                } else {
                    symlink_metadata(dest.as_raw_fd(), &n, e)?;
                    symlinks.push((i, dest.try_clone()?, n.to_vec(), file));
                }
            }
            if next.len() == before {
                return Err(Error::Invalid("unresolved or cyclic hardlinks"));
            }
            pending = next;
        }
        // Traversing parent symlinks may update their atime during extraction.
        finish_symlinks(symlinks, layer.entries(), c)?;
        let mut finalized = std::collections::BTreeSet::new();
        for (i, fd) in dirs.into_iter().rev() {
            check(c)?;
            let e = &layer.entries()[i];
            let a = stat(fd.as_raw_fd(), b".")?;
            if a.st_nlink != 0 && finalized.insert((a.st_dev, a.st_ino)) {
                metadata(fd.as_raw_fd(), e, c)?;
            }
        }
        check(c)?;
        Ok(out)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{
        layer,
        oci::{BlobStore, Descriptor, Sha256Digest},
    };
    use sha2::{Digest, Sha256};
    use std::{
        cell::Cell,
        fs,
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, symlink},
        },
    };

    struct Item {
        path: String,
        kind: u8,
        data: Vec<u8>,
        target: Option<String>,
        mode: u32,
        pax: Vec<(String, Vec<u8>)>,
    }
    fn file(p: &str, data: &[u8]) -> Item {
        Item {
            path: p.into(),
            kind: b'0',
            data: data.into(),
            target: None,
            mode: 0o640,
            pax: vec![],
        }
    }
    fn directory(p: &str) -> Item {
        Item {
            kind: b'5',
            mode: 0o755,
            ..file(p, b"")
        }
    }
    fn link(p: &str, target: &str, hard: bool) -> Item {
        Item {
            kind: if hard { b'1' } else { b'2' },
            target: Some(target.into()),
            mode: 0o777,
            ..file(p, b"")
        }
    }
    fn verified(items: Vec<Item>) -> VerifiedLayer {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let spool = tmp.path().join("spool");
        fs::create_dir(&spool).unwrap();
        let mut tar = tar::Builder::new(Vec::new());
        for item in items {
            if !item.pax.is_empty() {
                tar.append_pax_extensions(item.pax.iter().map(|(k, v)| (k.as_str(), v.as_slice())))
                    .unwrap();
            }
            let mut h = tar::Header::new_ustar();
            h.set_path(item.path).unwrap();
            h.set_entry_type(tar::EntryType::new(item.kind));
            h.set_mode(item.mode);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(123);
            h.set_size(item.data.len() as u64);
            if let Some(t) = item.target {
                h.set_link_name(t).unwrap();
            }
            h.set_cksum();
            tar.append(&h, item.data.as_slice()).unwrap();
        }
        let bytes = tar.into_inner().unwrap();
        let digest: Sha256Digest = format!("sha256:{:x}", Sha256::digest(&bytes))
            .parse()
            .unwrap();
        let d = Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            digest: digest.to_string(),
            size: bytes.len() as i64,
            annotations: Default::default(),
            extensions: Default::default(),
        };
        store
            .ingest(bytes.as_slice(), &d, bytes.len() as u64, || false)
            .unwrap();
        layer::verify(
            &store,
            &d,
            &digest,
            &spool,
            layer::Limits {
                max_blob_bytes: 10_000_000,
                max_uncompressed_bytes: 10_000_000,
                max_entries: 10_000,
                max_metadata_bytes: 10_000_000,
                max_gzip_header_bytes: 1024,
            },
            || false,
        )
        .unwrap()
    }
    fn apply(root: &Path, items: Vec<Item>) -> Summary {
        apply_layer(root, &mut verified(items), || false).unwrap()
    }

    #[test]
    fn recorded_replay_tracks_inode_targets_through_aliases_and_whiteouts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let mut receipt = ReplayReceipt::new(&root, 1 << 20).unwrap();
        let mut first = verified(vec![
            directory("d"),
            link("alias", "d", false),
            link("alias/s", "old", false),
            link("held", "d/s", true),
        ]);
        receipt.apply(&root, &mut first, || false).unwrap();
        let mut second = verified(vec![
            file("d/.wh.s", b""),
            link("d/s", "new", false),
            link("chain", "held", true),
        ]);
        receipt.apply(&root, &mut second, || false).unwrap();
        receipt
            .validate(&root, &[first.diff_id().clone(), second.diff_id().clone()])
            .unwrap();
        for (name, expected) in [
            ("alias", "d"),
            ("d/s", "new"),
            ("held", "old"),
            ("chain", "old"),
        ] {
            let before = fs::symlink_metadata(root.join(name)).unwrap();
            assert_eq!(
                receipt.target((before.dev(), before.ino())),
                Some(Path::new(expected))
            );
            let after = fs::symlink_metadata(root.join(name)).unwrap();
            assert_eq!(
                (
                    before.atime(),
                    before.atime_nsec(),
                    before.ctime(),
                    before.ctime_nsec()
                ),
                (
                    after.atime(),
                    after.atime_nsec(),
                    after.ctime(),
                    after.ctime_nsec()
                )
            );
        }
        assert!(
            receipt
                .validate(&root, &[second.diff_id().clone()])
                .is_err()
        );
        let replacement = tmp.path().join("replacement");
        fs::create_dir(&replacement).unwrap();
        assert!(receipt.validate(&replacement, &receipt.diff_ids).is_err());
        let mut cancelled = verified(vec![file("must-not-exist", b"")]);
        assert!(receipt.apply(&root, &mut cancelled, || true).is_err());
        assert!(receipt.validate(&root, &receipt.diff_ids).is_err());
        assert!(!root.join("must-not-exist").exists());
    }

    #[test]
    fn recorded_replay_requires_empty_root_and_bounded_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let mut receipt = ReplayReceipt::new(tmp.path(), 128).unwrap();
        let mut layer = verified(vec![link("link", "target", false)]);
        assert!(receipt.apply(tmp.path(), &mut layer, || false).is_err());
        assert!(!receipt.valid);
        assert!(ReplayReceipt::new(tmp.path(), 1024).is_err());
    }

    #[test]
    fn optional_receipt_admission_preserves_root_and_required_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let mut layer = verified(vec![link("link", "target", false)]);
        let small = ReplayReceipt::new(tmp.path(), 261).unwrap();
        assert!(!small.can_record(tmp.path(), &layer, || false).unwrap());
        assert!(fs::symlink_metadata(tmp.path().join("link")).is_err());
        small.validate(tmp.path(), &[]).unwrap();
        assert!(matches!(
            small.can_record(tmp.path(), &layer, || true),
            Err(Error::Cancelled)
        ));
        let mut exact = ReplayReceipt::new(tmp.path(), 262).unwrap();
        assert!(exact.can_record(tmp.path(), &layer, || false).unwrap());
        exact.apply(tmp.path(), &mut layer, || false).unwrap();
        assert_eq!(exact.metadata_bytes(), 262);
        assert!(!exact.can_record(tmp.path(), &layer, || false).unwrap());
        exact.valid = false;
        assert!(exact.can_record(tmp.path(), &layer, || false).is_err());
    }

    #[test]
    fn basic_image_bin_link_stream_and_directory_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let data = vec![42; 200_001];
        let summary = apply(
            root,
            vec![
                directory("usr"),
                directory("usr/bin"),
                link("bin", "usr/bin", false),
                file("bin/tool", &data),
            ],
        );
        assert_eq!(summary.bytes_written, 200_001);
        assert_eq!(fs::read(root.join("usr/bin/tool")).unwrap(), data);
        let m = fs::metadata(root.join("usr/bin/tool")).unwrap();
        assert_eq!(
            (m.mode() & 0o7777, m.uid(), m.gid(), m.mtime()),
            (0o640, 0, 0, 123)
        );
        assert_eq!(fs::metadata(root.join("usr/bin")).unwrap().mtime(), 123);
    }
    #[test]
    fn escape_targets_are_image_relative_and_outer_canaries_survive() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(tmp.path().join("canary"), b"outside").unwrap();
        apply(
            &root,
            vec![
                link("absolute", "/", false),
                link("up", "../../../../", false),
                file("absolute/canary", b"image"),
                file("up/another", b"safe"),
            ],
        );
        assert_eq!(fs::read(tmp.path().join("canary")).unwrap(), b"outside");
        assert_eq!(fs::read(root.join("canary")).unwrap(), b"image");
        assert_eq!(fs::read(root.join("another")).unwrap(), b"safe");
        apply(&root, vec![file("absolute/.wh.canary", b"")]);
        assert!(!root.join("canary").exists());
        assert_eq!(fs::read(tmp.path().join("canary")).unwrap(), b"outside");
        let mut l = verified(vec![link("leak", "../../canary", true)]);
        assert!(apply_layer(&root, &mut l, || false).is_err());
        assert!(!root.join("leak").exists());
    }
    #[test]
    fn whiteouts_are_lower_only_in_either_archive_order() {
        for reverse in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            apply(
                root,
                vec![
                    file("d/old", b"old"),
                    file("gone/x", b"old"),
                    file("same", b"old"),
                ],
            );
            let mut entries = vec![
                file("d/new", b"new"),
                file("d/.wh..wh..opq", b""),
                file(".wh.gone", b""),
                file("same", b"new"),
                file(".wh.same", b""),
            ];
            if reverse {
                entries.reverse();
            }
            let s = apply(root, entries);
            assert_eq!(s.whiteouts, 3);
            assert_eq!(fs::read(root.join("d/new")).unwrap(), b"new");
            assert_eq!(fs::read(root.join("same")).unwrap(), b"new");
            assert!(!root.join("d/old").exists());
            assert!(!root.join("gone").exists());
            assert_eq!(fs::read_dir(root.join("d")).unwrap().count(), 1);
        }
    }
    #[test]
    fn whiteouts_below_lower_files_have_nothing_to_remove() {
        for marker in ["d/.wh..wh..opq", "d/.wh.old", "d/sub/.wh..wh..opq"] {
            let tmp = tempfile::tempdir().unwrap();
            apply(tmp.path(), vec![file("d", b"lower")]);
            let s = apply(
                tmp.path(),
                vec![directory("d"), file(marker, b""), file("d/new", b"upper")],
            );
            assert_eq!(s.whiteouts, 1);
            assert_eq!(fs::read(tmp.path().join("d/new")).unwrap(), b"upper");
        }
    }
    #[test]
    fn deferred_hardlinks_in_removed_directories_do_not_reappear_or_change_targets() {
        for forward in [false, true] {
            for replacement in [0, 1, 2, 3] {
                let tmp = tempfile::tempdir().unwrap();
                let mut entries = vec![directory("other")];
                if !forward {
                    entries.push(file("target", b"target"));
                }
                entries.push(link("d/nested/h", "target", true));
                match replacement {
                    0 => entries.push(link("d", "other", false)),
                    1 => entries.push(file("d", b"replacement")),
                    2 => {
                        entries.push(file("d", b"replacement"));
                        entries.push(link("root", ".", false));
                        entries.push(directory("root/d"));
                    }
                    _ => entries.push(link("d", "replacement", true)),
                }
                if forward {
                    entries.push(file("target", b"target"));
                }
                entries.push(file("replacement", b"replacement"));
                apply(tmp.path(), entries);
                assert!(!tmp.path().join("d/nested/h").exists());
                assert!(!tmp.path().join("other/nested/h").exists());
                assert_eq!(
                    fs::metadata(tmp.path().join("target")).unwrap().mode() & 0o7777,
                    0o640
                );
                assert_eq!(fs::metadata(tmp.path().join("target")).unwrap().nlink(), 1);
            }
        }
    }
    #[test]
    fn deferred_hardlink_destination_survives_parent_symlink_retargeting() {
        let tmp = tempfile::tempdir().unwrap();
        apply(
            tmp.path(),
            vec![directory("original"), link("d", "original", false)],
        );
        apply(
            tmp.path(),
            vec![
                directory("other"),
                link("d/h", "target", true),
                link("d", "other", false),
                file("target", b"forward"),
            ],
        );
        assert_eq!(fs::read(tmp.path().join("original/h")).unwrap(), b"forward");
        assert!(!tmp.path().join("other/h").exists());
        assert_eq!(
            fs::metadata(tmp.path().join("original/h")).unwrap().ino(),
            fs::metadata(tmp.path().join("target")).unwrap().ino()
        );
    }
    #[test]
    fn replaced_hardlink_parent_does_not_redirect_to_other() {
        let tmp = tempfile::tempdir().unwrap();
        apply(
            tmp.path(),
            vec![
                file("target", b"target"),
                directory("other"),
                link("d/h", "target", true),
                link("d", "other", false),
            ],
        );
        assert!(!tmp.path().join("other/h").exists());
        assert_eq!(
            fs::metadata(tmp.path().join("target")).unwrap().mode() & 0o7777,
            0o640
        );
    }
    #[test]
    fn forward_chain_uses_pinned_destination_identity_after_retargeting() {
        let tmp = tempfile::tempdir().unwrap();
        apply(
            tmp.path(),
            vec![directory("original"), link("d", "original", false)],
        );
        apply(
            tmp.path(),
            vec![
                directory("other"),
                link("first", "original/h", true),
                link("d/h", "target", true),
                link("d", "other", false),
                file("target", b"forward"),
            ],
        );
        assert_eq!(fs::read(tmp.path().join("first")).unwrap(), b"forward");
        assert_eq!(
            fs::metadata(tmp.path().join("first")).unwrap().ino(),
            fs::metadata(tmp.path().join("original/h")).unwrap().ino()
        );
        assert!(!tmp.path().join("other/h").exists());
    }
    #[test]
    fn later_entries_supersede_pending_hardlinks_through_aliases() {
        for replacement in [
            file("alias/h", b"new"),
            directory("alias/h"),
            link("alias/h", "new", false),
            link("alias/h", "new", true),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            apply(
                tmp.path(),
                vec![
                    directory("d"),
                    link("alias", "d", false),
                    link("d/h", "missing", true),
                    replacement,
                    file("new", b"new"),
                ],
            );
            assert!(fs::symlink_metadata(tmp.path().join("d/h")).is_ok());
        }
    }
    #[test]
    fn type_replacements_do_not_follow_leaf_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        apply(root, vec![file("x", b"file"), file("target", b"stay")]);
        apply(root, vec![directory("x"), file("x/a", b"child")]);
        apply(root, vec![link("x", "target", false)]);
        apply(root, vec![file("x", b"replacement")]);
        assert_eq!(fs::read(root.join("target")).unwrap(), b"stay");
        assert_eq!(fs::read(root.join("x")).unwrap(), b"replacement");
        // A later ancestor replacement invalidates pending directory metadata.
        apply(root, vec![directory("tree/child"), file("tree", b"final")]);
        assert_eq!(fs::read(root.join("tree")).unwrap(), b"final");
    }
    #[test]
    fn forward_chain_and_lower_hardlinks_share_inodes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        apply(root, vec![file("lower", b"lower"), file("b", b"obsolete")]);
        apply(
            root,
            vec![
                link("a", "/b", true),
                link("b", "c", true),
                file("c", b"forward"),
                link("copy", "lower", true),
            ],
        );
        assert_eq!(fs::read(root.join("a")).unwrap(), b"forward");
        assert_eq!(
            fs::metadata(root.join("a")).unwrap().ino(),
            fs::metadata(root.join("c")).unwrap().ino()
        );
        assert_eq!(
            fs::metadata(root.join("copy")).unwrap().ino(),
            fs::metadata(root.join("lower")).unwrap().ino()
        );
        let mut bad = verified(vec![link("bad", "/", true)]);
        assert!(apply_layer(root, &mut bad, || false).is_err());
        let mut cycle = verified(vec![
            link("cycle1", "cycle2", true),
            link("cycle2", "cycle1", true),
        ]);
        assert!(apply_layer(root, &mut cycle, || false).is_err());
    }
    #[test]
    fn symlink_bytes_and_hardlinks_to_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        apply(
            root,
            vec![link("s", "/../../missing", false), link("h", "s", true)],
        );
        assert_eq!(
            fs::read_link(root.join("h"))
                .unwrap()
                .as_os_str()
                .as_bytes(),
            b"/../../missing"
        );
        assert_eq!(
            fs::symlink_metadata(root.join("h")).unwrap().ino(),
            fs::symlink_metadata(root.join("s")).unwrap().ino()
        );
    }
    #[test]
    fn deferred_symlink_pins_survive_alias_replacement() {
        if isolated_fd_inspection("deferred_symlink_pins_survive_alias_replacement") {
            return;
        }
        use std::os::fd::RawFd;
        for replacement_symlink in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let mut replacement = if replacement_symlink {
                link("alias/s", "new-target", false)
            } else {
                file("alias/s", b"replacement")
            };
            replacement.pax.push(("mtime".into(), b"456".to_vec()));
            let mut layer = verified(vec![
                directory("d"),
                link("alias", "d", false),
                link("d/s", "old-target", false),
                replacement,
            ]);
            let original = Cell::new(None);
            let pin = Cell::new(None::<RawFd>);
            let saw_unlinked = Cell::new(false);
            apply_layer(root, &mut layer, || {
                if original.get().is_none()
                    && let Ok(m) = fs::symlink_metadata(root.join("d/s"))
                {
                    original.set(Some((m.dev(), m.ino())));
                }
                if let Some(identity) = original.get() {
                    if pin.get().is_none() {
                        for entry in fs::read_dir("/proc/self/fd").unwrap() {
                            let entry = entry.unwrap();
                            let Ok(fd) = entry.file_name().to_str().unwrap().parse::<RawFd>()
                            else {
                                continue;
                            };
                            if let Ok(m) = fs::metadata(entry.path())
                                && (m.dev(), m.ino()) == identity
                                && unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_PATH != 0
                            {
                                pin.set(Some(fd));
                                break;
                            }
                        }
                        assert!(pin.get().is_some(), "original symlink must be pinned");
                    }
                    let fd = pin.get().unwrap();
                    if let Ok(m) = fs::metadata(format!("/proc/self/fd/{fd}")) {
                        assert_eq!((m.dev(), m.ino()), identity);
                        assert!(m.file_type().is_symlink());
                        if m.nlink() == 0 {
                            saw_unlinked.set(true);
                        }
                    } else {
                        // Pins may close only after finalization, which follows replacement.
                        assert!(saw_unlinked.get());
                    }
                }
                false
            })
            .unwrap();
            assert!(saw_unlinked.get(), "pin must retain the unlinked inode");
            let m = fs::symlink_metadata(root.join("d/s")).unwrap();
            assert_eq!(m.mtime(), 456);
            assert_eq!(m.file_type().is_symlink(), replacement_symlink);
        }
    }

    #[test]
    fn symlink_hardlink_metadata_follows_resolution_order() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // h resolves first; the later chain resolves on the next pass and changes
        // the same inode again. Finalization must preserve that application order.
        let mut h = link("h", "s", true);
        h.pax.push(("mtime".into(), b"456".to_vec()));
        let mut chain = link("chain", "h", true);
        chain.pax.push(("mtime".into(), b"789".to_vec()));
        apply(root, vec![link("s", "missing", false), chain, h]);
        for name in ["s", "h", "chain"] {
            assert_eq!(fs::symlink_metadata(root.join(name)).unwrap().mtime(), 789);
        }
    }

    #[test]
    fn later_symlink_hardlink_metadata_survives_replaced_alias() {
        if isolated_fd_inspection("later_symlink_hardlink_metadata_survives_replaced_alias") {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut h = link("d/h", "s", true);
        h.pax.push(("mtime".into(), b"456".to_vec()));
        let mut layer = verified(vec![
            link("s", "missing", false),
            file("regular", b"replacement"),
            link("d", "forward", true),
            h,
            link("forward", "regular", true),
        ]);
        let saw_hardlink_pins = Cell::new(false);
        apply_layer(root, &mut layer, || {
            if let Ok(m) = fs::symlink_metadata(root.join("d/h")) {
                let pins = fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        let fd: i32 = entry.file_name().to_str().unwrap().parse().unwrap();
                        fs::metadata(entry.path()).is_ok_and(|s| {
                            (s.dev(), s.ino()) == (m.dev(), m.ino())
                                && s.file_type().is_symlink()
                                && unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_PATH != 0
                        })
                    })
                    .count();
                // Both the direct symlink and the hardlink retain their own pin.
                assert_eq!(pins, 2);
                saw_hardlink_pins.set(true);
            }
            false
        })
        .unwrap();
        assert!(saw_hardlink_pins.get());
        assert_eq!(fs::read(root.join("d")).unwrap(), b"replacement");
        assert_eq!(fs::symlink_metadata(root.join("s")).unwrap().mtime(), 456);
    }
    #[test]
    fn xattrs_signed_fraction_and_preflight_precision() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut item = file("f", b"data");
        item.pax = vec![
            ("mtime".into(), b"-0.25".to_vec()),
            ("SCHILY.xattr.user.weld".into(), b"value".to_vec()),
        ];
        apply(root, vec![item]);
        let m = fs::metadata(root.join("f")).unwrap();
        assert_eq!((m.mtime(), m.mtime_nsec()), (-1, 750_000_000));
        let path = std::ffi::CString::new(root.join("f").as_os_str().as_bytes()).unwrap();
        let mut value = [0u8; 32];
        let len = unsafe {
            libc::getxattr(
                path.as_ptr(),
                c"user.weld".as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        assert_eq!(&value[..len as usize], b"value");
        for (key, val) in [
            ("mtime", "0.0000000001"),
            ("ctime", "1"),
            ("mtime", "18446744073709551615"),
        ] {
            let mut bad = file("bad", b"");
            bad.pax = vec![(key.into(), val.as_bytes().to_vec())];
            let mut l = verified(vec![file("must-not-appear", b""), bad]);
            assert!(matches!(
                apply_layer(root, &mut l, || false),
                Err(Error::Unsupported(_))
            ));
            assert!(!root.join("must-not-appear").exists());
        }
    }
    #[test]
    fn cancellation_during_content_and_before_deletion() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("keep"), b"keep").unwrap();
        let mut l = verified(vec![file(".wh.keep", b"")]);
        assert!(matches!(
            apply_layer(root, &mut l, || true),
            Err(Error::Cancelled)
        ));
        assert_eq!(fs::read(root.join("keep")).unwrap(), b"keep");
        let mut l = verified(vec![file("large", &vec![7; 1_000_000])]);
        assert!(matches!(
            apply_layer(root, &mut l, || {
                fs::metadata(root.join("large")).is_ok_and(|m| m.len() >= 65536)
            }),
            Err(Error::Cancelled)
        ));
        assert!(fs::metadata(root.join("large")).unwrap().len() < 1_000_000);
    }
    // Raw FD observations must not race unrelated tests opening/closing/reusing FDs.
    fn isolated_fd_inspection(name: &str) -> bool {
        const KEY: &str = "RPWELD_ISOLATED_FD_INSPECTION";
        if std::env::var(KEY).as_deref() == Ok(name) {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("rootfs::tests::{name}"), "--nocapture"])
            .env(KEY, name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    #[test]
    fn descriptor_budget_subprocess() {
        const CHILD: &str = "RPWELD_ROOTFS_FD_BUDGET_CHILD";
        let Ok(case) = std::env::var(CHILD) else {
            for case in [
                "raise",
                "insufficient",
                "cancel",
                "opaque",
                "unchanged",
                "phases",
            ] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "rootfs::tests::descriptor_budget_subprocess",
                        "--nocapture",
                    ])
                    .env(CHILD, case)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{case}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        };
        fn limits() -> libc::rlimit {
            let mut value = std::mem::MaybeUninit::uninit();
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, value.as_mut_ptr()) },
                0
            );
            unsafe { value.assume_init() }
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("keep"), b"unchanged").unwrap();
        let mut entries = vec![file(".wh.keep", b"")];
        if case == "opaque" {
            fs::create_dir(root.join("lower")).unwrap();
            for i in 0..1500 {
                fs::write(root.join(format!("lower/{i}")), b"").unwrap();
            }
            entries = vec![file("lower/.wh..wh..opq", b"")];
        } else if case == "phases" {
            entries.clear();
            for i in 0..500 {
                fs::write(root.join(format!("old{i}")), b"old").unwrap();
                entries.push(file(&format!(".wh.old{i}"), b""));
                entries.push(directory(&format!("new{i}")));
            }
        } else if case == "unchanged" {
            entries = vec![file("small", b"ok")];
        } else {
            for i in 0..1250 {
                entries.push(directory(&format!("d{i}")));
                entries.push(link(&format!("d{i}/s"), "missing", false));
                entries.push(link(&format!("h{i}"), &format!("d{i}/s"), true));
            }
        }
        let mut layer = verified(entries);
        // Existing non-rootfs descriptors must contribute to the budget.
        let _held: Vec<_> = (0..96)
            .map(|_| fs::File::open("/dev/null").unwrap())
            .collect();
        let hard = if case == "raise" { 16_384 } else { 1024 };
        assert!(
            limits().rlim_max >= hard,
            "test needs hard NOFILE >= {hard}"
        );
        assert_eq!(
            unsafe {
                libc::setrlimit(
                    libc::RLIMIT_NOFILE,
                    &libc::rlimit {
                        rlim_cur: 1024,
                        rlim_max: hard,
                    },
                )
            },
            0
        );
        // Doctor observes the inherited limits without changing them, including
        // a runtime where soft and hard are both fixed at 1024.
        let observed = crate::capabilities::inspect();
        assert_eq!(observed["nofile"]["soft"], 1024);
        assert_eq!(observed["nofile"]["hard"], hard);
        assert_eq!(limits().rlim_cur, 1024);
        assert_eq!(limits().rlim_max, hard);
        // Cancel during preflight, after the initial cancellation check.
        let calls = Cell::new(0);
        let result = apply_layer(root, &mut layer, || {
            calls.set(calls.get() + 1);
            case == "cancel" && calls.get() >= 10
        });
        match case.as_str() {
            "insufficient" | "cancel" => {
                let error = result.unwrap_err();
                if case == "cancel" {
                    assert!(matches!(error, Error::Cancelled));
                } else {
                    let message = error.to_string();
                    assert!(message.contains("descriptor budget requires"), "{message}");
                    assert!(message.contains("hard limit 1024"), "{message}");
                    assert!(message.contains("root unchanged"), "{message}");
                }
                assert_eq!(fs::read(root.join("keep")).unwrap(), b"unchanged");
                assert_eq!(fs::read_dir(root).unwrap().count(), 1);
                assert_eq!(limits().rlim_cur, 1024);
            }
            "raise" => {
                result.unwrap();
                let raised = limits().rlim_cur;
                assert!(raised > 6250 && raised < hard);
                // Replay must preserve pinned inode identity and metadata too.
                apply_layer(root, &mut layer, || false).unwrap();
                assert_eq!(limits().rlim_cur, raised);
                for i in 0..1250 {
                    let s = fs::symlink_metadata(root.join(format!("d{i}/s"))).unwrap();
                    let h = fs::symlink_metadata(root.join(format!("h{i}"))).unwrap();
                    assert_eq!(s.ino(), h.ino());
                    assert_eq!(s.nlink(), 2);
                    assert_eq!(s.mtime(), 123);
                    assert_eq!(
                        fs::metadata(root.join(format!("d{i}"))).unwrap().mode() & 0o7777,
                        0o755
                    );
                }
            }
            "opaque" => {
                result.unwrap();
                assert_eq!(fs::read_dir(root.join("lower")).unwrap().count(), 0);
                assert_eq!(limits().rlim_cur, 1024);
            }
            "phases" => {
                result.unwrap();
                for i in 0..500 {
                    assert!(!root.join(format!("old{i}")).exists());
                    assert!(root.join(format!("new{i}")).is_dir());
                }
                assert_eq!(limits().rlim_cur, 1024);
            }
            "unchanged" => {
                result.unwrap();
                assert_eq!(limits().rlim_cur, 1024);
            }
            _ => unreachable!(),
        }
        assert_eq!(limits().rlim_max, hard);
    }
    #[test]
    fn host_root_and_symlink_aliases_refused_and_loop_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        symlink("/", tmp.path().join("alias")).unwrap();
        for root in [
            Path::new("/"),
            Path::new("//"),
            tmp.path().join("alias").as_path(),
            Path::new("relative"),
        ] {
            assert!(apply_layer(root, &mut verified(vec![]), || false).is_err());
        }
        apply(tmp.path(), vec![link("loop", "loop", false)]);
        assert!(
            apply_layer(
                tmp.path(),
                &mut verified(vec![file("loop/file", b"")]),
                || false
            )
            .is_err()
        );
    }
    #[test]
    fn hardlink_xattrs_merge_in_resolution_order_on_the_shared_inode() {
        for forward in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let mut target = file("target", b"payload");
            target.pax = vec![
                ("SCHILY.xattr.user.keep".into(), b"keep".to_vec()),
                ("SCHILY.xattr.user.change".into(), b"target".to_vec()),
            ];
            let mut first = link("first", "target", true);
            first.pax = vec![("SCHILY.xattr.user.change".into(), b"first".to_vec())];
            let mut last = link("last", "first", true);
            last.pax = vec![("SCHILY.xattr.user.change".into(), b"last".to_vec())];
            let absent = link("absent", "last", true);
            if forward {
                apply(root, vec![absent, last, first, target]);
            } else {
                apply(root, vec![target]);
                apply(root, vec![first, last, absent]);
            }
            let inode = fs::metadata(root.join("target")).unwrap().ino();
            for name in ["target", "first", "last", "absent"] {
                let path = root.join(name);
                assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
                assert_eq!(read_xattr(&path, c"user.keep"), Some(b"keep".to_vec()));
                assert_eq!(read_xattr(&path, c"user.change"), Some(b"last".to_vec()));
            }
        }
    }

    fn read_xattr(path: &Path, name: &std::ffi::CStr) -> Option<Vec<u8>> {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut buf = vec![0; 256];
        let len = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if len < 0 {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODATA)
            );
            None
        } else {
            buf.truncate(len as usize);
            Some(buf)
        }
    }

    #[test]
    fn hardlink_capability_is_cleared_by_chown_unless_explicitly_restored() {
        let cap = vec![1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for explicit in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let mut target = file("target", b"payload");
            target.pax = vec![("SCHILY.xattr.security.capability".into(), cap.clone())];
            match apply_layer(root, &mut verified(vec![target]), || false) {
                Ok(_) => {}
                Err(Error::Io(e))
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::EPERM | libc::EACCES | libc::EOPNOTSUPP)
                    ) =>
                {
                    continue;
                }
                Err(e) => panic!("{e}"),
            }
            assert_eq!(
                read_xattr(&root.join("target"), c"security.capability"),
                Some(cap.clone())
            );
            let mut alias = link("alias", "target", true);
            if explicit {
                alias.pax = vec![("SCHILY.xattr.security.capability".into(), cap.clone())];
            }
            apply(root, vec![alias]);
            for name in ["target", "alias"] {
                assert_eq!(
                    read_xattr(&root.join(name), c"security.capability"),
                    explicit.then(|| cap.clone())
                );
            }
        }
    }

    #[test]
    fn directory_xattrs_are_replaced_and_capabilities_preserved_or_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut d = directory("d");
        d.pax = vec![("SCHILY.xattr.user.old".into(), b"old".to_vec())];
        apply(root, vec![d]);
        apply(root, vec![directory("d")]);
        let path = std::ffi::CString::new(root.join("d").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::getxattr(path.as_ptr(), c"user.old".as_ptr(), std::ptr::null_mut(), 0) },
            -1
        );
        let mut f = file("cap", b"x");
        // VFS_CAP_REVISION_2, effective + CAP_NET_BIND_SERVICE.
        let cap = vec![1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        f.pax = vec![("SCHILY.xattr.security.capability".into(), cap.clone())];
        match apply_layer(root, &mut verified(vec![f]), || false) {
            Ok(_) => {
                let p = std::ffi::CString::new(root.join("cap").as_os_str().as_bytes()).unwrap();
                let mut buf = [0u8; 24];
                let len = unsafe {
                    libc::getxattr(
                        p.as_ptr(),
                        c"security.capability".as_ptr(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                    )
                };
                assert_eq!(&buf[..len as usize], cap);
            }
            Err(Error::Io(e)) => assert!(matches!(
                e.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::EOPNOTSUPP)
            )),
            Err(e) => panic!("{e}"),
        }
    }
}
