//! Read-only, bounded observations of the existing Weld store.
//!
//! No snapshot isolation: concurrent publication/removal can produce partial results.
//! Nothing here proves inactivity or deletion eligibility. Shared/exclusive worker
//! leases must exist before a deletion planner can use these observations.
//! Unknown entries (including credentials) are named but never opened for reading.

use serde::Serialize;
use std::path::{Path, PathBuf};

// UTF-8 paths retain the v1 string shape; other paths carry lossless native units.
fn serialize_path<S: serde::Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    if let Some(path) = path.to_str() {
        return serializer.serialize_str(path);
    }
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(1))?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        map.serialize_entry("unix_bytes", path.as_os_str().as_bytes())?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        map.serialize_entry(
            "windows_wide",
            &path.as_os_str().encode_wide().collect::<Vec<_>>(),
        )?;
    }
    #[cfg(not(any(unix, windows)))]
    return Err(serde::ser::Error::custom(
        "unsupported native path encoding",
    ));
    map.end()
}

fn serialize_optional_path<S: serde::Serializer>(
    path: &Option<PathBuf>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match path {
        Some(path) => serialize_path(path, serializer),
        None => serializer.serialize_none(),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_entries: usize,
    pub max_depth: usize,
    pub max_record_bytes: usize,
    pub max_metadata_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_depth: 64,
            max_record_bytes: 64 * 1024,
            max_metadata_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Missing,
    Present,
    Invalid,
    Unknown,
    Protected,
    LegacyUnknown,
    Temporary,
    /// Structurally complete OCI metadata, not a verified image or safe to delete.
    Complete,
    Current,
    /// Reserved for future evidence: current stores retain no generation history.
    Superseded,
    /// Not named by any observed valid ref; may also be superseded or being published.
    Orphan,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    Managed,
    External,
    Unknown,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Usage {
    /// Regular-file bytes per pathname, including repeated hard links.
    pub logical_bytes: u64,
    /// Regular-file bytes counted once per (device, inode).
    pub unique_logical_bytes: u64,
    /// st_blocks * 512 counted once per (device, inode); excludes directory blocks.
    /// Not exclusive/reclaimable bytes: other links and reflinks may exist.
    pub allocated_bytes: u64,
    pub files: u64,
    pub shared_hardlink_paths: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_record: Option<crate::build_record::Record>,
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub status: Status,
    pub ownership: Ownership,
    /// Always true: ownership evidence does not authorize deletion.
    pub protected: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Tag {
    #[serde(serialize_with = "serialize_path")]
    pub record: PathBuf,
    pub reference: Option<String>,
    #[serde(serialize_with = "serialize_optional_path")]
    pub image: Option<PathBuf>,
    pub status: Status,
    pub ownership: Ownership,
    /// External targets are never stat'ed or traversed. Internal targets are not
    /// ownership evidence either; their existence is deliberately not resolved.
    pub target_status: Status,
}
#[derive(Clone, Debug, Serialize)]
pub struct BaseRef {
    #[serde(serialize_with = "serialize_path")]
    pub record: PathBuf,
    pub reference: Option<String>,
    pub generation: Option<String>,
    pub status: Status,
}
#[derive(Clone, Debug, Serialize)]
pub struct Issue {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    /// Fixed diagnostic codes only, never parser errors or record contents.
    pub code: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Inventory {
    #[serde(serialize_with = "serialize_path")]
    pub store: PathBuf,
    pub status: Status,
    pub best_effort: bool,
    pub partial: bool,
    /// False on any scan failure or interruption, independently of diagnostics.
    /// Intentional symlink/special payload skips alone do not make this false.
    pub scan_complete: bool,
    /// True if any diagnostic was omitted by the bounded issue list.
    pub issues_truncated: bool,
    pub tags: Vec<Tag>,
    pub base_refs: Vec<BaseRef>,
    pub generations: Vec<Entry>,
    pub stages: Vec<Entry>,
    pub builds: Vec<Entry>,
    pub protected_entries: Vec<Entry>,
    /// Scanned cache/build regular files only; excludes records and unknown areas.
    pub usage: Usage,
    /// Independently deduplicated within caches; do not sum with builds_usage.
    pub cache_usage: Usage,
    pub builds_usage: Usage,
    pub issues: Vec<Issue>,
}
impl Inventory {
    pub fn image_inspect(&self, exact_reference: &str) -> Option<&Tag> {
        self.tags
            .iter()
            .find(|t| t.reference.as_deref() == Some(exact_reference))
    }
    pub fn build_inspect(&self, name: &str) -> Option<&Entry> {
        self.builds.iter().find(|b| b.path == Path::new(name))
    }
    pub fn cache_inspect(&self, relative_path: &Path) -> Option<&Entry> {
        self.stages
            .iter()
            .chain(&self.generations)
            .find(|e| e.path == relative_path)
    }
}

/// Resolve environment only. Unlike registry::store_dir, never creates anything.
pub fn resolve_store() -> std::io::Result<PathBuf> {
    let path = match std::env::var_os("RPWELD_HOME") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| std::io::Error::other("HOME must be an absolute directory"))?,
        )
        .join(".local/share/rpweld"),
    };
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(std::io::Error::other(
            "store must be absolute without parent components",
        ));
    }
    Ok(path)
}

pub fn inspect_existing(
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> std::io::Result<Inventory> {
    inspect(&resolve_store()?, limits, cancelled)
}

pub fn inspect(
    store: &Path,
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> std::io::Result<Inventory> {
    #[cfg(target_os = "linux")]
    {
        linux::inspect(store, limits, &cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store, limits, cancelled);
        Err(std::io::Error::other(
            "safe store inventory requires Linux openat2",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashSet,
        ffi::{CStr, CString, OsString},
        fs::File,
        io::{self, Read},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::{OsStrExt, OsStringExt},
                fs::MetadataExt,
            },
        },
    };

    // openat2 resolves each lookup beneath a pinned descriptor. NO_XDEV also
    // rejects same-device bind mounts, which st_dev comparisons cannot detect.
    fn open(parent: i32, path: &Path, directory: bool, root: bool) -> io::Result<File> {
        #[repr(C)]
        struct How {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let name = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("invalid path"))?;
        let how = How {
            flags: (libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | libc::O_NOFOLLOW
                | if directory { libc::O_DIRECTORY } else { 0 }) as u64,
            mode: 0,
            resolve: 0x02 | 0x04 | if root { 0 } else { 0x01 | 0x08 },
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent,
                name.as_ptr(),
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
    fn owned_dir(file: &File) -> io::Result<()> {
        let m = file.metadata()?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "directory must be user-owned and not group/world writable",
            ));
        }
        Ok(())
    }
    fn hex(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn generation(s: &str) -> bool {
        s.starts_with("gen-")
            && s.len() > 4
            && s.len() <= 128
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }
    fn safe_reference(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 4096
            && !s.contains("://")
            && !s.chars().any(|c| c.is_control() || c.is_whitespace())
    }
    fn entry(path: PathBuf, status: Status, ownership: Ownership) -> Entry {
        Entry {
            build_record: None,
            path,
            status,
            ownership,
            protected: true,
        }
    }
    struct Scan<'a> {
        out: Inventory,
        limits: Limits,
        cancel: &'a dyn Fn() -> bool,
        entries: usize,
        bytes: usize,
        stopped: bool,
        seen: HashSet<(u64, u64)>,
        cache_seen: HashSet<(u64, u64)>,
        builds_seen: HashSet<(u64, u64)>,
        refs_uncertain: bool,
    }
    impl Scan<'_> {
        fn issue(&mut self, path: &Path, code: &str) {
            self.out.partial = true;
            if code != "symlink_or_special_file_skipped" {
                self.out.scan_complete = false;
            }
            self.diagnostic(path, code);
        }
        fn diagnostic(&mut self, path: &Path, code: &str) {
            // Diagnostics are bounded independently of errors from traversal.
            if self.out.issues.len() < self.limits.max_entries.min(1024) {
                self.out.issues.push(Issue {
                    path: path.into(),
                    code: code.into(),
                });
            } else {
                self.out.issues_truncated = true;
            }
        }
        fn stop(&mut self) -> bool {
            if !self.stopped && (self.cancel)() {
                self.issue(Path::new(""), "cancelled");
                self.stopped = true;
            }
            self.stopped
        }
        fn charge(&mut self, bytes: usize, path: &Path) -> bool {
            if bytes > self.limits.max_metadata_bytes.saturating_sub(self.bytes) {
                self.issue(path, "metadata_budget");
                self.stopped = true;
                return false;
            }
            self.bytes += bytes;
            true
        }
        fn names(&mut self, dir: &File, path: &Path) -> Vec<OsString> {
            let mut names = Vec::new();
            let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                self.issue(path, "directory_read_failed");
                return names;
            }
            let stream = unsafe { libc::fdopendir(fd) };
            if stream.is_null() {
                unsafe {
                    libc::close(fd);
                }
                self.issue(path, "directory_read_failed");
                return names;
            }
            while !self.stop() {
                unsafe {
                    *libc::__errno_location() = 0;
                }
                let e = unsafe { libc::readdir(stream) };
                if e.is_null() {
                    if unsafe { *libc::__errno_location() } != 0 {
                        self.issue(path, "directory_read_failed");
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }.to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                if self.entries >= self.limits.max_entries {
                    self.issue(path, "entry_budget");
                    self.stopped = true;
                    break;
                }
                self.entries += 1;
                if !self.charge(name.len() + path.as_os_str().len() + 128, path) {
                    break;
                }
                names.push(OsString::from_vec(name.to_vec()));
            }
            unsafe {
                libc::closedir(stream);
            }
            names.sort();
            names
        }
        fn dir(&mut self, parent: &File, name: &Path, path: &Path) -> Option<File> {
            match open(parent.as_raw_fd(), name, true, false).and_then(|f| {
                owned_dir(&f)?;
                Ok(f)
            }) {
                Ok(f) => Some(f),
                Err(_) => {
                    self.issue(path, "unsafe_missing_or_unreadable_directory");
                    None
                }
            }
        }
        fn record<T: serde::de::DeserializeOwned>(
            &mut self,
            parent: &File,
            name: &Path,
            path: &Path,
        ) -> Option<T> {
            if self.stop() {
                return None;
            }
            let result = (|| -> io::Result<Vec<u8>> {
                let f = open(parent.as_raw_fd(), name, false, false)?;
                let m = f.metadata()?;
                if !m.is_file()
                    || m.uid() != unsafe { libc::geteuid() }
                    || m.nlink() != 1
                    || m.mode() & 0o077 != 0
                {
                    return Err(io::Error::other("unsafe record"));
                }
                if m.len() > self.limits.max_record_bytes as u64 {
                    return Err(io::Error::other("record too large"));
                }
                let cap = self
                    .limits
                    .max_record_bytes
                    .min(self.limits.max_metadata_bytes.saturating_sub(self.bytes));
                if m.len() > cap as u64 {
                    self.issue(path, "metadata_budget");
                    self.stopped = true;
                    return Err(io::Error::other("metadata budget"));
                }
                let mut bytes = Vec::new();
                f.take(cap as u64 + 1).read_to_end(&mut bytes)?;
                if !self.charge(bytes.len(), path) {
                    return Err(io::Error::other("metadata budget"));
                }
                if bytes.len() > cap {
                    return Err(io::Error::other("record too large"));
                }
                Ok(bytes)
            })();
            match result {
                Ok(bytes) => match serde_json::from_slice(&bytes) {
                    Ok(record) => Some(record),
                    Err(_) => {
                        self.issue(path, "invalid_record");
                        None
                    }
                },
                _ => {
                    self.issue(path, "unsafe_missing_or_oversized_record");
                    None
                }
            }
        }
        fn tag(&mut self, root: &File, path: &Path) {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Record {
                reference: String,
                image: PathBuf,
            }
            let mut tag = Tag {
                record: path.into(),
                reference: None,
                image: None,
                status: Status::Invalid,
                ownership: Ownership::Unknown,
                target_status: Status::Unknown,
            };
            if let Some(r) = self.record::<Record>(root, path, path) {
                let expected = format!("tag-{:x}.json", Sha256::digest(r.reference.as_bytes()));
                if safe_reference(&r.reference)
                    && path == Path::new(&expected)
                    && r.image.is_absolute()
                    && !r
                        .image
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    tag.status = Status::Present;
                    tag.ownership = if r.image.starts_with(&self.out.store) {
                        Ownership::Unknown
                    } else {
                        Ownership::External
                    };
                    tag.reference = Some(r.reference);
                    tag.image = Some(r.image);
                } else {
                    self.issue(path, "invalid_tag_identity");
                }
            }
            self.out.tags.push(tag);
        }
        fn base_ref(&mut self, dir: &File, name: &Path, path: &Path) {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Record {
                version: u32,
                reference: String,
                platform: String,
                source_digest: Option<String>,
                generation: String,
                selected: serde_json::Value,
            }
            let mut r = BaseRef {
                record: path.into(),
                reference: None,
                generation: None,
                status: Status::Invalid,
            };
            if let Some(v) = self.record::<Record>(dir, name, path) {
                let expected = format!(
                    "{:x}.json",
                    Sha256::digest(format!("{}\nlinux/amd64", v.reference))
                );
                let digest = v
                    .selected
                    .get("digest")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if v.version == 1
                    && v.platform == "linux/amd64"
                    && generation(&v.generation)
                    && safe_reference(&v.reference)
                    && name == Path::new(&expected)
                    && v.source_digest.as_deref() == v.reference.split_once('@').map(|(_, d)| d)
                    && digest.strip_prefix("sha256:").is_some_and(hex)
                    && v.selected.get("size").and_then(|v| v.as_u64()).is_some()
                    && v.selected
                        .get("mediaType")
                        .and_then(|v| v.as_str())
                        .is_some()
                {
                    r.reference = Some(v.reference);
                    r.generation = Some(v.generation);
                    r.status = Status::Present;
                } else {
                    self.issue(path, "invalid_base_identity");
                }
            }
            if r.status == Status::Invalid {
                self.refs_uncertain = true;
            }
            self.out.base_refs.push(r);
        }
        fn layout(&mut self, dir: &File, path: &Path) -> Status {
            // OCI metadata has public 0644 permissions; record() is intentionally
            // stricter, so use a separate bounded reader with no auth fallback.
            fn io_status(e: io::Error) -> Status {
                match e.kind() {
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => Status::Invalid,
                    _ => Status::Unknown,
                }
            }
            let result = (|| -> Result<(), Status> {
                for name in ["oci-layout", "index.json"] {
                    if self.stop() {
                        return Err(Status::Unknown);
                    }
                    let p = path.join(name);
                    let value = (|| -> Result<serde_json::Value, Status> {
                        let f = open(dir.as_raw_fd(), Path::new(name), false, false)
                            .map_err(io_status)?;
                        let m = f.metadata().map_err(io_status)?;
                        if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.nlink() != 1 {
                            return Err(Status::Invalid);
                        }
                        if m.len() > self.limits.max_record_bytes as u64 {
                            self.issue(&p, "record_budget");
                            return Err(Status::Unknown);
                        }
                        let cap = self
                            .limits
                            .max_record_bytes
                            .min(self.limits.max_metadata_bytes.saturating_sub(self.bytes));
                        if m.len() > cap as u64 {
                            self.issue(&p, "metadata_budget");
                            self.stopped = true;
                            return Err(Status::Unknown);
                        }
                        let mut b = Vec::new();
                        f.take(cap as u64 + 1)
                            .read_to_end(&mut b)
                            .map_err(io_status)?;
                        if !self.charge(b.len(), &p) {
                            return Err(Status::Unknown);
                        }
                        if b.len() > cap {
                            self.issue(&p, "record_budget");
                            return Err(Status::Unknown);
                        }
                        serde_json::from_slice(&b).map_err(|_| Status::Invalid)
                    })()?;
                    let valid = {
                        let v = value;
                        if name == "oci-layout" {
                            v["imageLayoutVersion"] == "1.0.0"
                        } else {
                            v["schemaVersion"] == 2
                                && v["manifests"].as_array().is_some_and(|a| {
                                    !a.is_empty()
                                        && a.iter().all(|d| {
                                            d["digest"]
                                                .as_str()
                                                .and_then(|s| s.strip_prefix("sha256:"))
                                                .is_some_and(hex)
                                                && d["size"].as_u64().is_some()
                                                && d["mediaType"].as_str().is_some()
                                        })
                                })
                        }
                    };
                    if !valid {
                        return Err(Status::Invalid);
                    }
                }
                if self.stop() {
                    return Err(Status::Unknown);
                }
                let blobs =
                    open(dir.as_raw_fd(), Path::new("blobs"), true, false).map_err(io_status)?;
                owned_dir(&blobs).map_err(io_status)?;
                if self.stop() {
                    return Err(Status::Unknown);
                }
                let sha256 =
                    open(blobs.as_raw_fd(), Path::new("sha256"), true, false).map_err(io_status)?;
                owned_dir(&sha256).map_err(io_status)?;
                Ok(())
            })();
            match result {
                Ok(()) => Status::Complete,
                Err(status) => {
                    if status == Status::Invalid {
                        self.diagnostic(path, "invalid_layout");
                    } else {
                        self.issue(path, "incomplete_layout");
                    }
                    status
                }
            }
        }
        fn usage(&mut self, dir: &File, path: &Path, depth: usize) {
            if self.stop() {
                return;
            }
            if depth > self.limits.max_depth {
                self.issue(path, "depth_budget");
                return;
            }
            for name in self.names(dir, path) {
                if self.stop() {
                    break;
                }
                let p = path.join(&name);
                if depth >= self.limits.max_depth {
                    self.issue(&p, "depth_budget");
                    continue;
                }
                // Metadata lookup does not follow links. Subsequent opens remain
                // constrained by the pinned parent and openat2.
                let n = CString::new(name.as_bytes()).unwrap();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe {
                    libc::fstatat(
                        dir.as_raw_fd(),
                        n.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    self.issue(&p, "metadata_failed");
                    continue;
                }
                if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                    if let Some(child) = self.dir(dir, Path::new(&name), &p) {
                        self.usage(&child, &p, depth + 1);
                    }
                } else if st.st_mode & libc::S_IFMT == libc::S_IFREG {
                    // Resolve even regular-file mounts with NO_XDEV before counting.
                    if let Ok(f) = open(dir.as_raw_fd(), Path::new(&name), false, false) {
                        if let Ok(m) = f.metadata() {
                            if !m.is_file() {
                                self.issue(&p, "changed_file");
                                continue;
                            }
                            fn count(
                                u: &mut Usage,
                                seen: &mut HashSet<(u64, u64)>,
                                m: &std::fs::Metadata,
                            ) {
                                u.files = u.files.saturating_add(1);
                                u.logical_bytes = u.logical_bytes.saturating_add(m.len());
                                if seen.insert((m.dev(), m.ino())) {
                                    u.unique_logical_bytes =
                                        u.unique_logical_bytes.saturating_add(m.len());
                                    u.allocated_bytes = u
                                        .allocated_bytes
                                        .saturating_add(m.blocks().saturating_mul(512));
                                } else {
                                    u.shared_hardlink_paths += 1;
                                }
                            }
                            count(&mut self.out.usage, &mut self.seen, &m);
                            if path.starts_with("cache-v1") || path.starts_with("base-cache-v1") {
                                count(&mut self.out.cache_usage, &mut self.cache_seen, &m);
                            } else {
                                count(&mut self.out.builds_usage, &mut self.builds_seen, &m);
                            }
                        } else {
                            self.issue(&p, "metadata_failed");
                        }
                    } else {
                        self.issue(&p, "unsafe_or_unreadable_file");
                    }
                } else {
                    self.issue(&p, "symlink_or_special_file_skipped");
                }
            }
        }
        fn area(&mut self, root: &File, name: &Path) {
            // Classification looks two levels into an OCI layout. A shallower
            // budget cannot establish that structure, so leave the area unknown.
            if self.limits.max_depth < 5 {
                self.issue(name, "depth_budget");
                return;
            }
            let Some(dir) = self.dir(root, name, name) else {
                return;
            };
            for child in self.names(&dir, name) {
                if self.stop() {
                    break;
                }
                let p = name.join(&child);
                let s = child.to_str().unwrap_or("");
                if name == Path::new("cache-v1") && (hex(s) || s.starts_with(".publish-")) {
                    let d = self.dir(&dir, Path::new(&child), &p);
                    let status = if s.starts_with(".publish-") {
                        Status::Temporary
                    } else {
                        d.as_ref().map_or(Status::Unknown, |d| self.layout(d, &p))
                    };
                    self.out
                        .stages
                        .push(entry(p.clone(), status, Ownership::Managed));
                    if let Some(d) = d {
                        self.usage(&d, &p, 2);
                    }
                } else if name == Path::new("base-cache-v1") && ["refs", "generations"].contains(&s)
                {
                    let Some(d) = self.dir(&dir, Path::new(&child), &p) else {
                        self.refs_uncertain = true;
                        continue;
                    };
                    for item in self.names(&d, &p) {
                        if self.stop() {
                            break;
                        }
                        let q = p.join(&item);
                        let t = item.to_str().unwrap_or("");
                        if s == "refs" && t.ends_with(".json") && hex(t.trim_end_matches(".json")) {
                            self.base_ref(&d, Path::new(&item), &q);
                        } else if s == "generations" && generation(t) {
                            let g = self.dir(&d, Path::new(&item), &q);
                            let status =
                                match g.as_ref().map_or(Status::Unknown, |g| self.layout(g, &q)) {
                                    Status::Complete => Status::Orphan,
                                    status => status,
                                };
                            self.out
                                .generations
                                .push(entry(q.clone(), status, Ownership::Managed));
                            if let Some(g) = g {
                                self.usage(&g, &q, 3);
                            }
                        } else {
                            self.out.protected_entries.push(entry(
                                q,
                                Status::Protected,
                                Ownership::Unknown,
                            ));
                        }
                    }
                } else if name == Path::new("base-cache-v1")
                    && (s == "content" || s.starts_with("staging-"))
                {
                    self.out.protected_entries.push(entry(
                        p.clone(),
                        if s == "content" {
                            Status::Present
                        } else {
                            Status::Temporary
                        },
                        Ownership::Managed,
                    ));
                    if let Some(d) = self.dir(&dir, Path::new(&child), &p) {
                        self.usage(&d, &p, 2);
                    }
                } else {
                    self.out.protected_entries.push(entry(
                        p,
                        Status::Protected,
                        Ownership::Unknown,
                    ));
                }
            }
        }
    }
    pub(super) fn inspect(
        store: &Path,
        limits: Limits,
        cancel: &dyn Fn() -> bool,
    ) -> io::Result<Inventory> {
        if !store.is_absolute()
            || store
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(io::Error::other(
                "store must be absolute without parent components",
            ));
        }
        let mut scan = Scan {
            out: Inventory {
                store: store.into(),
                status: Status::Present,
                best_effort: true,
                partial: false,
                scan_complete: true,
                issues_truncated: false,
                tags: vec![],
                base_refs: vec![],
                generations: vec![],
                stages: vec![],
                builds: vec![],
                protected_entries: vec![],
                usage: Usage::default(),
                cache_usage: Usage::default(),
                builds_usage: Usage::default(),
                issues: vec![],
            },
            limits,
            cancel,
            entries: 0,
            bytes: 0,
            stopped: false,
            seen: HashSet::new(),
            cache_seen: HashSet::new(),
            builds_seen: HashSet::new(),
            refs_uncertain: false,
        };
        if scan.stop() {
            return Ok(scan.out);
        }
        let root = match open(libc::AT_FDCWD, store, true, true) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                scan.out.status = Status::Missing;
                return Ok(scan.out);
            }
            Err(e) => return Err(e),
        };
        owned_dir(&root)?;
        if root.metadata()?.mode() & 0o077 != 0 {
            return Err(io::Error::other("store must have mode 0700"));
        }
        for name in scan.names(&root, Path::new("")) {
            if scan.stop() {
                break;
            }
            let p = Path::new(&name);
            let s = name.to_str().unwrap_or("");
            if s.starts_with("tag-") && s.ends_with(".json") && hex(&s[4..s.len() - 5]) {
                scan.tag(&root, p);
            } else if ["base-cache-v1", "cache-v1"].contains(&s) {
                scan.area(&root, p);
            } else if s.starts_with("build-") {
                let mut build = entry(p.into(), Status::LegacyUnknown, Ownership::Unknown);
                if scan.limits.max_depth >= 2
                    && let Some(d) = scan.dir(&root, p, p)
                {
                    let record_path = p.join(crate::build_record::FILE);
                    let missing = open(
                        d.as_raw_fd(),
                        Path::new(crate::build_record::FILE),
                        false,
                        false,
                    )
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound);
                    let limit = scan.limits.max_record_bytes;
                    scan.limits.max_record_bytes = limit.min(crate::build_record::MAX_BYTES);
                    let record = if missing {
                        None
                    } else {
                        scan.record::<crate::build_record::Record>(
                            &d,
                            Path::new(crate::build_record::FILE),
                            &record_path,
                        )
                    };
                    scan.limits.max_record_bytes = limit;
                    if let Some(record) = record {
                        if record
                            .validate(&root, &d, p, |depth| {
                                if scan.stop() {
                                    return Err(io::Error::other("cancelled"));
                                }
                                if depth > scan.limits.max_depth {
                                    scan.issue(p, "depth_budget");
                                    return Err(io::Error::other("depth budget"));
                                }
                                if scan.entries >= scan.limits.max_entries {
                                    scan.issue(p, "entry_budget");
                                    scan.stopped = true;
                                    return Err(io::Error::other("entry budget"));
                                }
                                scan.entries += 1;
                                Ok(())
                            })
                            .is_ok()
                        {
                            build.status = Status::Present;
                            build.ownership = Ownership::Managed;
                            build.build_record = Some(record);
                        } else {
                            scan.issue(&record_path, "invalid_build_identity");
                        }
                    }
                }
                scan.out.builds.push(build);
                if scan.limits.max_depth == 0 {
                    scan.issue(p, "depth_budget");
                } else if let Some(d) = scan.dir(&root, p, p) {
                    scan.usage(&d, p, 1);
                }
            } else {
                scan.out.protected_entries.push(entry(
                    p.into(),
                    Status::Protected,
                    Ownership::Unknown,
                ));
            }
        }
        for r in &mut scan.out.base_refs {
            if let Some(g) = &r.generation {
                if let Some(e) = scan
                    .out
                    .generations
                    .iter_mut()
                    .find(|e| e.path.file_name().is_some_and(|n| n == g.as_str()))
                {
                    if matches!(e.status, Status::Orphan | Status::Current) {
                        e.status = Status::Current;
                    } else {
                        r.status = e.status;
                    }
                } else {
                    r.status = if scan.out.partial {
                        Status::Unknown
                    } else {
                        Status::Missing
                    };
                }
            }
        }
        if scan.refs_uncertain || scan.out.partial {
            for e in &mut scan.out.generations {
                if e.status == Status::Orphan {
                    e.status = Status::Unknown;
                }
            }
        }
        Ok(scan.out)
    }

    #[test]
    fn suppressed_failures_still_invalidate_completion() {
        let temp = tempfile::tempdir().unwrap();
        for code in [
            "cancelled",
            "metadata_budget",
            "entry_budget",
            "metadata_failed",
        ] {
            let cancel = || code == "cancelled";
            let mut scan = Scan {
                out: inspect(&temp.path().join("missing"), Limits::default(), &|| false).unwrap(),
                limits: Limits::default(),
                cancel: &cancel,
                entries: 0,
                bytes: 0,
                stopped: false,
                seen: HashSet::new(),
                cache_seen: HashSet::new(),
                builds_seen: HashSet::new(),
                refs_uncertain: false,
            };
            for _ in 0..1024 {
                scan.issue(
                    Path::new("build-test/work/link"),
                    "symlink_or_special_file_skipped",
                );
            }
            assert!(scan.out.scan_complete);
            assert!(!scan.out.issues_truncated);
            match code {
                "cancelled" => assert!(scan.stop()),
                "metadata_budget" => assert!(!scan.charge(usize::MAX, Path::new("cache-v1"))),
                "entry_budget" => {
                    scan.entries = scan.limits.max_entries;
                    std::fs::write(temp.path().join("entry"), b"").unwrap();
                    let dir = File::open(temp.path()).unwrap();
                    assert!(scan.names(&dir, Path::new("cache-v1")).is_empty());
                }
                _ => scan.issue(Path::new("cache-v1/file"), code),
            }
            assert!(scan.out.partial);
            assert!(!scan.out.scan_complete, "{code}");
            assert!(scan.out.issues_truncated, "{code}");
            assert_eq!(scan.out.issues.len(), 1024);
            assert!(
                scan.out
                    .issues
                    .iter()
                    .all(|i| i.code == "symlink_or_special_file_skipped")
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn every_inventory_path_serializes_losslessly() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"non-utf8-\xff".to_vec()));
        let temp = store();
        let mut inventory = run(&temp.path().join("missing"));
        inventory.store = path.clone();
        let entry = Entry {
            build_record: None,
            path: path.clone(),
            status: Status::Unknown,
            ownership: Ownership::Unknown,
            protected: true,
        };
        inventory.tags.push(Tag {
            record: path.clone(),
            reference: None,
            image: Some(path.clone()),
            status: Status::Unknown,
            ownership: Ownership::Unknown,
            target_status: Status::Unknown,
        });
        inventory.base_refs.push(BaseRef {
            record: path.clone(),
            reference: None,
            generation: None,
            status: Status::Unknown,
        });
        inventory.generations.push(entry.clone());
        inventory.stages.push(entry.clone());
        inventory.builds.push(entry.clone());
        inventory.protected_entries.push(entry);
        inventory.issues.push(Issue {
            path,
            code: "test".into(),
        });
        let value = serde_json::to_value(&inventory).unwrap();
        let expected = serde_json::json!({"unix_bytes": b"non-utf8-\xff".as_slice()});
        for pointer in [
            "/store",
            "/tags/0/record",
            "/tags/0/image",
            "/base_refs/0/record",
            "/generations/0/path",
            "/stages/0/path",
            "/builds/0/path",
            "/protected_entries/0/path",
            "/issues/0/path",
        ] {
            assert_eq!(value.pointer(pointer), Some(&expected), "{pointer}");
        }
        inventory.tags[0].image = None;
        assert!(serde_json::to_value(&inventory).unwrap()["tags"][0]["image"].is_null());
    }
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };

    fn store() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        t
    }
    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn run(path: &Path) -> Inventory {
        inspect(path, Limits::default(), || false).unwrap()
    }
    fn tag(root: &Path, reference: &str, image: &Path) {
        let name = format!("tag-{:x}.json", Sha256::digest(reference));
        write(
            &root.join(name),
            &serde_json::to_vec(&serde_json::json!({"reference":reference,"image":image})).unwrap(),
        );
    }
    fn layout(path: &Path) {
        fs::create_dir_all(path.join("blobs/sha256")).unwrap();
        write(
            &path.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        );
        write(&path.join("index.json"), &serde_json::to_vec(&serde_json::json!({
            "schemaVersion":2,"manifests":[{"digest":format!("sha256:{}", "a".repeat(64)),"size":1,"mediaType":"test"}]
        })).unwrap());
    }
    struct Watch(fs::File);
    impl Watch {
        fn new(path: &Path, mask: u32) -> Self {
            use std::{
                ffi::CString,
                os::{
                    fd::{AsRawFd, FromRawFd},
                    unix::ffi::OsStrExt,
                },
            };
            let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            assert!(fd >= 0);
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert!(unsafe { libc::inotify_add_watch(file.as_raw_fd(), path.as_ptr(), mask) } >= 0);
            Self(file)
        }
        fn observed(&self) -> bool {
            use std::io::Read;
            match (&self.0).read(&mut [0; 4096]) {
                Ok(n) => n > 0,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(e) => panic!("inotify read failed: {e}"),
            }
        }
    }
    #[test]
    fn hardlinked_oci_metadata_is_rejected_before_reading() {
        for name in ["oci-layout", "index.json"] {
            let t = store();
            let p = t.path().join("cache-v1").join("a".repeat(64));
            layout(&p);
            // Keep valid metadata: rejection must precede parsing, not depend on it.
            let auth = t.path().join("storeauth.json");
            fs::rename(p.join(name), &auth).unwrap();
            let mut metadata: serde_json::Value =
                serde_json::from_slice(&fs::read(&auth).unwrap()).unwrap();
            metadata["credential"] = "SECRET_CREDENTIAL".into();
            write(&auth, &serde_json::to_vec(&metadata).unwrap());
            fs::hard_link(&auth, p.join(name)).unwrap();
            let watch = Watch::new(&auth, libc::IN_ACCESS);
            let i = run(t.path());
            assert!(!watch.observed(), "read hardlinked {name}");
            assert_eq!(i.stages[0].status, Status::Invalid);
            assert!(i.issues.iter().any(|e| e.code == "invalid_layout"));
            assert!(
                !serde_json::to_string(&i)
                    .unwrap()
                    .contains("SECRET_CREDENTIAL")
            );
        }
    }
    #[test]
    fn shared_oci_blobs_are_counted_without_reading() {
        let t = store();
        let p = t.path().join("cache-v1").join("a".repeat(64));
        layout(&p);
        let blob = p.join("blobs/sha256/a");
        write(&blob, b"SECRET_BLOB");
        fs::hard_link(&blob, p.join("blobs/sha256/b")).unwrap();
        let watch = Watch::new(&blob, libc::IN_ACCESS);
        let i = run(t.path());
        assert_eq!(i.stages[0].status, Status::Complete);
        assert_eq!(i.cache_usage.shared_hardlink_paths, 1);
        assert_eq!(
            i.cache_usage.logical_bytes - i.cache_usage.unique_logical_bytes,
            11
        );
        assert!(!watch.observed());
        assert!(!serde_json::to_string(&i).unwrap().contains("SECRET_BLOB"));
    }
    #[test]
    fn incomplete_layouts_are_unknown_for_budgets_and_cancellation() {
        for relative in [
            format!("cache-v1/{}", "a".repeat(64)),
            "base-cache-v1/generations/gen-valid".into(),
        ] {
            let t = store();
            let p = t.path().join(&relative);
            layout(&p);
            let mut found = false;
            for budget in (300..700).step_by(10) {
                let i = inspect(
                    t.path(),
                    Limits {
                        max_metadata_bytes: budget,
                        ..Limits::default()
                    },
                    || false,
                )
                .unwrap();
                let entries: Vec<_> = i.stages.iter().chain(&i.generations).collect();
                assert!(entries.iter().all(|e| e.status != Status::Invalid));
                if entries.iter().any(|e| e.status == Status::Unknown)
                    && i.issues.iter().any(|e| e.code == "incomplete_layout")
                {
                    assert!(i.partial);
                    assert!(i.issues.iter().any(|e| e.code == "metadata_budget"));
                    found = true;
                    break;
                }
            }
            assert!(found, "budget never interrupted {relative}");
            // Cancel precisely after the first metadata read, inside layout().
            let watch = Watch::new(&p.join("oci-layout"), libc::IN_ACCESS);
            let i = inspect(t.path(), Limits::default(), || watch.observed()).unwrap();
            let e = i.stages.iter().chain(&i.generations).next().unwrap();
            assert_eq!(e.status, Status::Unknown);
            assert!(i.issues.iter().any(|e| e.code == "cancelled"));
            assert!(i.issues.iter().any(|e| e.code == "incomplete_layout"));
            assert!(!i.issues.iter().any(|e| e.code == "invalid_layout"));
        }
    }
    #[test]
    fn depth_limit_precedes_child_access() {
        let t = store();
        let child = t.path().join("build-old/child");
        fs::create_dir_all(&child).unwrap();
        write(&child.join("secret"), b"SECRET");
        symlink("missing", t.path().join("build-old/link")).unwrap();
        let watch = Watch::new(&child, libc::IN_OPEN | libc::IN_ACCESS);
        let i = inspect(
            t.path(),
            Limits {
                max_depth: 1,
                ..Limits::default()
            },
            || false,
        )
        .unwrap();
        assert!(!watch.observed());
        assert_eq!(i.usage.files, 0);
        assert_eq!(i.issues.len(), 2);
        assert!(i.issues.iter().all(|e| e.code == "depth_budget"));
        assert!(
            i.issues
                .iter()
                .any(|e| e.path == Path::new("build-old/link"))
        );
    }
    #[test]
    fn referenced_generation_with_incomplete_metadata_stays_unknown() {
        let t = store();
        let base = t.path().join("base-cache-v1");
        let p = base.join("generations/gen-valid");
        layout(&p);
        let mut index = fs::read(p.join("index.json")).unwrap();
        index.resize(2048, b' ');
        write(&p.join("index.json"), &index);
        fs::create_dir_all(base.join("refs")).unwrap();
        let reference = "example/app:latest";
        let key = format!(
            "{:x}.json",
            Sha256::digest(format!("{reference}\nlinux/amd64"))
        );
        write(&base.join("refs").join(key), &serde_json::to_vec(&serde_json::json!({
            "version":1,"reference":reference,"platform":"linux/amd64","source_digest":null,
            "generation":"gen-valid","selected":{"digest":format!("sha256:{}", "a".repeat(64)),"size":1,"mediaType":"test"}
        })).unwrap());
        let i = inspect(
            t.path(),
            Limits {
                max_record_bytes: 1024,
                ..Limits::default()
            },
            || false,
        )
        .unwrap();
        assert_eq!(i.generations[0].status, Status::Unknown);
        assert_eq!(i.base_refs[0].status, Status::Unknown);
        assert!(i.issues.iter().any(|e| e.code == "record_budget"));
        assert!(!i.issues.iter().any(|e| e.code == "invalid_layout"));
    }
    #[test]
    fn missing_store_creates_nothing() {
        let t = store();
        let p = t.path().join("missing/nested");
        let i = run(&p);
        assert_eq!(i.status, Status::Missing);
        assert!(i.tags.is_empty());
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 0);
    }
    #[test]
    fn external_canaries_and_symlinks_are_not_traversed() {
        let t = store();
        let external = store();
        write(&external.path().join("canary"), b"DO_NOT_READ_SECRET");
        tag(t.path(), "example/app:tag", external.path());
        fs::create_dir(t.path().join("build-old")).unwrap();
        symlink(external.path(), t.path().join("build-old/escape")).unwrap();
        symlink(external.path(), t.path().join("cache-v1")).unwrap();
        let i = run(t.path());
        assert_eq!(i.tags[0].ownership, Ownership::External);
        assert_eq!(i.tags[0].target_status, Status::Unknown);
        assert_eq!(i.usage.files, 0);
        assert!(i.partial);
        assert!(
            !serde_json::to_string(&i)
                .unwrap()
                .contains("DO_NOT_READ_SECRET")
        );
        assert!(inspect(&t.path().join("cache-v1"), Limits::default(), || false).is_err());
    }
    #[test]
    fn internal_tag_does_not_prove_ownership() {
        let t = store();
        tag(t.path(), "exact:Tag", &t.path().join("output"));
        let i = run(t.path());
        assert_eq!(
            i.image_inspect("exact:Tag").unwrap().ownership,
            Ownership::Unknown
        );
        assert!(i.image_inspect("exact:tag").is_none());
    }
    #[test]
    fn malformed_and_oversized_records_are_bounded_and_redacted() {
        let t = store();
        write(
            &t.path().join(format!("tag-{}.json", "a".repeat(64))),
            b"{SECRET",
        );
        write(
            &t.path().join(format!("tag-{}.json", "b".repeat(64))),
            &vec![b'X'; 2048],
        );
        write(&t.path().join("auth.json"), b"SECRET_CREDENTIAL");
        let i = inspect(
            t.path(),
            Limits {
                max_record_bytes: 1024,
                ..Limits::default()
            },
            || false,
        )
        .unwrap();
        assert_eq!(i.tags.len(), 2);
        assert!(
            i.tags
                .iter()
                .all(|t| t.status == Status::Invalid && t.reference.is_none())
        );
        assert_eq!(i.protected_entries.len(), 1);
        assert!(!serde_json::to_string(&i).unwrap().contains("SECRET"));
    }
    #[test]
    fn physical_hardlink_accounting_and_legacy_protection() {
        let t = store();
        fs::create_dir(t.path().join("build-old")).unwrap();
        let p = t.path().join("build-old/a");
        write(&p, &[1; 8192]);
        fs::hard_link(&p, t.path().join("build-old/b")).unwrap();
        let i = run(t.path());
        assert_eq!(i.usage.logical_bytes, 16384);
        assert_eq!(i.usage.unique_logical_bytes, 8192);
        assert_eq!(
            i.usage.allocated_bytes,
            fs::metadata(&p).unwrap().blocks() * 512
        );
        assert_eq!(i.usage.shared_hardlink_paths, 1);
        assert_eq!(
            i.build_inspect("build-old").unwrap().status,
            Status::LegacyUnknown
        );
        assert!(i.builds[0].protected);
        assert_eq!(i.builds[0].ownership, Ownership::Unknown);
    }
    #[test]
    fn budgets_and_cancellation_are_explicit() {
        let t = store();
        fs::create_dir_all(t.path().join("build-old/a/b/c")).unwrap();
        write(&t.path().join("build-old/a/b/c/file"), b"data");
        for limits in [
            Limits {
                max_entries: 0,
                ..Limits::default()
            },
            Limits {
                max_depth: 0,
                ..Limits::default()
            },
            Limits {
                max_metadata_bytes: 1,
                ..Limits::default()
            },
        ] {
            let i = inspect(t.path(), limits, || false).unwrap();
            assert!(i.partial);
            assert_eq!(i.usage.files, 0);
        }
        let i = inspect(t.path(), Limits::default(), || true).unwrap();
        assert!(i.partial);
        assert_eq!(i.issues[0].code, "cancelled");
    }
    #[test]
    fn base_current_orphan_missing_and_stage_states() {
        let t = store();
        let base = t.path().join("base-cache-v1");
        fs::create_dir_all(base.join("refs")).unwrap();
        layout(&base.join("generations/gen-current"));
        layout(&base.join("generations/gen-unreferenced"));
        for (reference, generation) in [
            ("docker.io/library/a:latest", "gen-current"),
            ("docker.io/library/b:latest", "gen-missing"),
        ] {
            let key = format!(
                "{:x}.json",
                Sha256::digest(format!("{reference}\nlinux/amd64"))
            );
            write(&base.join("refs").join(key), &serde_json::to_vec(&serde_json::json!({
                "version":1,"reference":reference,"platform":"linux/amd64","source_digest":null,
                "generation":generation,"selected":{"digest":format!("sha256:{}", "a".repeat(64)),"size":1,"mediaType":"test"}
            })).unwrap());
        }
        layout(&t.path().join("cache-v1").join("a".repeat(64)));
        fs::create_dir(t.path().join("cache-v1").join("b".repeat(64))).unwrap();
        fs::create_dir(t.path().join("cache-v1/.publish-test")).unwrap();
        let i = run(t.path());
        assert!(i.generations.iter().any(|g| g.status == Status::Current));
        assert!(i.generations.iter().any(|g| g.status == Status::Orphan));
        assert!(i.base_refs.iter().any(|r| r.status == Status::Missing));
        for status in [Status::Complete, Status::Invalid, Status::Temporary] {
            assert!(i.stages.iter().any(|s| s.status == status));
        }
        assert!(i.generations.iter().all(|g| g.protected));
    }
    #[test]
    fn unsafe_store_and_unknown_directories_are_not_scanned() {
        let t = store();
        fs::create_dir(t.path().join("credentials")).unwrap();
        write(&t.path().join("credentials/private"), b"secret");
        let i = run(t.path());
        assert_eq!(i.usage.files, 0);
        assert_eq!(i.protected_entries.len(), 1);
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(inspect(t.path(), Limits::default(), || false).is_err());
    }

    #[test]
    fn malformed_ref_prevents_orphan_claim() {
        let t = store();
        let base = t.path().join("base-cache-v1");
        fs::create_dir_all(base.join("refs")).unwrap();
        layout(&base.join("generations/gen-unreferenced"));
        write(
            &base.join("refs").join(format!("{}.json", "a".repeat(64))),
            b"{}",
        );
        let i = run(t.path());
        assert_eq!(i.base_refs[0].status, Status::Invalid);
        assert_eq!(i.generations[0].status, Status::Unknown);
    }

    #[test]
    #[ignore = "run in an isolated user/mount namespace with CAP_SYS_ADMIN"]
    fn same_device_bind_mount_is_not_traversed() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        // Never mount into the invoking process's namespace, even when root.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0
        );
        let t = store();
        let outside = store();
        write(&outside.path().join("canary"), b"secret");
        fs::create_dir_all(t.path().join("build-old/mounted")).unwrap();
        let source = CString::new(outside.path().as_os_str().as_bytes()).unwrap();
        let target =
            CString::new(t.path().join("build-old/mounted").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0
        );
        struct Mount(CString);
        impl Drop for Mount {
            fn drop(&mut self) {
                unsafe {
                    libc::umount2(self.0.as_ptr(), libc::MNT_DETACH);
                }
            }
        }
        let _mount = Mount(target);
        assert_eq!(
            fs::metadata(outside.path()).unwrap().dev(),
            fs::metadata(t.path()).unwrap().dev()
        );
        let i = run(t.path());
        assert_eq!(i.usage.files, 0);
        assert!(i.partial);
        assert!(
            i.issues
                .iter()
                .any(|e| e.path == Path::new("build-old/mounted"))
        );
    }
}
