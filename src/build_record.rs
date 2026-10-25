//! Conservative ownership evidence, never deletion authorization.
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

pub const FILE: &str = "build-record.json";
pub const MAX_BYTES: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Component(String);
impl TryFrom<String> for Component {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty()
            || s.len() > 128
            || s == "."
            || s == ".."
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err("invalid component");
        }
        Ok(Self(s))
    }
}
impl From<Component> for String {
    fn from(c: Component) -> Self {
        c.0
    }
}
impl Component {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Building,
    ImageReady,
    Complete,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushResult {
    NotRequested,
    Pending,
    Succeeded,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owned {
    pub components: Vec<Component>,
    pub identity: Identity,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct External {
    pub role: String,
    pub unix_bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    pub run_id: Component,
    pub store: Identity,
    pub run: Identity,
    pub phase: Phase,
    pub owned: Vec<Owned>,
    pub external: Vec<External>,
    pub manifest: Option<crate::oci::Descriptor>,
    pub references: Vec<String>,
    pub push: PushResult,
}
// The directory descriptor is pinned; the borrow passed to every write proves a live lease.
#[derive(Debug)]
pub struct BuildRecord {
    pub path: PathBuf,
    #[cfg(target_os = "linux")]
    dir: std::fs::File,
    pub record: Record,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    allowed: Vec<PathBuf>,
}
#[cfg(target_os = "linux")]
pub fn identity(m: &std::fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    Identity {
        device: m.dev(),
        inode: m.ino(),
    }
}
#[cfg(target_os = "linux")]
pub fn open_dir(parent: i32, path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = How {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x02
            | 0x04
            | if parent == libc::AT_FDCWD {
                0
            } else {
                0x01 | 0x08
            },
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            path.as_ptr(),
            &how,
            std::mem::size_of::<How>(),
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_fd(fd as i32) })
    }
}
impl Record {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn validate_shape(&self) -> std::io::Result<()> {
        let invalid = || std::io::Error::other("invalid build record");
        if self.version != 1
            || !self.run_id.as_str().starts_with("build-")
            || self.run_id.as_str().len() <= 6
            || self.owned.len() > 4096
            || self.external.len() > 2
            || self.references.len() > 128
        {
            return Err(invalid());
        }
        if matches!(self.phase, Phase::ImageReady | Phase::Complete) != self.manifest.is_some()
            || (self.phase == Phase::Preparing && !self.owned.is_empty())
            || (self.push == PushResult::Succeeded
                && !matches!(self.phase, Phase::ImageReady | Phase::Complete))
            || (self.push == PushResult::Failed && self.phase != Phase::ImageReady)
            || (self.phase == Phase::Complete && self.push == PushResult::Pending)
        {
            return Err(invalid());
        }
        if let Some(m) = &self.manifest {
            let digest = m.digest.strip_prefix("sha256:").ok_or_else(invalid)?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || m.size < 0
                || m.media_type != "application/vnd.oci.image.manifest.v1+json"
            {
                return Err(invalid());
            }
        }
        if self.references.iter().any(|r| {
            r.is_empty()
                || r.len() > 4096
                || r.contains("://")
                || r.chars().any(|c| c.is_control() || c.is_whitespace())
        }) {
            return Err(invalid());
        }
        let mut roles = std::collections::HashSet::new();
        for e in &self.external {
            if !["work", "image"].contains(&e.role.as_str())
                || !roles.insert(e.role.as_str())
                || e.unix_bytes.is_empty()
                || e.unix_bytes.contains(&0)
            {
                return Err(invalid());
            }
        }
        let mut paths = std::collections::HashSet::new();
        for o in &self.owned {
            let parts: Vec<_> = o.components.iter().map(Component::as_str).collect();
            let valid = match parts.as_slice() {
                ["work"] | ["image"] => !roles.contains(parts[0]),
                ["stages"] => true,
                ["stages", stage] => stage
                    .strip_prefix("stage-")
                    .and_then(|s| s.strip_suffix("-work").or_else(|| s.strip_suffix("-image")))
                    .is_some_and(|s| {
                        !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())
                    }),
                _ => false,
            };
            if !valid || !paths.insert(parts.join("/")) {
                return Err(invalid());
            }
        }
        if paths.iter().any(|p| p.starts_with("stages/")) && !paths.contains("stages") {
            return Err(invalid());
        }
        if matches!(self.phase, Phase::ImageReady | Phase::Complete)
            && !roles.contains("image")
            && !paths.contains("image")
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
impl Record {
    pub fn validate(
        &self,
        store: &std::fs::File,
        run: &std::fs::File,
        name: &Path,
        mut check: impl FnMut(usize) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let run_meta = run.metadata()?;
        if run_meta.mode() & 0o077 != 0 || run_meta.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::other("nonprivate run"));
        }
        if self.version != 1
            || !self.run_id.as_str().starts_with("build-")
            || name != Path::new(self.run_id.as_str())
            || self.store != identity(&store.metadata()?)
            || self.run != identity(&run.metadata()?)
            || self.owned.len() > 4096
            || self.external.len() > 2
        {
            return Err(std::io::Error::other("record identity mismatch"));
        }
        self.validate_shape()?;
        let mut seen = std::collections::HashSet::new();
        for o in &self.owned {
            if o.components.is_empty() || o.components.len() > 3 {
                return Err(std::io::Error::other("invalid owned path"));
            }
            check(1 + o.components.len())?;
            let p: PathBuf = o.components.iter().map(|c| c.as_str()).collect();
            if !seen.insert(p.clone())
                || identity(&open_dir(run.as_raw_fd(), &p)?.metadata()?) != o.identity
            {
                return Err(std::io::Error::other("owned identity mismatch"));
            }
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
impl BuildRecord {
    pub fn allocate(
        store: &Path,
        lease: &crate::store_lease::StoreLease,
        work_external: Option<&Path>,
        output_external: Option<&Path>,
        references: Vec<String>,
        push: bool,
    ) -> std::io::Result<Self> {
        use std::os::{
            fd::AsRawFd,
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, PermissionsExt},
            },
        };
        crate::store_access::validate_root(store, lease)?;
        let root = open_dir(libc::AT_FDCWD, store)?;
        // Keep before recording: interruption leaves an unknown, protected run.
        let run = tempfile::Builder::new()
            .prefix("build-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(store)?
            .keep();
        let name = run
            .file_name()
            .ok_or_else(|| std::io::Error::other("missing run name"))?;
        if run.parent() != Some(store) {
            return Err(std::io::Error::other("run outside store"));
        }
        let dir = open_dir(root.as_raw_fd(), Path::new(name))?;
        let m = dir.metadata()?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(std::io::Error::other("run must be private"));
        }
        let run_id = Component::try_from(
            name.to_str()
                .ok_or_else(|| std::io::Error::other("invalid run name"))?
                .to_owned(),
        )
        .map_err(std::io::Error::other)?;
        let mut external = Vec::new();
        let mut allowed = vec![run.join("stages")];
        for (role, path) in [("work", work_external), ("image", output_external)] {
            if let Some(path) = path {
                external.push(External {
                    role: role.into(),
                    unix_bytes: path.as_os_str().as_bytes().to_vec(),
                });
            } else {
                allowed.push(run.join(role));
            }
        }
        let record = Record {
            version: 1,
            run_id,
            store: identity(&root.metadata()?),
            run: identity(&m),
            phase: Phase::Preparing,
            owned: vec![],
            external,
            manifest: None,
            references,
            push: if push {
                PushResult::Pending
            } else {
                PushResult::NotRequested
            },
        };
        let this = Self {
            path: run,
            dir,
            record,
            allowed,
        };
        this.write(lease, true)?;
        root.sync_all()?;
        Ok(this)
    }
    fn write(&self, lease: &crate::store_lease::StoreLease, initial: bool) -> std::io::Result<()> {
        use std::{io::Write, os::fd::AsRawFd};
        let id = lease.root_identity();
        if self.record.store
            != (Identity {
                device: id.device,
                inode: id.inode,
            })
            || self.record.run != identity(&self.dir.metadata()?)
        {
            return Err(std::io::Error::other("lease identity mismatch"));
        }
        self.record.validate_shape()?;
        let bytes = serde_json::to_vec(&self.record)?;
        if bytes.len() > MAX_BYTES {
            return Err(std::io::Error::other("record exceeds limit"));
        }
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd()));
        let mut temp = tempfile::Builder::new()
            .prefix(".build-record-")
            .tempfile_in(&pinned)?;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        if initial {
            temp.persist_noclobber(pinned.join(FILE))
                .map_err(|e| e.error)?;
        } else {
            temp.persist(pinned.join(FILE)).map_err(|e| e.error)?;
        }
        self.dir.sync_all()
    }
    pub fn update(
        &mut self,
        lease: &crate::store_lease::StoreLease,
        change: impl FnOnce(&mut Record),
    ) -> std::io::Result<()> {
        let before = self.record.clone();
        change(&mut self.record);
        if let Err(e) = self.write(lease, false) {
            self.record = before;
            return Err(e);
        }
        Ok(())
    }
    /// Called only immediately after the builder creates a fresh directory.
    pub(crate) fn created(
        &mut self,
        path: &Path,
        lease: &crate::store_lease::StoreLease,
    ) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        if !self
            .allowed
            .iter()
            .any(|p| path == p || (p == &self.path.join("stages") && path.parent() == Some(p)))
        {
            return Ok(());
        }
        let relative = path
            .strip_prefix(&self.path)
            .map_err(std::io::Error::other)?;
        let components = relative
            .iter()
            .map(|s| {
                Component::try_from(s.to_string_lossy().into_owned()).map_err(std::io::Error::other)
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let id = identity(&open_dir(self.dir.as_raw_fd(), relative)?.metadata()?);
        self.update(lease, |r| {
            r.owned.push(Owned {
                components,
                identity: id,
            })
        })
    }
}
