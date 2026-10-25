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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::store_lease::StoreLease;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Arc, Barrier},
    };

    #[test]
    fn updates_validate_durable_metadata_and_private_store_identity() {
        let store = tempfile::tempdir().unwrap();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let lease = StoreLease::shared(store.path(), &|| false).unwrap();
        let mut b = BuildRecord::allocate(store.path(), &lease, None, None, vec![], false).unwrap();
        let path = b.path.join(FILE);
        let original = std::fs::read(&path).unwrap();
        for case in [
            "permissions",
            "oversize",
            "malformed",
            "identity",
            "hardlink",
        ] {
            match case {
                "permissions" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "oversize" => std::fs::write(&path, vec![b' '; MAX_BYTES + 1]).unwrap(),
                "malformed" => std::fs::write(&path, b"{}").unwrap(),
                "identity" => {
                    let mut record = b.record.clone();
                    record.run.inode ^= 1;
                    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                _ => std::fs::hard_link(&path, b.path.join("alias")).unwrap(),
            }
            let before = std::fs::read(&path).unwrap();
            assert!(
                b.update(&lease, |r| r.phase = Phase::Building).is_err(),
                "{case}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before, "{case}");
            if case == "hardlink" {
                std::fs::remove_file(b.path.join("alias")).unwrap();
            }
            std::fs::write(&path, &original).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let other = tempfile::tempdir().unwrap();
        let other_lease = StoreLease::shared(other.path(), &|| false).unwrap();
        assert!(
            b.update(&other_lease, |r| r.store =
                identity(&std::fs::metadata(other.path()).unwrap()))
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        b.update(&lease, |r| r.phase = Phase::Building).unwrap();
    }

    #[test]
    fn concurrent_handles_refuse_stale_replacement() {
        let store = tempfile::tempdir().unwrap();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let lease = StoreLease::shared(store.path(), &|| false).unwrap();
        let first = BuildRecord::allocate(store.path(), &lease, None, None, vec![], false).unwrap();
        let second = BuildRecord {
            path: first.path.clone(),
            dir: first.dir.try_clone().unwrap(),
            root: first.root.try_clone().unwrap(),
            record: first.record.clone(),
            allowed: first.allowed.clone(),
            saved: first.saved.clone(),
        };
        let path = first.path.join(FILE);
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let handles = [first, second]
                .into_iter()
                .enumerate()
                .map(|(i, mut b)| {
                    let barrier = barrier.clone();
                    let lease = &lease;
                    scope.spawn(move || {
                        barrier.wait();
                        let result = b.update(lease, |r| {
                            r.phase = Phase::Building;
                            r.references.push(format!("example/test:{i}"));
                        });
                        (result, b)
                    })
                })
                .collect::<Vec<_>>();
            let results = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(results.iter().filter(|(r, _)| r.is_ok()).count(), 1);
            let (error, mut stale) = results.into_iter().find(|(r, _)| r.is_err()).unwrap();
            assert!(error.unwrap_err().to_string().contains("stale"));
            let durable = std::fs::read(&path).unwrap();
            // Public cached state cannot reset the private expected durable state.
            stale.record = serde_json::from_slice(&durable).unwrap();
            assert!(stale.update(&lease, |r| r.phase = Phase::Failed).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), durable);
            std::fs::remove_file(&path).unwrap();
            assert!(stale.update(&lease, |_| {}).is_err());
            assert!(!path.exists());
        });
    }
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
    /// Version 2 tombstones retain identity evidence without claiming live data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<Vec<Component>>,
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
    #[cfg(target_os = "linux")]
    root: std::fs::File,
    #[cfg(target_os = "linux")]
    saved: Vec<u8>,
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
    pub(crate) fn validate_shape(&self) -> std::io::Result<()> {
        let invalid = || std::io::Error::other("invalid build record");
        if ![1, 2].contains(&self.version)
            || (self.version == 1 && !self.removed.is_empty())
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
        let mut removed = std::collections::HashSet::new();
        for parts in &self.removed {
            let path = parts
                .iter()
                .map(Component::as_str)
                .collect::<Vec<_>>()
                .join("/");
            if path == "stages"
                || !removed.insert(path)
                || !self.owned.iter().any(|o| o.components == *parts)
            {
                return Err(invalid());
            }
        }
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
        if ![1, 2].contains(&self.version)
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
            if self.removed.contains(&o.components) {
                // Any replacement, including a dangling link, is unknown data.
                let pinned = PathBuf::from(format!("/proc/self/fd/{}", run.as_raw_fd()));
                if !std::fs::symlink_metadata(pinned.join(&p))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    return Err(std::io::Error::other("removed component reappeared"));
                }
                continue;
            }
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
            removed: vec![],
            external,
            manifest: None,
            references,
            push: if push {
                PushResult::Pending
            } else {
                PushResult::NotRequested
            },
        };
        let mut this = Self {
            path: run,
            dir,
            record,
            allowed,
            root,
            saved: Vec::new(),
        };
        this.write(lease, true)?;
        this.root.sync_all()?;
        Ok(this)
    }
    fn write(
        &mut self,
        lease: &crate::store_lease::StoreLease,
        initial: bool,
    ) -> std::io::Result<()> {
        use std::{
            io::{Read, Write},
            os::{
                fd::AsRawFd,
                unix::fs::{MetadataExt, OpenOptionsExt},
            },
        };
        // Independent open descriptions serialize writers even under shared store leases.
        let lock = open_dir(self.dir.as_raw_fd(), Path::new("."))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let id = lease.root_identity();
        if self.record.store
            != (Identity {
                device: id.device,
                inode: id.inode,
            })
            || self.record.store != identity(&self.root.metadata()?)
            || self.record.run != identity(&self.dir.metadata()?)
        {
            return Err(std::io::Error::other("lease identity mismatch"));
        }
        self.record.validate_shape()?;
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd()));
        if !initial {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(pinned.join(FILE))?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.len() > MAX_BYTES as u64
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o077 != 0
            {
                return Err(std::io::Error::other("unsafe build record"));
            }
            let mut data = Vec::new();
            file.take(MAX_BYTES as u64 + 1).read_to_end(&mut data)?;
            if data.len() > MAX_BYTES {
                return Err(std::io::Error::other("record exceeds limit"));
            }
            let durable: Record = serde_json::from_slice(&data)?;
            durable.validate(
                &self.root,
                &self.dir,
                Path::new(durable.run_id.as_str()),
                |_| Ok(()),
            )?;
            if durable.version != 1 {
                return Err(std::io::Error::other("cleaned build cannot be resumed"));
            }
            if serde_json::to_vec(&durable)? != self.saved {
                return Err(std::io::Error::other("stale build record"));
            }
            if self.record.version != 1 || self.record.run_id != durable.run_id {
                return Err(std::io::Error::other(
                    "build record identity or version changed",
                ));
            }
        }
        let bytes = serde_json::to_vec(&self.record)?;
        if bytes.len() > MAX_BYTES {
            return Err(std::io::Error::other("record exceeds limit"));
        }
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
        self.dir.sync_all()?;
        self.saved = bytes;
        Ok(())
    }
    pub fn update(
        &mut self,
        lease: &crate::store_lease::StoreLease,
        change: impl FnOnce(&mut Record),
    ) -> std::io::Result<()> {
        if self.record.version != 1 {
            return Err(std::io::Error::other("cleaned build cannot be resumed"));
        }
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
