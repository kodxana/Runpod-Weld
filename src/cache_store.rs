//! Owned checkpoint layouts. All writers retain a shared store lease and keep
//! published inodes immutable; maintenance must hold the exclusive store lease.
//! Unknown/pre-protocol directories are never adopted. No deletion API lives here.
use crate::{
    build::Error,
    build_cache::{self, COPY_TARGETS},
    build_record::{Identity, identity, open_dir},
    image,
    oci::{BlobStore, Descriptor},
    store_access,
    store_lease::StoreLease,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Error>;
const OWNER: &str = "weld-cache-owner.json";
const ENTRY: &str = "weld-cache-entry.json";
const RECORD_LIMIT: u64 = 16 * 1024;
const LOCK: &str = "publication.lock";
const BLOB_OWNER: &str = "weld-cache-blob.json";
const MAX_SCAN_ENTRIES: usize = 100_000;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Namespace {
    version: u32,
    store: Identity,
    root: Identity,
    entries: Identity,
    content: Identity,
    blobs: Identity,
    sha256: Identity,
    objects: Identity,
    lock: Identity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobOwner {
    version: u32,
    namespace: Identity,
    directory: Identity,
    inode: Identity,
    digest: String,
    size: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    version: u32,
    store: Identity,
    namespace: Identity,
    directory: Identity,
    key: String,
    manifest: String,
    receipt: String,
    instructions: usize,
}

/// Explicit authority for `STORE/cache-v2`. Borrowing the lease prevents safe
/// callers from dropping coordination while using this capability. Returned paths
/// must also be consumed while the caller retains that lease.
/// Cooperative operations serialize publication and alias accounting. As with
/// BlobStore, an uncooperative same-user writer racing the final validation or
/// modifying an inode after return remains outside the stable-store contract.
pub struct ManagedCache<'a> {
    store: PathBuf,
    root: PathBuf,
    lease: &'a StoreLease,
    owner: Namespace,
    #[cfg(test)]
    scan_limit: usize,
    #[cfg(test)]
    before_objects_sync: Option<fn(&Path) -> io::Result<()>>,
}

impl<'a> ManagedCache<'a> {
    /// Create an owned namespace atomically, or validate an already owned one.
    /// A pre-existing unmarked directory is an error, including an empty one.
    pub fn open(
        store: &Path,
        lease: &'a StoreLease,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Self> {
        check(cancelled)?;
        store_access::validate_root(store, lease)?;
        // Keep path-based BlobStore operations within its stable, real-directory model.
        let store = fs::canonicalize(store)?;
        private_dir(&store)?;
        let root = store.join("cache-v2");
        retirement_barrier(&root)?;
        if !exists(&root)? {
            let temp = tempfile::Builder::new()
                .prefix(".cache-v2-")
                .tempdir_in(&store)?;
            for name in [
                "entries",
                "content",
                "content/blobs",
                "content/blobs/sha256",
                "objects",
            ] {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(temp.path().join(name))?;
            }
            write_new(&temp.path().join(LOCK), b"")?;
            let owner = namespace(&store, temp.path())?;
            write_new(&temp.path().join(OWNER), &serde_json::to_vec(&owner)?)?;
            sync_dirs(
                temp.path(),
                &[
                    "content/blobs/sha256",
                    "content/blobs",
                    "content",
                    "entries",
                    "objects",
                    "",
                ],
            )?;
            check(cancelled)?;
            match rename_new(temp.path(), &root) {
                Ok(()) => {
                    let _ = temp.keep();
                    File::open(&store)?.sync_all()?;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.into()),
            }
        }
        private_dir(&root)?;
        let owner: Namespace = read_record(&root.join(OWNER))?;
        let cache = Self {
            store,
            root,
            lease,
            owner,
            #[cfg(test)]
            scan_limit: MAX_SCAN_ENTRIES,
            #[cfg(test)]
            before_objects_sync: None,
        };
        cache.validate()?;
        // Also make a concurrent winner durable before returning success.
        File::open(&cache.store)?.sync_all()?;
        check(cancelled)?;
        Ok(cache)
    }

    /// Missing is the only cache miss. Malformed ownership, content or receipts
    /// are errors, never permission to replace the entry or silently rebuild it.
    pub fn lookup(
        &self,
        key: &str,
        limits: image::Limits,
        receipt_metadata_limit: u64,
        instructions: usize,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Option<PathBuf>> {
        check_key(key)?;
        check(cancelled)?;
        self.validate()?;
        let _lock = self.lock(cancelled)?;
        self.audit_links(cancelled)?;
        let path = self.root.join("entries").join(key);
        if !exists(&path)? {
            return Ok(None);
        }
        self.verify_entry(
            &path,
            key,
            limits,
            receipt_metadata_limit,
            instructions,
            cancelled,
        )?;
        self.audit_links(cancelled)?;
        Ok(Some(path))
    }

    /// Ingest arbitrary source bytes into fresh pool inodes, then hardlink only
    /// verified pool content into a private checkpoint. Source and mutable outputs
    /// must never share inodes with the pool. This does not materialize outputs;
    /// the engine's existing copy publication remains the output boundary.
    pub fn publish(
        &self,
        source: &Path,
        key: &str,
        limits: image::Limits,
        targets: &[Vec<Vec<u8>>],
        receipt_metadata_limit: u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<PathBuf> {
        check_key(key)?;
        check(cancelled)?;
        self.validate()?;
        let _lock = self.lock(cancelled)?;
        let remaining = self.audit_links(cancelled)?;
        store_access::validate_path(source, Some(self.lease))?;
        let receipt = build_cache::receipt_bytes(targets, receipt_metadata_limit)?;
        let metadata = image::load_layout(source, None, limits, cancelled)?;
        let destination = self.root.join("entries").join(key);
        if exists(&destination)? {
            self.verify_winner(
                &destination,
                key,
                targets.len(),
                limits,
                receipt_metadata_limit,
                cancelled,
            )?;
            return Ok(destination);
        }
        self.reserve_publication(&metadata, limits, remaining, cancelled)?;
        let temp = tempfile::Builder::new()
            .prefix(".publish-")
            .tempdir_in(self.root.join("entries"))?;
        let entry = Entry {
            version: 1,
            store: self.owner.store,
            namespace: self.owner.root,
            directory: private_dir(temp.path())?,
            key: key.into(),
            manifest: metadata.selected.digest.clone(),
            receipt: hash(&receipt),
            instructions: targets.len(),
        };
        // Written before payloads: crash leftovers carry explicit ownership.
        write_new(&temp.path().join(ENTRY), &serde_json::to_vec(&entry)?)?;
        File::open(temp.path())?.sync_all()?;
        File::open(self.root.join("entries"))?.sync_all()?;
        let source_store = BlobStore::open(source)?;
        let pool = BlobStore::open(self.root.join("content"))?;
        let target = BlobStore::open(temp.path())?;
        for (descriptor, cap) in descriptors(&metadata, limits) {
            check(cancelled)?;
            self.ensure_blob(&source_store, &pool, descriptor, cap, cancelled)?;
            pool.link_verified(&target, descriptor, cap, cancelled)?;
        }
        // Selected-only layout: never copy unreferenced blobs or unrelated source files.
        write_new(
            &temp.path().join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )?;
        write_new(
            &temp.path().join("index.json"),
            &serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2, "manifests": [metadata.selected]
            }))?,
        )?;
        write_new(&temp.path().join(COPY_TARGETS), &receipt)?;
        self.verify_entry(
            temp.path(),
            key,
            limits,
            receipt_metadata_limit,
            targets.len(),
            cancelled,
        )?;
        sync_dirs(
            &self.root,
            &["content/blobs/sha256", "content/blobs", "content"],
        )?;
        sync_dirs(temp.path(), &["blobs/sha256", "blobs", ""])?;
        self.validate()?;
        self.audit_links(cancelled)?;
        check(cancelled)?;
        match rename_new(temp.path(), &destination) {
            Ok(()) => {
                let _ = temp.keep();
                // Never roll back a visible publication, including on sync failure.
                File::open(self.root.join("entries"))?.sync_all()?;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                self.verify_winner(
                    &destination,
                    key,
                    targets.len(),
                    limits,
                    receipt_metadata_limit,
                    cancelled,
                )?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(destination)
    }

    fn validate(&self) -> Result<()> {
        retirement_barrier(&self.root)?;
        store_access::validate_root(&self.store, self.lease)?;
        private_dir(&self.root)?;
        let durable: Namespace = read_record(&self.root.join(OWNER))?;
        if durable != self.owner
            || durable != namespace(&self.store, &self.root)?
            || durable.version != 2
        {
            return Err("cache namespace identity mismatch".into());
        }
        exact_names(&self.root, &[OWNER, LOCK, "entries", "content", "objects"])?;
        exact_names(&self.root.join("content"), &["blobs"])?;
        exact_names(&self.root.join("content/blobs"), &["sha256"])?;
        Ok(())
    }

    // Open a fresh file description per operation, including concurrent calls on
    // the same capability. The store lease must always be acquired first.
    fn lock(&self, cancelled: &impl Fn() -> bool) -> Result<File> {
        let file = private_file(&self.root.join(LOCK))?;
        if identity(&file.metadata()?) != self.owner.lock {
            return Err("cache publication lock changed".into());
        }
        loop {
            check(cancelled)?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::Interrupted {
                return Err(e.into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        self.validate()?;
        check(cancelled)?;
        Ok(file)
    }

    fn ensure_blob(
        &self,
        source: &BlobStore,
        pool: &BlobStore,
        descriptor: &Descriptor,
        cap: u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        let digest = descriptor.digest.parse::<crate::oci::Sha256Digest>()?;
        let object = self.root.join("objects").join(digest.encoded());
        let pooled = self
            .root
            .join("content/blobs/sha256")
            .join(digest.encoded());
        if !exists(&object)? {
            // An existing pool filename without provenance is never an ingest hit.
            if exists(&pooled)? {
                return Err("cache pool blob has no inode provenance".into());
            }
            let staging = tempfile::Builder::new()
                .prefix(".ingest-")
                .tempdir_in(self.root.join("objects"))?;
            let fresh = BlobStore::open(staging.path())?;
            fresh.ingest(
                source.open_verified(descriptor, cap, cancelled)?,
                descriptor,
                cap,
                cancelled,
            )?;
            let file = fresh.open_verified(descriptor, cap, cancelled)?;
            let meta = file.metadata()?;
            if meta.nlink() != 1 {
                return Err("new cache blob has unexpected aliases".into());
            }
            let owner = BlobOwner {
                version: 1,
                namespace: self.owner.root,
                directory: private_dir(staging.path())?,
                inode: identity(&meta),
                digest: descriptor.digest.clone(),
                size: meta.len(),
            };
            write_new(
                &staging.path().join(BLOB_OWNER),
                &serde_json::to_vec(&owner)?,
            )?;
            sync_dirs(staging.path(), &["blobs/sha256", "blobs", ""])?;
            check(cancelled)?;
            rename_new(staging.path(), &object)?;
            let _ = staging.keep();
        }
        self.blob_owner(&object, digest.encoded())?;
        // Reuse may follow a crash after rename but before its parent fsync.
        // Establish the anchor name durably before publishing any new aliases.
        self.sync_objects()?;
        // The durable anchor is published before any pool/entry alias. A crash
        // before this link leaves a reusable owned object, never an adopted inode.
        BlobStore::open(&object)?.link_verified(pool, descriptor, cap, cancelled)?;
        Ok(())
    }

    fn sync_objects(&self) -> Result<()> {
        let path = self.root.join("objects");
        #[cfg(test)]
        if let Some(before) = self.before_objects_sync {
            before(&path)?;
        }
        File::open(path)?.sync_all()?;
        Ok(())
    }

    fn reserve_publication(
        &self,
        metadata: &image::ImageMetadata,
        limits: image::Limits,
        mut remaining: usize,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        let capacity = || "cache publication would exceed alias scan capacity";
        // The publication lock keeps this reservation valid through final audit.
        // .publish -> entry and .ingest -> object renames consume the same slots;
        // abandoned staging from earlier crashes is already charged by the audit.
        remaining = remaining.checked_sub(1).ok_or_else(capacity)?;
        let mut unique = BTreeSet::new();
        for (descriptor, _) in descriptors(metadata, limits) {
            check(cancelled)?;
            let digest = descriptor.digest.parse::<crate::oci::Sha256Digest>()?;
            if !unique.insert(digest.encoded().to_owned()) {
                continue;
            }
            let object_missing = !exists(&self.root.join("objects").join(digest.encoded()))?;
            let pool_missing = !exists(
                &self
                    .root
                    .join("content/blobs/sha256")
                    .join(digest.encoded()),
            )?;
            remaining = remaining
                .checked_sub(1 + usize::from(object_missing) + usize::from(pool_missing))
                .ok_or_else(capacity)?;
        }
        Ok(())
    }

    fn blob_owner(&self, object: &Path, digest: &str) -> Result<(Identity, fs::Metadata)> {
        let directory = private_dir(object)?;
        let owner: BlobOwner = read_record(&object.join(BLOB_OWNER))?;
        if owner.version != 1
            || owner.namespace != self.owner.root
            || owner.directory != directory
            || owner.digest != format!("sha256:{digest}")
        {
            return Err("cache blob provenance mismatch".into());
        }
        exact_names(object, &[BLOB_OWNER, "blobs"])?;
        exact_names(&object.join("blobs"), &["sha256"])?;
        exact_names(&object.join("blobs/sha256"), &[digest])?;
        let meta = blob_metadata(&object.join("blobs/sha256").join(digest))?;
        if identity(&meta) != owner.inode || meta.len() != owner.size {
            return Err("cache blob inode provenance mismatch".into());
        }
        Ok((owner.inode, meta))
    }

    // Do not infer immutability from a digest or st_nlink alone. Count only links
    // within durable blob objects and identity-validated cache entries. Anything
    // else (including an external hardlink added after publication) fails closed.
    // shortcut: bounded full scan under one lock; replace with a durable link
    // ledger only if measured cache sizes make this scan a bottleneck.
    fn audit_links(&self, cancelled: &impl Fn() -> bool) -> Result<usize> {
        #[cfg(not(test))]
        let mut budget = MAX_SCAN_ENTRIES;
        #[cfg(test)]
        let mut budget = self.scan_limit;
        let mut blobs = BTreeMap::new();
        let mut inodes = BTreeSet::new();
        for name in scan_names(&self.root.join("objects"), &mut budget, cancelled)? {
            // Interrupted ingests have never been linked into the pool. They are
            // not counted, adopted or removed, even if a record was written.
            if name.starts_with(".ingest-") {
                continue;
            }
            check_key(&name)?;
            let (id, meta) = self.blob_owner(&self.root.join("objects").join(&name), &name)?;
            if !inodes.insert((id.device, id.inode)) {
                return Err("cache blob objects alias each other".into());
            }
            blobs.insert(name, (id, meta.nlink(), 1u64));
        }
        for name in scan_names(
            &self.root.join("content/blobs/sha256"),
            &mut budget,
            cancelled,
        )? {
            check_key(&name)?;
            count_link(
                &self.root.join("content/blobs/sha256").join(&name),
                &name,
                &mut blobs,
                true,
            )?;
        }
        for name in scan_names(&self.root.join("entries"), &mut budget, cancelled)? {
            let pending = name.starts_with(".publish-");
            if !pending {
                check_key(&name)?;
            }
            let path = self.root.join("entries").join(&name);
            let directory = private_dir(&path)?;
            // A crash before the entry record cannot have published any links.
            if pending && !exists(&path.join(ENTRY))? {
                continue;
            }
            let owner: Entry = read_record(&path.join(ENTRY))?;
            check_key(&owner.key)?;
            if owner.version != 1
                || owner.store != self.owner.store
                || owner.namespace != self.owner.root
                || owner.directory != directory
                || (!pending && owner.key != name)
            {
                return Err("cache alias entry ownership mismatch".into());
            }
            let blobs_path = path.join("blobs");
            if pending && !exists(&blobs_path)? {
                continue;
            }
            private_dir(&blobs_path)?;
            let sha_path = blobs_path.join("sha256");
            if pending && !exists(&sha_path)? {
                continue;
            }
            private_dir(&sha_path)?;
            for digest in scan_names(&sha_path, &mut budget, cancelled)? {
                check_key(&digest)?;
                count_link(&sha_path.join(&digest), &digest, &mut blobs, false)?;
            }
        }
        for (_, (_, actual, accounted)) in blobs {
            if actual != accounted {
                return Err("cache blob has unaccounted hardlink aliases".into());
            }
        }
        check(cancelled)?;
        Ok(budget)
    }

    fn verify_entry(
        &self,
        path: &Path,
        key: &str,
        limits: image::Limits,
        receipt_metadata_limit: u64,
        instructions: usize,
        cancelled: &impl Fn() -> bool,
    ) -> Result<(image::ImageMetadata, Vec<Vec<Vec<u8>>>)> {
        check(cancelled)?;
        let directory = private_dir(path)?;
        let entry: Entry = read_record(&path.join(ENTRY))?;
        if entry.version != 1
            || entry.store != self.owner.store
            || entry.namespace != self.owner.root
            || entry.directory != directory
            || entry.key != key
            || entry.instructions != instructions
        {
            return Err("cache entry ownership mismatch".into());
        }
        exact_names(
            path,
            &[ENTRY, COPY_TARGETS, "oci-layout", "index.json", "blobs"],
        )?;
        exact_names(&path.join("blobs"), &["sha256"])?;
        for name in [COPY_TARGETS, "oci-layout", "index.json"] {
            private_file(&path.join(name))?;
        }
        let targets = build_cache::copy_targets(
            path,
            Some(self.lease),
            receipt_metadata_limit,
            instructions,
        )?;
        if hash(&build_cache::receipt_bytes(
            &targets,
            receipt_metadata_limit,
        )?) != entry.receipt
        {
            return Err("cache receipt identity mismatch".into());
        }
        let metadata = image::load_layout(path, None, limits, cancelled)?;
        if metadata.selected.digest != entry.manifest {
            return Err("cache manifest identity mismatch".into());
        }
        let pool = BlobStore::open(self.root.join("content"))?;
        let mut names = BTreeSet::new();
        for (descriptor, cap) in descriptors(&metadata, limits) {
            let digest = descriptor.digest.parse::<crate::oci::Sha256Digest>()?;
            names.insert(digest.encoded().to_owned());
            let pooled = pool.open_verified(descriptor, cap, cancelled)?;
            let local = fs::symlink_metadata(path.join("blobs/sha256").join(digest.encoded()))?;
            if identity(&pooled.metadata()?) != identity(&local) {
                return Err("cache blob is not the owned pool inode".into());
            }
        }
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        exact_names(&path.join("blobs/sha256"), &names)?;
        check(cancelled)?;
        Ok((metadata, targets))
    }

    fn verify_winner(
        &self,
        path: &Path,
        key: &str,
        instructions: usize,
        limits: image::Limits,
        receipt_metadata_limit: u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        // A key identifies inputs, not deterministic output bytes or resolved
        // COPY paths. Keep the winner's manifest and receipt together; publishing
        // a loser must neither replace them nor change that build's own output.
        self.verify_entry(
            path,
            key,
            limits,
            receipt_metadata_limit,
            instructions,
            cancelled,
        )?;
        self.audit_links(cancelled)?;
        self.sync_objects()?;
        sync_dirs(
            &self.root,
            &["content/blobs/sha256", "content/blobs", "content"],
        )?;
        sync_dirs(path, &["blobs/sha256", "blobs", ""])?;
        File::open(self.root.join("entries"))?.sync_all()?;
        Ok(())
    }
}

fn retirement_barrier(root: &Path) -> Result<()> {
    if exists(&root.join(crate::store_inventory::cache::JOURNAL))? {
        return Err("cache retirement pending; run explicit cache prune recovery".into());
    }
    Ok(())
}

impl ManagedCache<'_> {
    pub(crate) fn maintenance_inspect(
        root: &File,
        limits: crate::store_inventory::Limits,
        cancelled: &impl Fn() -> bool,
        recovery: bool,
    ) -> io::Result<Option<crate::store_inventory::cache::Snapshot>> {
        maintenance::inspect(root, limits, cancelled, recovery)
    }

    pub(crate) fn maintenance_lock(
        root: &File,
        lease: &crate::store_lease::ExclusiveStoreLease,
    ) -> io::Result<Option<File>> {
        let id = lease.root_identity();
        maintenance::require(
            identity(&root.metadata()?)
                == Identity {
                    device: id.device,
                    inode: id.inode,
                },
        )?;
        let cache = match open_dir(root.as_raw_fd(), Path::new("cache-v2")) {
            Ok(cache) => cache,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let file = maintenance::open(&cache, LOCK, false)?;
        let m = file.metadata()?;
        maintenance::require(
            m.is_file()
                && m.nlink() == 1
                && m.mode() & 0o077 == 0
                && m.uid() == unsafe { libc::geteuid() },
        )?;
        // The exclusive store lease excludes all cooperative holders of this lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(file))
    }
}

mod maintenance {
    use super::*;
    use crate::store_inventory::{
        Limits,
        cache::{JOURNAL, Kind, Node, Retirement, Snapshot},
    };
    use std::os::fd::FromRawFd;

    pub(super) fn require(ok: bool) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::other(
                "cache ownership, closure or retirement validation failed",
            ))
        }
    }
    fn key(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    pub(super) fn open(dir: &File, name: &str, directory: bool) -> io::Result<File> {
        #[repr(C)]
        struct How {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let name = CString::new(name)?;
        let how = How {
            flags: (libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 }) as u64,
            mode: 0,
            resolve: 0x01 | 0x02 | 0x04 | 0x08,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir.as_raw_fd(),
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
    fn mount(file: &File) -> io::Result<u64> {
        let mut st: libc::statx = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::statx(
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                libc::STATX_MNT_ID,
                &mut st,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        require(st.stx_mask & libc::STATX_MNT_ID != 0)?;
        Ok(st.stx_mnt_id)
    }
    struct Budget<'a, F> {
        limits: Limits,
        entries: usize,
        bytes: usize,
        cancel: &'a F,
    }
    impl<F: Fn() -> bool> Budget<'_, F> {
        fn charge(&mut self, bytes: usize) -> io::Result<()> {
            if (self.cancel)() {
                return Err(io::Error::other("cache maintenance cancelled"));
            }
            require(bytes <= self.limits.max_metadata_bytes.saturating_sub(self.bytes))?;
            self.bytes += bytes;
            Ok(())
        }
        fn read(&mut self, f: File, limit: usize) -> io::Result<Vec<u8>> {
            let len = f.metadata()?.len();
            require(len <= limit as u64)?;
            self.charge(len as usize)?;
            let mut bytes = Vec::new();
            f.take(len + 1).read_to_end(&mut bytes)?;
            require(bytes.len() as u64 == len)?;
            Ok(bytes)
        }
    }
    // Recognize only the protocol tree, before opening any unknown file contents.
    // 0 directory, 1 private metadata, 2 immutable blob alias.
    fn shape(path: &str) -> io::Result<u8> {
        let p: Vec<_> = path.split('/').collect();
        let kind = match p.as_slice() {
            [""]
            | ["entries"]
            | ["objects"]
            | ["content"]
            | ["content", "blobs"]
            | ["content", "blobs", "sha256"] => 0,
            [OWNER] | [LOCK] => 1,
            ["entries", k] | ["objects", k] if key(k) => 0,
            ["entries", k, "blobs"] | ["objects", k, "blobs"] if key(k) => 0,
            ["entries", k, "blobs", "sha256"] | ["objects", k, "blobs", "sha256"] if key(k) => 0,
            [
                "entries",
                k,
                ENTRY | COPY_TARGETS | "index.json" | "oci-layout",
            ] if key(k) => 1,
            ["objects", k, BLOB_OWNER] if key(k) => 1,
            ["content", "blobs", "sha256", d] if key(d) => 2,
            ["entries", k, "blobs", "sha256", d] if key(k) && key(d) => 2,
            ["objects", k, "blobs", "sha256", d] if key(k) && k == d => 2,
            _ => return Err(io::Error::other("unknown cache child protected")),
        };
        Ok(kind)
    }
    fn canonical(path: &str, j: Option<&Retirement>) -> String {
        if let Some(j) = j {
            let retired = j.retired();
            if path == retired {
                return j.source();
            }
            if let Some(suffix) = path.strip_prefix(&(retired + "/")) {
                return format!("{}/{suffix}", j.source());
            }
        }
        path.into()
    }
    fn walk<F: Fn() -> bool>(
        dir: &File,
        path: &str,
        mount_id: u64,
        j: Option<&Retirement>,
        budget: &mut Budget<'_, F>,
        nodes: &mut BTreeMap<String, Node>,
    ) -> io::Result<()> {
        for e in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
            let name = e?
                .file_name()
                .into_string()
                .map_err(|_| io::Error::other("non-UTF8 cache child"))?;
            let p = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}/{name}")
            };
            if p == JOURNAL && j.is_some() {
                continue;
            }
            budget.entries += 1;
            require(
                budget.entries <= budget.limits.max_entries
                    && p.split('/').count() <= budget.limits.max_depth,
            )?;
            budget.charge(p.len() + 256)?;
            let kind = shape(&canonical(&p, j))?;
            let f = open(dir, &name, kind == 0)?;
            let m = f.metadata()?;
            require(
                m.uid() == unsafe { libc::geteuid() }
                    && mount(&f)? == mount_id
                    && if kind == 0 {
                        m.is_dir() && m.mode() & 0o022 == 0
                    } else {
                        m.is_file() && m.mode() & 0o077 == 0 && (kind == 2 || m.nlink() == 1)
                    },
            )?;
            let mut node = Node {
                identity: identity(&m),
                directory: kind == 0,
                mode: m.mode(),
                size: if kind == 0 { 0 } else { m.len() },
                links: m.nlink(),
                allocated: m.blocks() * 512,
                data: None,
            };
            if kind == 0 {
                walk(&f, &p, mount_id, j, budget, nodes)?;
            } else if kind == 1 {
                node.data = Some(budget.read(f, budget.limits.max_record_bytes)?);
            }
            nodes.insert(p, node);
        }
        Ok(())
    }
    fn parse<T: DeserializeOwned>(nodes: &BTreeMap<String, Node>, path: &str) -> io::Result<T> {
        let n = nodes
            .get(path)
            .ok_or_else(|| io::Error::other("missing cache metadata"))?;
        serde_json::from_slice(
            n.data
                .as_deref()
                .ok_or_else(|| io::Error::other("missing cache metadata bytes"))?,
        )
        .map_err(|_| io::Error::other("malformed cache metadata"))
    }
    fn node<'a>(nodes: &'a BTreeMap<String, Node>, path: &str) -> io::Result<&'a Node> {
        nodes
            .get(path)
            .ok_or_else(|| io::Error::other("incomplete cache tree"))
    }
    fn same(a: &Node, b: &Node) -> bool {
        a.identity == b.identity
            && a.directory == b.directory
            && a.mode == b.mode
            && a.size == b.size
            && a.data == b.data
    }
    fn children(nodes: &BTreeMap<String, Node>, path: &str) -> BTreeSet<String> {
        let prefix = format!("{path}/");
        nodes
            .keys()
            .filter_map(|p| p.strip_prefix(&prefix))
            .filter(|p| !p.contains('/'))
            .map(str::to_owned)
            .collect()
    }
    fn exact(nodes: &BTreeMap<String, Node>, path: &str, expected: &[&str]) -> io::Result<()> {
        require(children(nodes, path) == expected.iter().map(|s| s.to_string()).collect())
    }
    fn validate_journal(
        j: &Retirement,
        root: &File,
        cache: &File,
        limits: Limits,
    ) -> io::Result<()> {
        require(
            j.version == 1
                && key(&j.key)
                && j.store == identity(&root.metadata()?)
                && j.namespace == identity(&cache.metadata()?)
                && !j.nodes.is_empty()
                && j.nodes.len() <= limits.max_entries,
        )?;
        let source = j.source();
        require(node(&j.nodes, &source)?.directory)?;
        for (p, n) in &j.nodes {
            require(
                p == &source
                    || p.starts_with(&(source.clone() + "/"))
                    || (j.kind == Kind::Object && p == &j.pool()),
            )?;
            require(p.split('/').count() <= limits.max_depth)?;
            let kind = shape(p)?;
            require(
                n.directory == (kind == 0)
                    && n.data.is_some() == (kind == 1)
                    && n.mode & libc::S_IFMT
                        == if kind == 0 {
                            libc::S_IFDIR
                        } else {
                            libc::S_IFREG
                        }
                    && n.mode & if kind == 0 { 0o022 } else { 0o077 } == 0
                    && n.data.as_ref().is_none_or(|b| {
                        b.len() <= limits.max_record_bytes && b.len() as u64 == n.size
                    })
                    && (kind != 1 || n.links == 1),
            )?;
        }
        Ok(())
    }
    pub(super) fn inspect(
        root: &File,
        limits: Limits,
        cancel: &impl Fn() -> bool,
        recovery: bool,
    ) -> io::Result<Option<Snapshot>> {
        let cache = match open(root, "cache-v2", true) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        require(
            cache.metadata()?.uid() == unsafe { libc::geteuid() }
                && cache.metadata()?.mode() & 0o022 == 0,
        )?;
        let mut budget = Budget {
            limits,
            entries: 0,
            bytes: 0,
            cancel,
        };
        budget.charge(0)?;
        let mut journal_identity = None;
        let journal = match open(&cache, JOURNAL, false) {
            Ok(f) => {
                if !recovery {
                    return Err(io::Error::other(
                        "cache retirement pending; run explicit cache prune recovery",
                    ));
                }
                let m = f.metadata()?;
                require(
                    m.is_file()
                        && m.nlink() == 1
                        && m.mode() & 0o077 == 0
                        && m.uid() == unsafe { libc::geteuid() },
                )?;
                journal_identity = Some(identity(&m));
                let bytes = budget.read(f, limits.max_metadata_bytes)?;
                let j: Retirement = serde_json::from_slice(&bytes)
                    .map_err(|_| io::Error::other("malformed cache retirement"))?;
                validate_journal(&j, root, &cache, limits)?;
                Some(j)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let mut actual = BTreeMap::new();
        walk(
            &cache,
            "",
            mount(root)?,
            journal.as_ref(),
            &mut budget,
            &mut actual,
        )?;
        let mut nodes = BTreeMap::new();
        for (p, n) in &actual {
            require(
                nodes
                    .insert(canonical(p, journal.as_ref()), n.clone())
                    .is_none(),
            )?;
        }
        if let Some(j) = &journal {
            require(
                node(&nodes, LOCK)?.identity == j.lock
                    && node(&nodes, j.parent_path())?.identity == j.parent,
            )?;
            let source = j.source();
            let retired = j.retired();
            require(!(actual.contains_key(&source) && actual.contains_key(&retired)))?;
            for (p, n) in &actual {
                let c = canonical(p, Some(j));
                if c == source
                    || c.starts_with(&(source.clone() + "/"))
                    || (j.kind == Kind::Object && c == j.pool())
                {
                    require(j.nodes.get(&c).is_some_and(|expected| same(n, expected)))?;
                }
            }
            // Only a renamed target may have lost descendants. The pool is
            // removed before an object rename, so it may already be absent.
            if actual.contains_key(&source) {
                for p in j.nodes.keys().filter(|p| **p != j.pool()) {
                    require(actual.contains_key(p))?;
                }
            }
            if j.kind == Kind::Object && !actual.contains_key(&source) {
                require(!actual.contains_key(&j.pool()))?;
            }
            for (p, n) in &j.nodes {
                nodes.entry(p.clone()).or_insert_with(|| n.clone());
            }
        }
        require(nodes.len() <= limits.max_entries)?;
        let ns: Namespace = parse(&nodes, OWNER)?;
        require(
            ns.version == 2
                && ns.store == identity(&root.metadata()?)
                && ns.root == identity(&cache.metadata()?),
        )?;
        for (p, id) in [
            ("entries", ns.entries),
            ("objects", ns.objects),
            ("content", ns.content),
            ("content/blobs", ns.blobs),
            ("content/blobs/sha256", ns.sha256),
            (LOCK, ns.lock),
        ] {
            require(node(&nodes, p)?.identity == id)?;
        }
        for p in [
            OWNER,
            LOCK,
            "entries",
            "objects",
            "content",
            "content/blobs",
            "content/blobs/sha256",
        ] {
            node(&nodes, p)?;
        }
        let mut blobs = BTreeMap::new();
        let mut identities = BTreeSet::new();
        for digest in children(&nodes, "objects") {
            let p = format!("objects/{digest}");
            let owner: BlobOwner = parse(&nodes, &format!("{p}/{BLOB_OWNER}"))?;
            let anchor = node(&nodes, &format!("{p}/blobs/sha256/{digest}"))?;
            require(
                owner.version == 1
                    && owner.namespace == ns.root
                    && owner.directory == node(&nodes, &p)?.identity
                    && owner.digest == format!("sha256:{digest}")
                    && owner.inode == anchor.identity
                    && owner.size == anchor.size
                    && identities.insert((owner.inode.device, owner.inode.inode)),
            )?;
            exact(&nodes, &p, &[BLOB_OWNER, "blobs"])?;
            exact(&nodes, &format!("{p}/blobs"), &["sha256"])?;
            exact(&nodes, &format!("{p}/blobs/sha256"), &[&digest])?;
            blobs.insert(digest, (owner.inode, owner.size, 0usize));
        }
        // Account actual surviving names, including only journal-validated retired
        // names. Never infer ownership from link count or digest spelling alone.
        let mut links = BTreeMap::<(u64, u64), (u64, u64)>::new();
        for (p, n) in &actual {
            if shape(&canonical(p, journal.as_ref()))? != 2 {
                continue;
            }
            let digest = p.rsplit('/').next().unwrap();
            let b = blobs
                .get(digest)
                .ok_or_else(|| io::Error::other("unproven cache inode"))?;
            require(n.identity == b.0 && n.size == b.1)?;
            let count = links
                .entry((n.identity.device, n.identity.inode))
                .or_insert((n.links, 0));
            require(count.0 == n.links)?;
            count.1 += 1;
        }
        require(links.values().all(|(actual, counted)| actual == counted))?;
        for digest in children(&nodes, "content/blobs/sha256") {
            let n = node(&nodes, &format!("content/blobs/sha256/{digest}"))?;
            let b = blobs
                .get(&digest)
                .ok_or_else(|| io::Error::other("unproven cache pool"))?;
            require(n.identity == b.0 && n.size == b.1)?;
        }
        let mut entries = Vec::new();
        for key in children(&nodes, "entries") {
            let p = format!("entries/{key}");
            let owner: Entry = parse(&nodes, &format!("{p}/{ENTRY}"))?;
            require(
                owner.version == 1
                    && owner.store == ns.store
                    && owner.namespace == ns.root
                    && owner.directory == node(&nodes, &p)?.identity
                    && owner.key == key,
            )?;
            exact(
                &nodes,
                &p,
                &[ENTRY, COPY_TARGETS, "index.json", "oci-layout", "blobs"],
            )?;
            exact(&nodes, &format!("{p}/blobs"), &["sha256"])?;
            let receipt = node(&nodes, &format!("{p}/{COPY_TARGETS}"))?
                .data
                .as_ref()
                .unwrap();
            let targets: Vec<Vec<Vec<u8>>> = serde_json::from_slice(receipt)
                .map_err(|_| io::Error::other("malformed cache receipt"))?;
            require(targets.len() == owner.instructions && hash(receipt) == owner.receipt)?;
            build_cache::receipt_bytes(&targets, limits.max_record_bytes as u64)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let layout: serde_json::Value = parse(&nodes, &format!("{p}/oci-layout"))?;
            require(layout["imageLayoutVersion"] == "1.0.0")?;
            let index: serde_json::Value = parse(&nodes, &format!("{p}/index.json"))?;
            require(
                index["schemaVersion"] == 2
                    && index["manifests"].as_array().is_some_and(|a| a.len() == 1),
            )?;
            let selected: Descriptor = serde_json::from_value(index["manifests"][0].clone())
                .map_err(|_| io::Error::other("invalid cache descriptor"))?;
            require(
                selected.digest == owner.manifest
                    && selected.media_type == "application/vnd.oci.image.manifest.v1+json",
            )?;
            let manifest = blob_json(&cache, &nodes, &selected, &mut budget)?;
            require(
                manifest["schemaVersion"] == 2
                    && manifest.get("subject").is_none()
                    && manifest.get("artifactType").is_none(),
            )?;
            require(
                manifest
                    .get("mediaType")
                    .is_none_or(|m| m == "application/vnd.oci.image.manifest.v1+json"),
            )?;
            let config: Descriptor = serde_json::from_value(manifest["config"].clone())
                .map_err(|_| io::Error::other("invalid config descriptor"))?;
            require(config.media_type == "application/vnd.oci.image.config.v1+json")?;
            let config_json = blob_json(&cache, &nodes, &config, &mut budget)?;
            require(
                config_json["architecture"] == "amd64"
                    && config_json["os"] == "linux"
                    && config_json
                        .get("config")
                        .is_none_or(|c| c.is_null() || c.is_object()),
            )?;
            let layers: Vec<Descriptor> = serde_json::from_value(manifest["layers"].clone())
                .map_err(|_| io::Error::other("invalid cache layers"))?;
            require(
                layers.len() <= limits.max_entries
                    && config_json["rootfs"]["type"] == "layers"
                    && config_json["rootfs"]["diff_ids"]
                        .as_array()
                        .is_some_and(|a| {
                            a.len() == layers.len()
                                && a.iter().all(|d| {
                                    d.as_str()
                                        .and_then(|s| s.strip_prefix("sha256:"))
                                        .is_some_and(self::key)
                                })
                        }),
            )?;
            require(layers.iter().all(|d| {
                matches!(
                    d.media_type.as_str(),
                    "application/vnd.oci.image.layer.v1.tar"
                        | "application/vnd.oci.image.layer.v1.tar+gzip"
                        | "application/vnd.oci.image.layer.v1.tar+zstd"
                )
            }))?;
            let mut expected = BTreeSet::new();
            for d in std::iter::once(&selected)
                .chain(std::iter::once(&config))
                .chain(layers.iter())
            {
                let digest = d
                    .digest
                    .strip_prefix("sha256:")
                    .filter(|s| self::key(s))
                    .ok_or_else(|| io::Error::other("invalid digest"))?;
                require(d.size >= 0)?;
                let alias = node(&nodes, &format!("{p}/blobs/sha256/{digest}"))?;
                let pool = node(&nodes, &format!("content/blobs/sha256/{digest}"))?;
                require(
                    alias.identity == pool.identity
                        && alias.size == d.size as u64
                        && pool.size == alias.size,
                )?;
                expected.insert(digest.to_owned());
            }
            require(children(&nodes, &format!("{p}/blobs/sha256")) == expected)?;
            for d in expected {
                blobs
                    .get_mut(&d)
                    .ok_or_else(|| io::Error::other("missing owned object"))?
                    .2 += 1;
            }
            entries.push(key);
        }
        if let Some(j) = &journal
            && j.kind == Kind::Object
        {
            require(blobs.get(&j.key).is_some_and(|b| b.2 == 0))?;
        }
        budget.charge(0)?;
        let unreferenced = blobs
            .into_iter()
            .filter_map(|(key, (_, _, refs))| (refs == 0).then_some(key))
            .collect();
        Ok(Some(Snapshot {
            store: ns.store,
            namespace: ns.root,
            nodes: actual,
            entries,
            unreferenced,
            retirement: journal,
            scan_bytes: budget.bytes,
            journal_identity,
        }))
    }
    fn blob_json<F: Fn() -> bool>(
        cache: &File,
        nodes: &BTreeMap<String, Node>,
        d: &Descriptor,
        budget: &mut Budget<'_, F>,
    ) -> io::Result<serde_json::Value> {
        let digest = d
            .digest
            .strip_prefix("sha256:")
            .filter(|s| key(s))
            .ok_or_else(|| io::Error::other("invalid metadata digest"))?;
        let path = format!("content/blobs/sha256/{digest}");
        let n = node(nodes, &path)?;
        require(d.size >= 0 && n.size == d.size as u64)?;
        let f = open(cache, &path, false)?;
        require(identity(&f.metadata()?) == n.identity)?;
        let bytes = budget.read(f, budget.limits.max_record_bytes)?;
        require(hash(&bytes) == digest)?;
        serde_json::from_slice(&bytes)
            .map_err(|_| io::Error::other("malformed cache blob metadata"))
    }
}

fn descriptors(
    metadata: &image::ImageMetadata,
    limits: image::Limits,
) -> impl Iterator<Item = (&Descriptor, u64)> {
    [
        (&metadata.selected, limits.max_metadata_bytes),
        (&metadata.config_descriptor, limits.max_metadata_bytes),
    ]
    .into_iter()
    .chain(
        metadata
            .layers
            .iter()
            .map(move |d| (d, limits.max_layer_bytes)),
    )
}
fn check(cancelled: &impl Fn() -> bool) -> Result<()> {
    if cancelled() {
        Err("managed cache cancelled".into())
    } else {
        Ok(())
    }
}
fn check_key(key: &str) -> Result<()> {
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("cache key must be 64 lowercase hexadecimal characters".into());
    }
    Ok(())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
fn private_dir(path: &Path) -> Result<Identity> {
    let dir = open_dir(libc::AT_FDCWD, path)?;
    let m = dir.metadata()?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
        return Err("cache directory is not privately writable".into());
    }
    Ok(identity(&m))
}
fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err("cache metadata must be a private singly linked regular file".into());
    }
    Ok(file)
}
fn read_record<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = private_file(path)?;
    if file.metadata()?.len() > RECORD_LIMIT {
        return Err("cache ownership record exceeds limit".into());
    }
    let mut bytes = Vec::new();
    file.take(RECORD_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > RECORD_LIMIT {
        return Err("cache ownership record exceeds limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn namespace(store: &Path, root: &Path) -> Result<Namespace> {
    Ok(Namespace {
        version: 2,
        store: private_dir(store)?,
        root: private_dir(root)?,
        entries: private_dir(&root.join("entries"))?,
        content: private_dir(&root.join("content"))?,
        blobs: private_dir(&root.join("content/blobs"))?,
        sha256: private_dir(&root.join("content/blobs/sha256"))?,
        objects: private_dir(&root.join("objects"))?,
        lock: identity(&private_file(&root.join(LOCK))?.metadata()?),
    })
}

fn blob_metadata(path: &Path) -> Result<fs::Metadata> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("cache blob must be a private regular file".into());
    }
    Ok(meta)
}

fn count_link(
    path: &Path,
    digest: &str,
    blobs: &mut BTreeMap<String, (Identity, u64, u64)>,
    strict: bool,
) -> Result<()> {
    let meta = blob_metadata(path)?;
    let Some((id, links, counted)) = blobs.get_mut(digest) else {
        if strict {
            return Err("cache pool blob has no inode provenance".into());
        }
        return Ok(());
    };
    if identity(&meta) != *id {
        if strict {
            return Err("cache pool inode differs from provenance".into());
        }
        // A detached corrupt entry is not an alias of this blob. Its own lookup
        // fails content/identity validation without poisoning unrelated entries.
        return Ok(());
    }
    if meta.nlink() != *links {
        return Err("cache blob link count changed during audit".into());
    }
    *counted += 1;
    Ok(())
}

fn scan_names(
    path: &Path,
    budget: &mut usize,
    cancelled: &impl Fn() -> bool,
) -> Result<Vec<String>> {
    private_dir(path)?;
    let mut names = Vec::new();
    for entry in fs::read_dir(path)? {
        check(cancelled)?;
        *budget = budget
            .checked_sub(1)
            .ok_or("cache alias scan exceeds entry budget")?;
        names.push(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| "unexpected cache filename")?,
        );
    }
    Ok(names)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn exact_names(path: &Path, expected: &[&str]) -> Result<()> {
    private_dir(path)?;
    let mut seen = BTreeSet::new();
    for item in fs::read_dir(path)? {
        let name = item?
            .file_name()
            .into_string()
            .map_err(|_| "unexpected cache filename")?;
        if seen.len() >= expected.len() || !expected.contains(&name.as_str()) {
            return Err("unexpected cache child".into());
        }
        seen.insert(name);
    }
    if seen.len() != expected.len() {
        return Err("missing cache child".into());
    }
    Ok(())
}
fn sync_dirs(root: &Path, names: &[&str]) -> Result<()> {
    for name in names {
        open_dir(libc::AT_FDCWD, &root.join(name))?.sync_all()?;
    }
    Ok(())
}
fn rename_new(source: &Path, destination: &Path) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> image::Limits {
        image::Limits {
            max_metadata_bytes: 65536,
            max_total_metadata_bytes: 262144,
            max_descriptors: 32,
            max_layer_bytes: 4096,
            max_total_layer_bytes: 8192,
        }
    }

    fn blob(store: &BlobStore, media: &str, bytes: &[u8]) -> Descriptor {
        let d = Descriptor {
            media_type: media.into(),
            digest: format!("sha256:{}", hash(bytes)),
            size: bytes.len() as i64,
            annotations: Default::default(),
            extensions: Default::default(),
        };
        store.ingest(bytes, &d, 65536, || false).unwrap();
        d
    }

    fn source(path: &Path, version: u32) -> Descriptor {
        fs::create_dir(path).unwrap();
        let store = BlobStore::open(path).unwrap();
        let layer = blob(
            &store,
            "application/vnd.oci.image.layer.v1.tar",
            &[42; 4096],
        );
        let config = blob(
            &store,
            "application/vnd.oci.image.config.v1+json",
            &serde_json::to_vec(&serde_json::json!({
                "architecture":"amd64", "os":"linux", "version":version, "config":{},
                "rootfs":{"type":"layers", "diff_ids":[layer.digest]}
            }))
            .unwrap(),
        );
        let manifest = blob(&store, "application/vnd.oci.image.manifest.v1+json", &serde_json::to_vec(&serde_json::json!({
            "schemaVersion":2, "mediaType":"application/vnd.oci.image.manifest.v1+json", "config":config, "layers":[layer]
        })).unwrap());
        fs::write(
            path.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            path.join("index.json"),
            serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"manifests":[manifest]}))
                .unwrap(),
        )
        .unwrap();
        layer
    }

    #[test]
    fn capacity_rejection_does_not_poison_existing_lookups() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("source-a");
        source(&a, 1);
        let b = t.path().join("source-b");
        source(&b, 2);
        let lease = StoreLease::shared(t.path(), &|| false).unwrap();
        let mut cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
        cache.scan_limit = 12;
        let key = "a".repeat(64);
        cache
            .publish(&a, &key, limits(), &[], 0, &|| false)
            .unwrap();
        assert!(
            cache
                .publish(&b, &"b".repeat(64), limits(), &[], 0, &|| false)
                .is_err()
        );
        assert!(
            cache
                .lookup(&key, limits(), 0, 0, &|| false)
                .unwrap()
                .is_some()
        );
        for area in ["objects", "content/blobs/sha256"] {
            assert_eq!(fs::read_dir(cache.root.join(area)).unwrap().count(), 3);
        }
        assert_eq!(fs::read_dir(cache.root.join("entries")).unwrap().count(), 1);
        // Exactly full remains readable and idempotent. An all-shared new entry
        // still needs its directory and three links, so it must be rejected.
        cache.scan_limit = 10;
        cache
            .publish(&a, &key, limits(), &[], 0, &|| false)
            .unwrap();
        assert!(
            cache
                .publish(&a, &"c".repeat(64), limits(), &[], 0, &|| false)
                .is_err()
        );
        assert!(
            cache
                .lookup(&key, limits(), 0, 0, &|| false)
                .unwrap()
                .is_some()
        );
        // Crash staging consumes capacity even before records or links exist.
        cache.scan_limit = 12;
        fs::create_dir(cache.root.join("objects/.ingest-abandoned")).unwrap();
        fs::create_dir(cache.root.join("entries/.publish-abandoned")).unwrap();
        assert!(
            cache
                .publish(&b, &"b".repeat(64), limits(), &[], 0, &|| false)
                .is_err()
        );
        assert!(
            cache
                .lookup(&key, limits(), 0, 0, &|| false)
                .unwrap()
                .is_some()
        );
        assert_eq!(fs::read_dir(cache.root.join("objects")).unwrap().count(), 4);
        assert_eq!(
            fs::read_dir(cache.root.join("content/blobs/sha256"))
                .unwrap()
                .count(),
            3
        );
        assert_eq!(fs::read_dir(cache.root.join("entries")).unwrap().count(), 2);
    }

    #[test]
    fn recovered_object_requires_parent_sync_before_alias_publication() {
        fn fail_sync(_: &Path) -> io::Result<()> {
            Err(io::Error::other("injected objects fsync failure"))
        }
        let t = tempfile::tempdir().unwrap();
        let input = t.path().join("source");
        let layer = source(&input, 1);
        let lease = StoreLease::shared(t.path(), &|| false).unwrap();
        let mut cache = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
        let source = BlobStore::open(&input).unwrap();
        let pool = BlobStore::open(cache.root.join("content")).unwrap();
        cache.before_objects_sync = Some(fail_sync);
        // Inject exactly after the atomic object rename, before parent fsync.
        assert!(
            cache
                .ensure_blob(&source, &pool, &layer, 4096, &|| false)
                .is_err()
        );
        let digest = &layer.digest[7..];
        assert!(cache.root.join("objects").join(digest).is_dir());
        let pooled = cache.root.join("content/blobs/sha256").join(digest);
        assert!(!pooled.exists());
        // Reopen to discard all in-memory knowledge, as after a process crash.
        let mut reopened = ManagedCache::open(t.path(), &lease, &|| false).unwrap();
        reopened.before_objects_sync = Some(fail_sync);
        assert!(
            reopened
                .ensure_blob(&source, &pool, &layer, 4096, &|| false)
                .is_err()
        );
        assert!(!pooled.exists());
        reopened.before_objects_sync = None;
        reopened
            .ensure_blob(&source, &pool, &layer, 4096, &|| false)
            .unwrap();
        assert!(pool.open_verified(&layer, 4096, || false).is_ok());
    }
}
