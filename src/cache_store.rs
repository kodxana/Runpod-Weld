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
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Error>;
const OWNER: &str = "weld-cache-owner.json";
const ENTRY: &str = "weld-cache-entry.json";
const RECORD_LIMIT: u64 = 16 * 1024;

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
pub struct ManagedCache<'a> {
    store: PathBuf,
    root: PathBuf,
    lease: &'a StoreLease,
    owner: Namespace,
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
        if !exists(&root)? {
            let temp = tempfile::Builder::new()
                .prefix(".cache-v2-")
                .tempdir_in(&store)?;
            for name in [
                "entries",
                "content",
                "content/blobs",
                "content/blobs/sha256",
            ] {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(temp.path().join(name))?;
            }
            let owner = namespace(&store, temp.path())?;
            write_new(&temp.path().join(OWNER), &serde_json::to_vec(&owner)?)?;
            sync_dirs(
                temp.path(),
                &[
                    "content/blobs/sha256",
                    "content/blobs",
                    "content",
                    "entries",
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
        store_access::validate_path(source, Some(self.lease))?;
        let receipt = build_cache::receipt_bytes(targets, receipt_metadata_limit)?;
        let metadata = image::load_layout(source, None, limits, cancelled)?;
        let destination = self.root.join("entries").join(key);
        if exists(&destination)? {
            self.verify_winner(
                &destination,
                key,
                &metadata.selected,
                targets,
                limits,
                receipt_metadata_limit,
                cancelled,
            )?;
            return Ok(destination);
        }
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
            let digest = descriptor.digest.parse::<crate::oci::Sha256Digest>()?;
            if exists(
                &self
                    .root
                    .join("content/blobs/sha256")
                    .join(digest.encoded()),
            )? {
                pool.open_verified(descriptor, cap, cancelled)?;
            } else {
                let bytes = source_store.open_verified(descriptor, cap, cancelled)?;
                pool.ingest(bytes, descriptor, cap, cancelled)?;
            }
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
                    &metadata.selected,
                    targets,
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
        store_access::validate_root(&self.store, self.lease)?;
        private_dir(&self.root)?;
        let durable: Namespace = read_record(&self.root.join(OWNER))?;
        if durable != self.owner
            || durable != namespace(&self.store, &self.root)?
            || durable.version != 1
        {
            return Err("cache namespace identity mismatch".into());
        }
        exact_names(&self.root, &[OWNER, "entries", "content"])?;
        exact_names(&self.root.join("content"), &["blobs"])?;
        exact_names(&self.root.join("content/blobs"), &["sha256"])?;
        Ok(())
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

    #[allow(clippy::too_many_arguments)]
    fn verify_winner(
        &self,
        path: &Path,
        key: &str,
        selected: &Descriptor,
        targets: &[Vec<Vec<u8>>],
        limits: image::Limits,
        receipt_metadata_limit: u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        let (metadata, actual) = self.verify_entry(
            path,
            key,
            limits,
            receipt_metadata_limit,
            targets.len(),
            cancelled,
        )?;
        if metadata.selected != *selected || actual != targets {
            return Err("cache publication winner differs from source".into());
        }
        sync_dirs(
            &self.root,
            &["content/blobs/sha256", "content/blobs", "content"],
        )?;
        sync_dirs(path, &["blobs/sha256", "blobs", ""])?;
        File::open(self.root.join("entries"))?.sync_all()?;
        Ok(())
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
        version: 1,
        store: private_dir(store)?,
        root: private_dir(root)?,
        entries: private_dir(&root.join("entries"))?,
        content: private_dir(&root.join("content"))?,
        blobs: private_dir(&root.join("content/blobs"))?,
        sha256: private_dir(&root.join("content/blobs/sha256"))?,
    })
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
