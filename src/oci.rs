//! Verified local OCI blobs; not a complete OCI layout importer or exporter.
//!
//! The caller must own the store and all its ancestors and keep them stable: no
//! untrusted writers, symlink/reparse-point swaps, external hard links, or mutation
//! of published files. Checks reject existing links but are not a sandbox against
//! a hostile process racing pathname operations. Cooperative writers using this
//! API may run concurrently. Use a local filesystem supporting atomic hard links.
//! Successful publication is atomic, but directory entries are not crash-durable.
//! A crash may leave `.tmp-*` files; these are never treated as blobs.
//!
//! References: OCI image-spec v1.1.1 descriptor.md and image-layout.md;
//! RustCrypto sha2 0.10.9 incremental Digest API (MIT OR Apache-2.0, MSRV 1.41).

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
#[path = "cache_store.rs"]
mod cache_store;
#[cfg(target_os = "linux")]
pub use cache_store::ManagedCache;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

const BUFFER_SIZE: usize = 64 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Canonical `sha256:` followed by exactly 64 lowercase hexadecimal characters.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn encoded(&self) -> &str {
        &self.0[7..]
    }
}

impl FromStr for Sha256Digest {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self, Error> {
        let (algorithm, encoded) = value.split_once(':').ok_or(Error::MalformedDigest)?;
        if algorithm != "sha256" {
            return Err(Error::UnsupportedAlgorithm(algorithm.to_owned()));
        }
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::MalformedDigest);
        }
        Ok(Self(value.to_owned()))
    }
}
impl TryFrom<String> for Sha256Digest {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        value.parse()
    }
}
impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}
impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lossless descriptor metadata carrier. Unsupported digest algorithms and media
/// types survive round trips; blob operations explicitly require SHA-256. Media
/// type/schema semantics, URLs and embedded data are for the future importer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    #[serde(flatten, serialize_with = "serialize_extensions")]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

fn serialize_extensions<S: serde::Serializer>(
    extensions: &BTreeMap<String, serde_json::Value>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if extensions.keys().any(|key| {
        matches!(
            key.as_str(),
            "mediaType" | "digest" | "size" | "annotations"
        )
    }) {
        return Err(serde::ser::Error::custom(
            "descriptor extensions contain a reserved field",
        ));
    }
    extensions.serialize(serializer)
}

impl Descriptor {
    fn expected(&self, max_size: u64) -> Result<(Sha256Digest, u64), Error> {
        let digest = self.digest.parse()?;
        let size = u64::try_from(self.size).map_err(|_| Error::InvalidSize)?;
        if size > max_size {
            return Err(Error::SizeLimit { max: max_size });
        }
        Ok((digest, size))
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    MalformedDigest,
    UnsupportedAlgorithm(String),
    InvalidSize,
    SizeLimit { max: u64 },
    SizeMismatch { expected: u64, observed: u64 },
    DigestMismatch,
    Cancelled,
    UnsafePath(PathBuf),
    ExistingInvalid(Box<Error>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "blob I/O: {e}"),
            Self::MalformedDigest => f.write_str("expected sha256: and 64 lowercase hex digits"),
            Self::UnsupportedAlgorithm(a) => write!(f, "unsupported digest algorithm: {a}"),
            Self::InvalidSize => f.write_str("negative OCI descriptor size"),
            Self::SizeLimit { max } => write!(f, "blob exceeds maximum size {max}"),
            Self::SizeMismatch { expected, observed } => {
                write!(f, "expected {expected} bytes, observed {observed}")
            }
            Self::DigestMismatch => f.write_str("blob SHA-256 mismatch"),
            Self::Cancelled => f.write_str("blob operation cancelled"),
            Self::UnsafePath(p) => write!(f, "unsafe store path: {}", p.display()),
            Self::ExistingInvalid(e) => write!(f, "existing blob rejected: {e}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::ExistingInvalid(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// An OCI-compatible `blobs/sha256` directory beneath a caller-created root.
#[derive(Clone, Debug)]
pub struct BlobStore {
    directory: PathBuf,
}

impl BlobStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, Error> {
        let root = root.as_ref();
        if !root.is_absolute()
            || root
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(Error::UnsafePath(root.to_owned()));
        }
        check_directories(root)?;
        let blobs = root.join("blobs");
        ensure_directory(&blobs)?;
        let directory = blobs.join("sha256");
        ensure_directory(&directory)?;
        Ok(Self { directory })
    }

    /// Streams at most expected-size + one probe byte, using a fixed 64 KiB buffer.
    /// Cancellation is checked between reads and before publication; a blocking
    /// Read must implement its own timeout. A cancellation after publication's
    /// linearization point cannot revoke the successfully published blob.
    pub fn ingest<R: Read, C: Fn() -> bool>(
        &self,
        mut reader: R,
        descriptor: &Descriptor,
        max_size: u64,
        cancelled: C,
    ) -> Result<(), Error> {
        let (digest, size) = descriptor.expected(max_size)?;
        check_cancel(&cancelled)?;
        check_directories(&self.directory)?;
        let (mut file, temp) = self.create_temp()?;
        let result = verify_stream(&mut reader, Some(&mut file), &digest, size, &cancelled)
            .and_then(|()| file.sync_all().map_err(Error::Io));
        drop(file);
        result?;
        check_cancel(&cancelled)?;
        check_directories(&self.directory)?;
        let destination = self.directory.join(digest.encoded());
        match fs::hard_link(&temp.0, &destination) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => self
                .open_verified(descriptor, max_size, &cancelled)
                .map(|_| ())
                .map_err(|e| {
                    if matches!(e, Error::Cancelled) {
                        e
                    } else {
                        Error::ExistingInvalid(Box::new(e))
                    }
                }),
            Err(e) => Err(e.into()),
        }
    }

    /// Verifies the entire regular file, then returns the same read-only handle
    /// rewound to zero. No filename, existence check or cached result proves validity.
    pub fn open_verified<C: Fn() -> bool>(
        &self,
        descriptor: &Descriptor,
        max_size: u64,
        cancelled: C,
    ) -> Result<File, Error> {
        let (digest, size) = descriptor.expected(max_size)?;
        check_cancel(&cancelled)?;
        check_directories(&self.directory)?;
        let path = self.directory.join(digest.encoded());
        let metadata = fs::symlink_metadata(&path)?;
        if is_link(&metadata) || !metadata.is_file() {
            return Err(Error::UnsafePath(path));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options.open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(Error::UnsafePath(path));
        }
        verify_stream(&mut file, None, &digest, size, &cancelled)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    /// Link verified content into another store under the trusted stable-directory model.
    pub fn link_verified<C: Fn() -> bool>(
        &self,
        destination: &Self,
        descriptor: &Descriptor,
        max_size: u64,
        cancelled: C,
    ) -> Result<(), Error> {
        let file = self.open_verified(descriptor, max_size, &cancelled)?;
        file.sync_all()?;
        check_cancel(&cancelled)?;
        check_directories(&destination.directory)?;
        let (digest, _) = descriptor.expected(max_size)?;
        let target = destination.directory.join(digest.encoded());
        match fs::hard_link(self.directory.join(digest.encoded()), target) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                destination.open_verified(descriptor, max_size, &cancelled)?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    fn create_temp(&self) -> Result<(File, Temporary), Error> {
        for _ in 0..128 {
            let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = self
                .directory
                .join(format!(".tmp-{}-{serial}", std::process::id()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => return Ok((file, Temporary(path))),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary blob names exhausted",
        )
        .into())
    }
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn check_cancel(cancelled: &impl Fn() -> bool) -> Result<(), Error> {
    if cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn verify_stream<R: Read>(
    reader: &mut R,
    mut output: Option<&mut File>,
    digest: &Sha256Digest,
    expected: u64,
    cancelled: &impl Fn() -> bool,
) -> Result<(), Error> {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut hash = Sha256::new();
    let mut observed = 0u64;
    loop {
        check_cancel(cancelled)?;
        // One extra byte distinguishes exact EOF from trailing content without
        // reading an unbounded source. OCI sizes are at most i64::MAX.
        let limit = ((expected - observed).min(BUFFER_SIZE as u64 - 1) + 1) as usize;
        let count = match reader.read(&mut buffer[..limit]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        check_cancel(cancelled)?;
        if count == 0 {
            break;
        }
        observed += count as u64;
        if observed > expected {
            return Err(Error::SizeMismatch { expected, observed });
        }
        hash.update(&buffer[..count]);
        if let Some(file) = output.as_mut() {
            file.write_all(&buffer[..count])?;
        }
    }
    if observed != expected {
        return Err(Error::SizeMismatch { expected, observed });
    }
    if format!("{:x}", hash.finalize()) != digest.encoded() {
        return Err(Error::DigestMismatch);
    }
    Ok(())
}
fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Includes junctions and other reparse points, not just symbolic links.
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}
fn check_directories(path: &Path) -> Result<(), Error> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if is_link(&metadata) || !metadata.is_dir() {
            return Err(Error::UnsafePath(ancestor.to_owned()));
        }
    }
    Ok(())
}
fn ensure_directory(path: &Path) -> Result<(), Error> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    check_directories(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        sync::{Arc, Barrier},
    };

    const ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    struct Fixture(PathBuf, BlobStore);
    impl Fixture {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            let root = base.join(format!(
                "rpweld-oci-test-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let store = BlobStore::open(&root).unwrap();
            Self(root, store)
        }
        fn clean(&self) {
            assert!(fs::read_dir(&self.1.directory).unwrap().all(|e| {
                !e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tmp-")
            }));
        }
        fn destination(&self) -> PathBuf {
            self.1.directory.join(&ABC[7..])
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn descriptor() -> Descriptor {
        Descriptor {
            media_type: "application/octet-stream".into(),
            digest: ABC.into(),
            size: 3,
            annotations: BTreeMap::new(),
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn valid_and_idempotent() {
        let f = Fixture::new();
        for _ in 0..2 {
            f.1.ingest(&b"abc"[..], &descriptor(), 3, || false).unwrap();
        }
        let mut file = f.1.open_verified(&descriptor(), 3, || false).unwrap();
        let mut bytes = [0; 3];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");
        f.clean();
    }

    #[test]
    fn bounded_reads_short_reads_and_interrupts() {
        struct Endless(usize);
        impl Read for Endless {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                buffer.fill(b'a');
                self.0 += buffer.len();
                Ok(buffer.len())
            }
        }
        let f = Fixture::new();
        let mut endless = Endless(0);
        assert!(matches!(
            f.1.ingest(&mut endless, &descriptor(), 3, || false),
            Err(Error::SizeMismatch { .. })
        ));
        assert_eq!(endless.0, 4);
        struct Short {
            position: usize,
            interrupt: bool,
        }
        impl Read for Short {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                if self.position == 3 {
                    return Ok(0);
                }
                buffer[0] = b"abc"[self.position];
                self.position += 1;
                Ok(1)
            }
        }
        f.1.ingest(
            Short {
                position: 0,
                interrupt: false,
            },
            &descriptor(),
            3,
            || false,
        )
        .unwrap();
        f.clean();
    }

    #[test]
    fn cancellation_at_publication_and_existing_verification() {
        let f = Fixture::new();
        let calls = Cell::new(0);
        // Initial check, pre/post data read, pre/post EOF, publication check.
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &descriptor(), 3, || {
                calls.set(calls.get() + 1);
                calls.get() == 6
            }),
            Err(Error::Cancelled)
        ));
        assert!(!f.destination().exists());
        f.clean();
        f.1.ingest(&b"abc"[..], &descriptor(), 3, || false).unwrap();
        calls.set(0);
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &descriptor(), 3, || {
                calls.set(calls.get() + 1);
                calls.get() == 9
            }),
            Err(Error::Cancelled)
        ));
        assert_eq!(fs::read(f.destination()).unwrap(), b"abc");
        f.clean();
    }

    #[test]
    fn reserved_extension_fields_cannot_shadow_descriptor() {
        for name in ["mediaType", "digest", "size", "annotations"] {
            let mut d = descriptor();
            d.extensions
                .insert(name.into(), serde_json::json!("override"));
            assert!(serde_json::to_string(&d).is_err());
            assert!(serde_json::to_value(&d).is_err());
        }
    }

    #[test]
    fn malformed_and_unsupported_digests() {
        for bad in [
            "",
            "sha256",
            "sha256:abc",
            "sha256:../abc",
            "sha256:/abc",
            "sha256:ab:cd",
        ] {
            assert!(bad.parse::<Sha256Digest>().is_err(), "{bad}");
        }
        for bad in [
            ABC.to_uppercase(),
            format!("{ABC}0"),
            ABC.replace('a', "g"),
            format!(" {ABC}"),
            format!("{ABC}\n"),
        ] {
            assert!(bad.parse::<Sha256Digest>().is_err());
        }
        assert!(matches!(
            "sha512:abcd".parse::<Sha256Digest>(),
            Err(Error::UnsupportedAlgorithm(_))
        ));
        assert_eq!(ABC.parse::<Sha256Digest>().unwrap().as_str(), ABC);
        assert!(serde_json::from_str::<Sha256Digest>("\"sha256:bad\"").is_err());
    }

    #[test]
    fn failures_do_not_publish_or_leave_temps() {
        let f = Fixture::new();
        assert!(matches!(
            f.1.ingest(&b"abd"[..], &descriptor(), 3, || false),
            Err(Error::DigestMismatch)
        ));
        for input in [&b"ab"[..], &b"abcd"[..], &b""[..]] {
            assert!(matches!(
                f.1.ingest(input, &descriptor(), 3, || false),
                Err(Error::SizeMismatch { .. })
            ));
        }
        let mut wrong_size = descriptor();
        wrong_size.size = 4;
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &wrong_size, 4, || false),
            Err(Error::SizeMismatch { .. })
        ));
        wrong_size.size = -1;
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &wrong_size, 4, || false),
            Err(Error::InvalidSize)
        ));
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &descriptor(), 2, || false),
            Err(Error::SizeLimit { .. })
        ));
        assert!(!f.destination().exists());
        f.clean();
    }

    #[test]
    fn cancellation_before_and_during_read() {
        let f = Fixture::new();
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &descriptor(), 3, || true),
            Err(Error::Cancelled)
        ));
        let calls = Cell::new(0);
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &descriptor(), 3, || {
                calls.set(calls.get() + 1);
                calls.get() >= 3
            }),
            Err(Error::Cancelled)
        ));
        assert!(!f.destination().exists());
        f.clean();
    }

    #[test]
    fn existing_corruption_is_never_overwritten() {
        let f = Fixture::new();
        for bad in [&b"abd"[..], &b"ab"[..], &b"abcd"[..]] {
            fs::write(f.destination(), bad).unwrap();
            assert!(f.1.open_verified(&descriptor(), 3, || false).is_err());
            assert!(matches!(
                f.1.ingest(&b"abc"[..], &descriptor(), 3, || false),
                Err(Error::ExistingInvalid(_))
            ));
            assert_eq!(fs::read(f.destination()).unwrap(), bad);
            f.clean();
        }
    }

    #[test]
    fn concurrent_publication() {
        let f = Fixture::new();
        fs::remove_dir(&f.1.directory).unwrap();
        fs::remove_dir(f.0.join("blobs")).unwrap();
        let barrier = Arc::new(Barrier::new(4));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let barrier = barrier.clone();
                let root = &f.0;
                scope.spawn(move || {
                    barrier.wait();
                    let store = BlobStore::open(root).unwrap();
                    store
                        .ingest(&b"abc"[..], &descriptor(), 3, || false)
                        .unwrap();
                });
            }
        });
        f.1.open_verified(&descriptor(), 3, || false).unwrap();
        f.clean();
    }

    #[test]
    fn descriptor_round_trip_and_algorithm_rejection() {
        let value = serde_json::json!({
            "mediaType": "application/vnd.example.unknown", "digest": "sha512:abcd", "size": 3,
            "annotations": {"org.example.name": "test"},
            "platform": {"architecture": "amd64", "os": "linux"}, "urls": ["https://example.com/blob"]
        });
        let descriptor: Descriptor = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&descriptor).unwrap(), value);
        let f = Fixture::new();
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &descriptor, 3, || false),
            Err(Error::UnsupportedAlgorithm(_))
        ));
        f.clean();
    }

    #[test]
    fn empty_and_multiple_buffers() {
        let f = Fixture::new();
        for data in [vec![], vec![42; BUFFER_SIZE * 3 + 7]] {
            let mut d = descriptor();
            d.digest = format!("sha256:{:x}", Sha256::digest(&data));
            d.size = data.len() as i64;
            f.1.ingest(data.as_slice(), &d, data.len() as u64, || false)
                .unwrap();
            f.1.open_verified(&d, data.len() as u64, || false).unwrap();
        }
        f.clean();
    }

    #[test]
    fn reader_error_cleans_temp() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("injected"))
            }
        }
        let f = Fixture::new();
        assert!(matches!(
            f.1.ingest(Broken, &descriptor(), 3, || false),
            Err(Error::Io(_))
        ));
        f.clean();
        assert!(!f.destination().exists());
    }

    #[test]
    fn reject_relative_and_parent_paths() {
        assert!(matches!(
            BlobStore::open("relative"),
            Err(Error::UnsafePath(_))
        ));
        let f = Fixture::new();
        assert!(matches!(
            BlobStore::open(f.0.join("..")),
            Err(Error::UnsafePath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlink_files_and_directories() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let sentinel = f.0.join("sentinel");
        fs::write(&sentinel, b"abc").unwrap();
        symlink(&sentinel, f.destination()).unwrap();
        assert!(matches!(
            f.1.open_verified(&descriptor(), 3, || false),
            Err(Error::UnsafePath(_))
        ));
        assert!(f.1.ingest(&b"abc"[..], &descriptor(), 3, || false).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"abc");
        let alias = f.0.join("alias");
        symlink(&f.0, &alias).unwrap();
        assert!(matches!(BlobStore::open(&alias), Err(Error::UnsafePath(_))));
        fs::remove_file(f.destination()).unwrap();
        fs::remove_dir(&f.1.directory).unwrap();
        symlink(&f.0, &f.1.directory).unwrap();
        assert!(matches!(
            f.1.ingest(&b"abc"[..], &descriptor(), 3, || false),
            Err(Error::UnsafePath(_))
        ));
    }
}
