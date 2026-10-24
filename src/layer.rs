//! Verified, seekable OCI layer spools; no extraction or rootfs mutation.
//!
//! The store and caller-created absolute spool directory (including ancestors)
//! must stay owned and stable, without hostile writers or path swaps. The owned
//! anonymous tempfile is never published by name and is removed on close, including
//! failure. Only this module can write it; `VerifiedLayer` exposes Read + Seek.
//! Success is not a durable cache publication. Blocking I/O needs caller timeouts;
//! cancellation is cooperative between reads and before returning the capability.
//!
//! Narrow format policy: POSIX USTAR regular files, directories and symlinks only.
//! PAX/GNU extensions (including base-256 numbers), sparse files, hardlinks,
//! devices and unknown types are rejected. USTAR octal sizes are below 8 GiB.
//! Symlink text is preserved, including absolute and `..` targets: future extraction
//! MUST resolve it within the image root. Archive paths themselves cannot escape.
//! Exactly one gzip member is accepted; any compressed suffix (even zeros or another
//! member) is rejected. All decompressed bytes, including tar padding, enter diffID.
//! Tar requires two zero end blocks and only whole zero blocks afterward.
//!
//! Payload transfer uses 64 KiB buffers. Metadata is NOT constant-memory: a Vec of
//! entries plus a duplicate-path set is bounded by `max_entries` and a logical byte
//! budget charging 512 bytes per header plus twice the canonical path and once the link text.
//! Allocator/container overhead is additionally O(max_entries). Gzip header bytes
//! have their own input cap, including optional names/comments. The decoder may
//! additionally preallocate an extra field of at most 65,535 bytes before reading it.
//! The decoder also limits each gzip name/comment field to 65,535 bytes.
//! Reference: https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md
//! Dependency API/source review: flate2 1.1.10 (MSRV 1.67), tar 0.4.46 and
//! tempfile 3.27.0 (MSRV 1.63), all MIT OR Apache-2.0; SHA-256 uses existing sha2.
//! No tar unpack API is used. This is not a claim of an independent security audit.

use crate::oci::{BlobStore, Descriptor, Sha256Digest};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt, fs,
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Component, Path},
};

const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Stored descriptor size limit, enforced by BlobStore before decompression.
    pub max_blob_bytes: u64,
    /// Includes headers, payload, entry padding and all tar end padding.
    pub max_uncompressed_bytes: u64,
    pub max_entries: usize,
    /// Logical metadata charge described in the module docs, not an RSS limit.
    pub max_metadata_bytes: u64,
    /// Entire gzip header including its fixed ten bytes and optional header CRC.
    pub max_gzip_header_bytes: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Blob(crate::oci::Error),
    UnsupportedMediaType(String),
    Invalid(&'static str),
    Limit(&'static str),
    DiffIdMismatch,
    Cancelled,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "layer I/O: {e}"),
            Self::Blob(e) => write!(f, "layer blob: {e}"),
            Self::UnsupportedMediaType(t) => write!(f, "unsupported layer media type: {t}"),
            Self::Invalid(s) => write!(f, "invalid or unsupported layer: {s}"),
            Self::Limit(s) => write!(f, "layer limit exceeded: {s}"),
            Self::DiffIdMismatch => f.write_str("layer uncompressed SHA-256 diffID mismatch"),
            Self::Cancelled => f.write_str("layer verification cancelled"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Blob(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

/// Byte paths use POSIX separators and are canonical relative paths; the root
/// directory has an empty path. Offsets address the verified uncompressed spool.
/// Whiteout files remain markers here, never deletions or extracted files.
#[derive(Debug)]
pub struct Entry {
    pub path: Vec<u8>,
    pub link_target: Option<Vec<u8>>,
    pub kind: EntryKind,
    pub data_offset: u64,
    pub size: u64,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
}

#[derive(Debug)]
pub struct VerifiedLayer {
    spool: File,
    diff_id: Sha256Digest,
    size: u64,
    entries: Vec<Entry>,
}
impl VerifiedLayer {
    pub fn diff_id(&self) -> &Sha256Digest {
        &self.diff_id
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}
impl Read for VerifiedLayer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.spool.read(buf)
    }
}
impl Seek for VerifiedLayer {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.spool.seek(pos)
    }
}

/// Opens/verifies the stored compressed blob itself; arbitrary File handles cannot
/// mint this capability. On success the spool is rewound and retained until drop.
/// Limits are per layer; callers must also bound concurrent layers and disk usage.
pub fn verify<C: Fn() -> bool>(
    store: &BlobStore,
    descriptor: &Descriptor,
    diff_id: &Sha256Digest,
    spool_dir: &Path,
    limits: Limits,
    cancelled: C,
) -> Result<VerifiedLayer, Error> {
    let gzip = match descriptor.media_type.as_str() {
        "application/vnd.oci.image.layer.v1.tar"
        | "application/vnd.oci.image.layer.nondistributable.v1.tar" => false,
        "application/vnd.oci.image.layer.v1.tar+gzip"
        | "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip" => true,
        _ => return Err(Error::UnsupportedMediaType(descriptor.media_type.clone())),
    };
    check_cancel(&cancelled)?;
    check_directory(spool_dir)?;
    let input = store
        .open_verified(descriptor, limits.max_blob_bytes, &cancelled)
        .map_err(|e| match e {
            crate::oci::Error::Cancelled => Error::Cancelled,
            e => Error::Blob(e),
        })?;
    let result = spool(input, gzip, diff_id, spool_dir, limits, &cancelled);
    check_cancel(&cancelled)?;
    result
}

#[cfg(unix)]
fn anonymous_spool(dir: &Path, unlink: impl FnOnce(&Path) -> io::Result<()>) -> io::Result<File> {
    let (file, path) = tempfile::NamedTempFile::new_in(dir)?.into_parts();
    // Do not write payload until unlink succeeds. TempPath retries cleanup on error.
    unlink(&path)?;
    drop(path);
    Ok(file)
}

fn spool<R: Read>(
    input: R,
    gzip: bool,
    diff_id: &Sha256Digest,
    dir: &Path,
    limits: Limits,
    cancelled: &impl Fn() -> bool,
) -> Result<VerifiedLayer, Error> {
    #[cfg(unix)]
    let mut output = anonymous_spool(dir, |path| fs::remove_file(path))?;
    #[cfg(not(unix))]
    let mut output = tempfile::tempfile_in(dir)?;
    let guarded = Guarded {
        inner: BufReader::with_capacity(
            BUFFER_SIZE,
            RetryRead {
                inner: input,
                cancelled,
            },
        ),
        cancelled,
        header_remaining: if gzip {
            Some(limits.max_gzip_header_bytes)
        } else {
            None
        },
    };
    let size = if gzip {
        let mut decoder = GzDecoder::new(guarded);
        // Construction consumes only the header, under a byte budget. If parsing
        // failed, read() reports the decoder's saved error without lifting the cap.
        if decoder.header().is_some() {
            decoder.get_mut().header_remaining = None;
        } else if decoder.get_ref().header_remaining == Some(0) {
            return Err(Error::Limit("gzip header bytes"));
        }
        let size = copy_hash(
            &mut decoder,
            &mut output,
            diff_id,
            limits.max_uncompressed_bytes,
            cancelled,
        )?;
        if !decoder.into_inner().fill_buf()?.is_empty() {
            return Err(Error::Invalid("gzip suffix or concatenated members"));
        }
        size
    } else {
        copy_hash(
            &mut { guarded },
            &mut output,
            diff_id,
            limits.max_uncompressed_bytes,
            cancelled,
        )?
    };
    output.seek(SeekFrom::Start(0))?;
    let entries = inspect(&mut output, size, limits, cancelled)?;
    output.seek(SeekFrom::Start(0))?;
    check_cancel(cancelled)?;
    Ok(VerifiedLayer {
        spool: output,
        diff_id: diff_id.clone(),
        size,
        entries,
    })
}

// BufRead consumption, not prefetch, budgets gzip headers. This also checks
// cancellation while a decoder consumes many compressed bytes without output.
struct RetryRead<'a, R, C> {
    inner: R,
    cancelled: &'a C,
}
impl<R: Read, C: Fn() -> bool> Read for RetryRead<'_, R, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if (self.cancelled)() {
                return Err(io::Error::other("layer cancelled"));
            }
            match self.inner.read(buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
}

struct Guarded<'a, R, C> {
    inner: BufReader<R>,
    cancelled: &'a C,
    header_remaining: Option<u64>,
}
impl<R: Read, C: Fn() -> bool> BufRead for Guarded<'_, R, C> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if (self.cancelled)() {
            return Err(io::Error::other("layer cancelled"));
        }
        if self.header_remaining == Some(0) {
            return Err(io::Error::other("gzip header byte limit"));
        }
        let bytes = self.inner.fill_buf()?;
        let len = self
            .header_remaining
            .unwrap_or(u64::MAX)
            .min(bytes.len() as u64) as usize;
        Ok(&bytes[..len])
    }
    fn consume(&mut self, n: usize) {
        if let Some(left) = &mut self.header_remaining {
            *left -= n as u64;
        }
        self.inner.consume(n);
    }
}
impl<R: Read, C: Fn() -> bool> Read for Guarded<'_, R, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let bytes = self.fill_buf()?;
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        self.consume(n);
        Ok(n)
    }
}

fn copy_hash(
    reader: &mut impl Read,
    output: &mut impl Write,
    expected: &Sha256Digest,
    max: u64,
    cancelled: &impl Fn() -> bool,
) -> Result<u64, Error> {
    let mut buffer = [0; BUFFER_SIZE];
    let mut hash = Sha256::new();
    let mut size = 0;
    loop {
        check_cancel(cancelled)?;
        let limit = (max - size).min(BUFFER_SIZE as u64 - 1) as usize + 1;
        let result = reader.read(&mut buffer[..limit]);
        check_cancel(cancelled)?;
        let n = match result {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break;
        }
        if n as u64 > max - size {
            return Err(Error::Limit("uncompressed bytes"));
        }
        size += n as u64;
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    if format!("{:x}", hash.finalize()) != expected.encoded() {
        return Err(Error::DiffIdMismatch);
    }
    Ok(size)
}

fn inspect(
    file: &mut File,
    size: u64,
    limits: Limits,
    cancelled: &impl Fn() -> bool,
) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    let mut paths = BTreeSet::new();
    let mut metadata = 0u64;
    let mut offset = 0u64;
    let mut ended = false;
    let mut zero_blocks = 0u64;
    while offset < size {
        check_cancel(cancelled)?;
        let mut block = [0u8; 512];
        file.read_exact(&mut block)?;
        offset += 512;
        if block == [0; 512] {
            ended = true;
            zero_blocks += 1;
            continue;
        }
        if ended {
            return Err(Error::Invalid("nonzero data after tar end marker"));
        }
        if entries.len() >= limits.max_entries {
            return Err(Error::Limit("entry count"));
        }
        let header = tar::Header::from_byte_slice(&block);
        if &block[257..263] != b"ustar\0" || &block[263..265] != b"00" {
            return Err(Error::Invalid("only POSIX USTAR headers are supported"));
        }
        let checksum: u32 = block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u32
                }
            })
            .sum();
        if header.cksum()? != checksum {
            return Err(Error::Invalid("tar header checksum"));
        }
        // Reject binary numeric extensions: the tar crate's u64 accessor can
        // discard high bytes of a wider base-256 field. Also reject hidden tails.
        for range in [100..108, 108..116, 116..124, 124..136, 136..148, 148..156] {
            let field = &block[range];
            if !matches!(field.last(), Some(0 | b' '))
                || field.iter().any(|b| !matches!(b, b'0'..=b'7' | b' ' | 0))
                || field
                    .iter()
                    .position(|b| *b == 0)
                    .is_some_and(|nul| field[nul..].iter().any(|b| !matches!(b, 0 | b' ')))
            {
                return Err(Error::Invalid("non-octal or ambiguous tar numeric field"));
            }
        }
        if block[329..345]
            .iter()
            .any(|b| !matches!(b, 0 | b'0' | b' '))
        {
            return Err(Error::Invalid("device numbers on unsupported entry"));
        }
        // Reject hidden string suffixes rather than letting different readers
        // interpret different paths. USTAR has no extensions in its reserved tail.
        for range in [0..100, 157..257, 265..297, 297..329, 345..500] {
            let field = &block[range];
            if let Some(nul) = field.iter().position(|b| *b == 0)
                && field[nul..].iter().any(|b| *b != 0)
            {
                return Err(Error::Invalid(
                    "nonzero bytes after USTAR string terminator",
                ));
            }
        }
        if block[500..].iter().any(|b| *b != 0) {
            return Err(Error::Invalid("USTAR reserved bytes"));
        }
        let kind = match header.entry_type().as_byte() {
            0 | b'0' => EntryKind::File,
            b'5' => EntryKind::Directory,
            b'2' => EntryKind::Symlink,
            _ => {
                return Err(Error::Invalid(
                    "tar entry type (extensions, sparse, hardlinks and special files unsupported)",
                ));
            }
        };
        let length = header.size()?;
        if kind != EntryKind::File && length != 0 {
            return Err(Error::Invalid("payload on non-regular entry"));
        }
        let path = canonical_path(&header.path_bytes(), kind)?;
        let link = header.link_name_bytes().map(|s| s.into_owned());
        if (kind == EntryKind::Symlink) != link.as_ref().is_some_and(|s| !s.is_empty()) {
            return Err(Error::Invalid(
                "missing symlink target or link text on non-symlink",
            ));
        }
        validate_whiteout(&path, kind, length)?;
        let charge = 512 + 2 * path.len() as u64 + link.as_ref().map_or(0, |s| s.len() as u64);
        metadata = metadata
            .checked_add(charge)
            .ok_or(Error::Limit("metadata bytes"))?;
        if metadata > limits.max_metadata_bytes {
            return Err(Error::Limit("metadata bytes"));
        }
        if !paths.insert(path.clone()) {
            return Err(Error::Invalid("duplicate normalized tar path"));
        }
        let entry = Entry {
            path,
            link_target: link,
            kind,
            data_offset: offset,
            size: length,
            mode: header.mode()?,
            uid: header.uid()?,
            gid: header.gid()?,
            mtime: header.mtime()?,
        };
        if entry.mode > 0o7777 {
            return Err(Error::Invalid("unsupported tar mode bits"));
        }
        let padded = length
            .checked_add(511)
            .map(|v| v / 512 * 512)
            .ok_or(Error::Invalid("tar size overflow"))?;
        let next = offset
            .checked_add(padded)
            .filter(|v| *v <= size)
            .ok_or(Error::Invalid("truncated tar payload"))?;
        // Payload was already streamed and hashed. Seek over it, but check padding.
        file.seek(SeekFrom::Start(offset + length))?;
        let padding = (padded - length) as usize;
        file.read_exact(&mut block[..padding])?;
        if block[..padding].iter().any(|b| *b != 0) {
            return Err(Error::Invalid("nonzero tar entry padding"));
        }
        offset = next;
        entries.push(entry);
    }
    if zero_blocks < 2 {
        return Err(Error::Invalid("missing two-block tar end marker"));
    }
    Ok(entries)
}

fn canonical_path(raw: &[u8], kind: EntryKind) -> Result<Vec<u8>, Error> {
    if raw.is_empty() || raw.starts_with(b"/") || raw.contains(&0) {
        return Err(Error::Invalid("unsafe archive path"));
    }
    let mut path = Vec::with_capacity(raw.len());
    for part in raw.split(|b| *b == b'/') {
        if part == b".." {
            return Err(Error::Invalid("parent component in archive path"));
        }
        if part.is_empty() || part == b"." {
            continue;
        }
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(part);
    }
    if path.is_empty() && kind != EntryKind::Directory {
        return Err(Error::Invalid("non-directory root entry"));
    }
    if raw.ends_with(b"/") && kind != EntryKind::Directory {
        return Err(Error::Invalid("non-directory trailing slash"));
    }
    Ok(path)
}

fn validate_whiteout(path: &[u8], kind: EntryKind, size: u64) -> Result<(), Error> {
    let mut parts = path.split(|b| *b == b'/').peekable();
    while let Some(part) = parts.next() {
        if let Some(target) = part.strip_prefix(b".wh.")
            && (parts.peek().is_some()
                || kind != EntryKind::File
                || size != 0
                || target.is_empty()
                || target == b"."
                || target == b".."
                || (target.starts_with(b".wh.") && part != b".wh..wh..opq"))
        {
            return Err(Error::Invalid("unsupported or malformed whiteout"));
        }
    }
    Ok(())
}
fn check_cancel(cancelled: &impl Fn() -> bool) -> Result<(), Error> {
    if cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn check_directory(path: &Path) -> Result<(), Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(Error::Invalid(
            "spool directory must be absolute without dot components",
        ));
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(Error::Invalid("spool directory reparse point"));
            }
        }
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(Error::Invalid("spool directory link or non-directory"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn spool_requires_successful_unlink_before_use() {
        let dir = tempfile::tempdir().unwrap();
        let failure = anonymous_spool(dir.path(), |_| {
            Err(io::Error::other("injected unlink failure"))
        });
        assert!(failure.is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        let file = anonymous_spool(dir.path(), |path| fs::remove_file(path)).unwrap();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        drop(file);
    }

    #[test]
    fn posix_colons_and_backslashes_are_preserved() {
        let f = Fixture::new();
        for path in ["a:b", "a\\b", "C:/entry"] {
            let mut h = header("placeholder", b'0', 0, None);
            h.as_mut_bytes()[..100].fill(0);
            h.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            h.set_cksum();
            let bytes = archive(vec![(h, vec![])]);
            let verified = f.verify(&bytes, false, &digest(&bytes), limits()).unwrap();
            assert_eq!(verified.entries()[0].path, path.as_bytes());
        }
    }
    use flate2::{Compression, write::GzEncoder};
    use std::{cell::Cell, io::Cursor};

    fn limits() -> Limits {
        Limits {
            max_blob_bytes: 8 * 1024 * 1024,
            max_uncompressed_bytes: 8 * 1024 * 1024,
            max_entries: 100,
            max_metadata_bytes: 64 * 1024,
            max_gzip_header_bytes: 4096,
        }
    }
    fn digest(bytes: &[u8]) -> Sha256Digest {
        format!("sha256:{:x}", Sha256::digest(bytes))
            .parse()
            .unwrap()
    }
    fn header(path: &str, kind: u8, size: u64, link: Option<&str>) -> tar::Header {
        let mut h = tar::Header::new_ustar();
        h.set_path(path).unwrap();
        h.set_entry_type(tar::EntryType::new(kind));
        h.set_size(size);
        h.set_mode(0o755);
        h.set_uid(123);
        h.set_gid(456);
        h.set_mtime(789);
        if let Some(link) = link {
            h.set_link_name(link).unwrap();
        }
        h.set_cksum();
        h
    }
    fn archive(items: Vec<(tar::Header, Vec<u8>)>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (h, payload) in items {
            bytes.extend_from_slice(h.as_bytes());
            bytes.extend_from_slice(&payload);
            bytes.resize(bytes.len().next_multiple_of(512), 0);
        }
        bytes.extend_from_slice(&[0; 1024]);
        bytes
    }
    fn sample() -> Vec<u8> {
        let content: Vec<_> = (0..BUFFER_SIZE * 3 + 19).map(|i| (i % 251) as u8).collect();
        archive(vec![(
            header("data", b'0', content.len() as u64, None),
            content,
        )])
    }
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }
    struct Fixture {
        root: tempfile::TempDir,
        store: BlobStore,
        spool: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let path = fs::canonicalize(root.path()).unwrap();
            let store = BlobStore::open(&path).unwrap();
            let spool = path.join("spool");
            fs::create_dir(&spool).unwrap();
            Self { root, store, spool }
        }
        fn descriptor(&self, bytes: &[u8], gz: bool) -> Descriptor {
            let d = Descriptor {
                media_type: format!(
                    "application/vnd.oci.image.layer.v1.tar{}",
                    if gz { "+gzip" } else { "" }
                ),
                digest: digest(bytes).to_string(),
                size: bytes.len() as i64,
                annotations: Default::default(),
                extensions: Default::default(),
            };
            self.store
                .ingest(bytes, &d, bytes.len() as u64, || false)
                .unwrap();
            d
        }
        fn verify(
            &self,
            bytes: &[u8],
            gz: bool,
            expected: &Sha256Digest,
            l: Limits,
        ) -> Result<VerifiedLayer, Error> {
            verify(
                &self.store,
                &self.descriptor(bytes, gz),
                expected,
                &self.spool,
                l,
                || false,
            )
        }
        fn clean(&self) {
            assert_eq!(fs::read_dir(&self.spool).unwrap().count(), 0);
        }
    }
    #[test]
    fn valid_plain_and_gzip_seekable_large_streams_and_lifetime() {
        let f = Fixture::new();
        let bytes = sample();
        for gz in [false, true] {
            let encoded = if gz { gzip(&bytes) } else { bytes.clone() };
            let mut layer = f.verify(&encoded, gz, &digest(&bytes), limits()).unwrap();
            assert_eq!(layer.diff_id(), &digest(&bytes));
            assert_eq!(layer.size(), bytes.len() as u64);
            let entry = &layer.entries()[0];
            assert_eq!(
                (&entry.path[..], entry.uid, entry.gid, entry.mtime),
                (&b"data"[..], 123, 456, 789)
            );
            let offset = entry.data_offset;
            // Blob lifetime is independent of the successful spool.
            fs::remove_file(
                f.root
                    .path()
                    .join("blobs/sha256")
                    .join(digest(&encoded).encoded()),
            )
            .unwrap();
            let mut readback = Vec::new();
            layer.read_to_end(&mut readback).unwrap();
            assert_eq!(readback, bytes);
            layer.seek(SeekFrom::Start(offset)).unwrap();
            let mut data = [0; 251];
            layer.read_exact(&mut data).unwrap();
            assert_eq!(data, std::array::from_fn(|i| i as u8));
            drop(layer);
            f.clean();
        }
    }
    #[test]
    fn rejects_corrupted_truncated_and_suffixed_gzip() {
        let f = Fixture::new();
        let bytes = sample();
        let encoded = gzip(&bytes);
        let mut corrupt = encoded.clone();
        let n = corrupt.len();
        corrupt[n - 8] ^= 1; // CRC, while the stored blob's digest is valid.
        let mut bad_size = encoded.clone();
        bad_size[n - 4] ^= 1;
        let mut suffix = encoded.clone();
        suffix.push(0);
        let mut concat = encoded.clone();
        concat.extend(gzip(&[]));
        for invalid in [
            corrupt,
            bad_size,
            encoded[..n - 1].to_vec(),
            encoded[..n / 2].to_vec(),
            suffix,
            concat,
        ] {
            assert!(f.verify(&invalid, true, &digest(&bytes), limits()).is_err());
            f.clean();
        }
    }
    #[test]
    fn rejects_diffid_and_uncompressed_bomb_cap() {
        let f = Fixture::new();
        let bytes = sample();
        assert!(matches!(
            f.verify(&bytes, false, &digest(b"wrong"), limits()),
            Err(Error::DiffIdMismatch)
        ));
        let bomb = archive(vec![(
            header("bomb", b'0', 1024 * 1024, None),
            vec![0; 1024 * 1024],
        )]);
        let mut l = limits();
        l.max_uncompressed_bytes = 4096;
        for gz in [false, true] {
            let encoded = if gz { gzip(&bomb) } else { bomb.clone() };
            assert!(matches!(
                f.verify(&encoded, gz, &digest(&bomb), l),
                Err(Error::Limit("uncompressed bytes"))
            ));
        }
        f.clean();
    }
    #[test]
    fn strict_tar_end_payload_padding_and_checksum() {
        let f = Fixture::new();
        let bytes = archive(vec![(header("x", b'0', 1, None), vec![42])]);
        let mut suffix = bytes.clone();
        suffix.extend_from_slice(&[1; 512]);
        let mut partial_zero_suffix = bytes.clone();
        partial_zero_suffix.push(0);
        let mut padding = bytes.clone();
        padding[513] = 1;
        let mut checksum = bytes.clone();
        checksum[10] ^= 1;
        for invalid in [
            bytes[..600].to_vec(),
            bytes[..1024].to_vec(),
            bytes[..1536].to_vec(),
            suffix,
            partial_zero_suffix,
            padding,
            checksum,
        ] {
            assert!(
                f.verify(&invalid, false, &digest(&invalid), limits())
                    .is_err()
            );
            f.clean();
        }
        let mut padded = bytes;
        padded.extend_from_slice(&[0; 512]);
        assert!(f.verify(&padded, false, &digest(&padded), limits()).is_ok());
        assert!(
            f.verify(&[0; 1024], false, &digest(&[0; 1024]), limits())
                .is_ok()
        );
    }
    #[test]
    fn caps_metadata_entries_and_gzip_headers() {
        let f = Fixture::new();
        let bytes = sample();
        let mut l = limits();
        l.max_entries = 0;
        assert!(matches!(
            f.verify(&bytes, false, &digest(&bytes), l),
            Err(Error::Limit("entry count"))
        ));
        l = limits();
        l.max_metadata_bytes = 511;
        assert!(matches!(
            f.verify(&bytes, false, &digest(&bytes), l),
            Err(Error::Limit("metadata bytes"))
        ));
        let mut encoded = gzip(&bytes);
        encoded[3] |= 8; // FNAME, before deflate data.
        encoded.splice(10..10, std::iter::repeat_n(b'x', 5000).chain([0]));
        assert!(f.verify(&encoded, true, &digest(&bytes), limits()).is_err());
        let mut encoder = flate2::GzBuilder::new()
            .filename("normal.tar")
            .write(Vec::new(), Compression::default());
        encoder.write_all(&bytes).unwrap();
        assert!(
            f.verify(&encoder.finish().unwrap(), true, &digest(&bytes), limits())
                .is_ok()
        );
        f.clean();
    }
    #[test]
    fn symlinks_and_whiteouts_are_metadata_only() {
        let f = Fixture::new();
        let bytes = archive(vec![
            (header("./", b'5', 0, None), vec![]),
            (header("bin", b'2', 0, Some("/usr/bin")), vec![]),
            (
                header("relative", b'2', 0, Some("../outside-or-broken")),
                vec![],
            ),
            (header("dir/new", b'0', 0, None), vec![]),
            (header("dir/.wh..wh..opq", b'0', 0, None), vec![]),
            (header(".wh.deleted", b'0', 0, None), vec![]),
        ]);
        let layer = f.verify(&bytes, false, &digest(&bytes), limits()).unwrap();
        assert!(layer.entries()[0].path.is_empty());
        assert_eq!(
            layer.entries()[1].link_target.as_deref(),
            Some(&b"/usr/bin"[..])
        );
        assert_eq!(
            layer.entries()[2].link_target.as_deref(),
            Some(&b"../outside-or-broken"[..])
        );
        assert_eq!(layer.entries()[4].path, b"dir/.wh..wh..opq");
        assert!(!f.root.path().join("dir").exists());
    }
    #[test]
    fn rejects_unsafe_paths_duplicates_extensions_and_special_entries() {
        let f = Fixture::new();
        for path in ["/escape", "../escape", "a/../escape"] {
            let mut h = header("placeholder", b'0', 0, None);
            h.as_mut_bytes()[..100].fill(0);
            h.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            h.set_cksum();
            let bytes = archive(vec![(h, vec![])]);
            assert!(
                f.verify(&bytes, false, &digest(&bytes), limits()).is_err(),
                "{path}"
            );
        }
        for kind in [
            b'1', b'3', b'4', b'6', b'7', b'x', b'g', b'L', b'K', b'S', b'Z',
        ] {
            let bytes = archive(vec![(header("entry", kind, 0, None), vec![])]);
            assert!(
                f.verify(&bytes, false, &digest(&bytes), limits()).is_err(),
                "{kind}"
            );
        }
        let bytes = archive(vec![
            (header("x", b'0', 0, None), vec![]),
            (header("./x", b'0', 0, None), vec![]),
        ]);
        assert!(matches!(
            f.verify(&bytes, false, &digest(&bytes), limits()),
            Err(Error::Invalid("duplicate normalized tar path"))
        ));
        for (path, kind, payload, link) in [
            (".wh.", b'0', vec![], None),
            (".wh.x", b'0', vec![1], None),
            (".wh.x", b'2', vec![], Some("/target")),
            (".wh.x/child", b'0', vec![], None),
            ("link", b'2', vec![1], Some("target")),
            ("link", b'2', vec![], None),
            ("file", b'0', vec![], Some("target")),
        ] {
            let bytes = archive(vec![(
                header(path, kind, payload.len() as u64, link),
                payload,
            )]);
            assert!(f.verify(&bytes, false, &digest(&bytes), limits()).is_err());
        }
        f.clean();
    }
    #[test]
    fn rejects_ambiguous_numeric_headers_and_non_ustar_formats() {
        let f = Fixture::new();
        for (offset, value) in [
            (124, 0x80),
            (125, 0xff),
            (100, b'9'),
            (329, b'1'),
            (263, b'1'),
            (500, b'x'),
        ] {
            let mut h = header("x", b'0', 0, None);
            h.as_mut_bytes()[offset] = value;
            h.set_cksum();
            let bytes = archive(vec![(h, vec![])]);
            assert!(f.verify(&bytes, false, &digest(&bytes), limits()).is_err());
        }
        let mut h = header("x", b'0', 0, None);
        h.as_mut_bytes()[126] = 0;
        h.as_mut_bytes()[127] = b'1';
        h.set_cksum();
        let bytes = archive(vec![(h, vec![])]);
        assert!(f.verify(&bytes, false, &digest(&bytes), limits()).is_err());
        f.clean();
    }
    struct ShortReads<R> {
        inner: R,
        calls: usize,
    }
    impl<R: Read> Read for ShortReads<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls.is_multiple_of(7) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = buf.len().min(7);
            self.inner.read(&mut buf[..n])
        }
    }
    #[test]
    fn handles_short_reads_interrupted_reads_and_cancellation_cleanup() {
        let f = Fixture::new();
        let bytes = sample();
        for gz in [false, true] {
            let encoded = if gz { gzip(&bytes) } else { bytes.clone() };
            let input = ShortReads {
                inner: Cursor::new(&encoded),
                calls: 0,
            };
            assert!(spool(input, gz, &digest(&bytes), &f.spool, limits(), &|| false).is_ok());
            let checks = Cell::new(0);
            let cancel = || {
                checks.set(checks.get() + 1);
                checks.get() > 15
            };
            let input = ShortReads {
                inner: Cursor::new(&encoded),
                calls: 0,
            };
            assert!(matches!(
                spool(input, gz, &digest(&bytes), &f.spool, limits(), &cancel),
                Err(Error::Cancelled)
            ));
            f.clean();
        }
        let d = f.descriptor(&bytes, false);
        assert!(matches!(
            verify(&f.store, &d, &digest(&bytes), &f.spool, limits(), || true),
            Err(Error::Cancelled)
        ));
        let checks = Cell::new(0);
        let mut file = tempfile::tempfile_in(&f.spool).unwrap();
        file.write_all(&bytes).unwrap();
        file.rewind().unwrap();
        assert!(matches!(
            inspect(&mut file, bytes.len() as u64, limits(), &|| {
                checks.set(checks.get() + 1);
                checks.get() > 1
            }),
            Err(Error::Cancelled)
        ));
    }
    #[test]
    fn verified_blob_required_and_unsupported_media_rejected() {
        let f = Fixture::new();
        let bytes = sample();
        let mut d = f.descriptor(&bytes, false);
        let blob = f
            .root
            .path()
            .join("blobs/sha256")
            .join(digest(&bytes).encoded());
        fs::write(blob, b"corrupt").unwrap();
        assert!(matches!(
            verify(&f.store, &d, &digest(&bytes), &f.spool, limits(), || false),
            Err(Error::Blob(_))
        ));
        for media in [
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
        ] {
            d.media_type = media.into();
            assert!(matches!(
                verify(&f.store, &d, &digest(&bytes), &f.spool, limits(), || false),
                Err(Error::UnsupportedMediaType(_))
            ));
        }
        f.clean();
    }
    #[test]
    fn write_failure_propagates_and_cap_probes_only_one_byte() {
        struct NoSpace;
        impl Write for NoSpace {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(28))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(matches!(
            copy_hash(
                &mut Cursor::new(b"abc"),
                &mut NoSpace,
                &digest(b"abc"),
                3,
                &|| false
            ),
            Err(Error::Io(_))
        ));
        let mut input = Cursor::new(vec![0; BUFFER_SIZE * 2]);
        let mut output = Vec::new();
        assert!(matches!(
            copy_hash(&mut input, &mut output, &digest(&[]), 10, &|| false),
            Err(Error::Limit(_))
        ));
        assert_eq!(input.position(), 11);
        assert!(output.is_empty());
    }
}
