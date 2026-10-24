//! Verified, seekable OCI layer spools; no extraction or rootfs mutation.
//!
//! The store and caller-created absolute spool directory (including ancestors)
//! must stay owned and stable, without hostile writers or path swaps. The owned
//! anonymous tempfile is never published by name and is removed on close, including
//! failure. Only this module can write it; `VerifiedLayer` exposes Read + Seek.
//! Success is not a durable cache publication. Blocking I/O needs caller timeouts;
//! cancellation is cooperative between reads and before returning the capability.
//!
//! Supports USTAR/GNU ordinary entries, local PAX and GNU long names/links.
//! Sparse, device, global PAX and unknown semantic extensions are rejected.
//! Link targets are preserved without resolution, including forward/lower-layer links.
//! RFC 1952 gzip member sequences are accepted; non-member suffixes are rejected.
//! All decompressed bytes enter diffID. Tar ends with two whole zero blocks.
//!
//! Payload transfer uses 64 KiB buffers. Metadata accounting is cumulative:
//! every physical header costs 512 bytes; extension payloads cost twice their size,
//! every PAX record costs 128 bytes, and effective strings are charged before copying.
//! Overwritten/deleted records are not refunded. max_entries bounds physical nonzero
//! headers (including extensions), not just returned entries. Payload sizes are u64,
//! bounded by max_uncompressed_bytes and checked framing, without an 8 GiB cap.
//! Container overhead is also bounded by header/record charges. Gzip header bytes
//! have an aggregate input cap across all members, including optional names/comments.
//! Each member costs at least ten header bytes, bounding empty-member floods too.
//! The decoder may preallocate an extra field of at most 65,535 bytes before reading it.
//! The decoder also limits each gzip name/comment field to 65,535 bytes.
//! Reference: https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md
//! Dependency API/source review: flate2 1.1.10 (MSRV 1.67), tar 0.4.46 and
//! tempfile 3.27.0 (MSRV 1.63), all MIT OR Apache-2.0; SHA-256 uses existing sha2.
//! No tar unpack API is used. This is not a claim of an independent security audit.

use crate::oci::{BlobStore, Descriptor, Sha256Digest};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
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
    /// Physical nonzero headers, including PAX/GNU extension headers.
    pub max_entries: usize,
    /// Logical metadata charge described in the module docs, not an RSS limit.
    pub max_metadata_bytes: u64,
    /// Sum of all gzip headers, including each fixed ten bytes and optional CRC.
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
    Hardlink,
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
    pub mtime: Timestamp,
    pub atime: Option<Timestamp>,
    pub ctime: Option<Timestamp>,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Supported informational PAX records (currently comment).
    pub pax_records: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Exact signed decimal seconds. Fraction contains ASCII digits, with trailing
/// zeros removed; negative applies to the entire magnitude, including -0.fraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub negative: bool,
    pub seconds: u64,
    pub fraction: Vec<u8>,
}
impl Timestamp {
    fn integer(value: i128) -> Result<Self, Error> {
        Ok(Self {
            negative: value < 0,
            seconds: u64::try_from(value.unsigned_abs())
                .map_err(|_| Error::Invalid("timestamp overflow"))?,
            fraction: Vec::new(),
        })
    }
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
    let mut guarded = Guarded {
        inner: BufReader::with_capacity(
            BUFFER_SIZE,
            RetryRead {
                inner: input,
                cancelled,
            },
        ),
        cancelled,
        header_remaining: None,
    };
    let mut hash = Sha256::new();
    let mut size = 0;
    if gzip {
        let mut header_remaining = limits.max_gzip_header_bytes;
        loop {
            check_cancel(cancelled)?;
            guarded.header_remaining = Some(header_remaining);
            let mut decoder = GzDecoder::new(guarded);
            check_cancel(cancelled)?;
            // Construction consumes only this member's header. Keep the unused
            // aggregate budget before lifting the cap for its body and trailer.
            if decoder.header().is_some() {
                header_remaining = decoder.get_mut().header_remaining.take().unwrap();
            } else if decoder.get_ref().header_remaining == Some(0) {
                return Err(Error::Limit("gzip header bytes"));
            }
            copy_hash(
                &mut decoder,
                &mut output,
                &mut hash,
                &mut size,
                limits.max_uncompressed_bytes,
                cancelled,
            )?;
            // EOF validates this member's CRC/ISIZE. Preserve prefetched bytes
            // for the next header; any junk or truncated member must fail there.
            guarded = decoder.into_inner();
            let end = guarded.fill_buf().map(|bytes| bytes.is_empty());
            check_cancel(cancelled)?;
            if end? {
                break;
            }
        }
    } else {
        copy_hash(
            &mut guarded,
            &mut output,
            &mut hash,
            &mut size,
            limits.max_uncompressed_bytes,
            cancelled,
        )?;
    }
    if format!("{:x}", hash.finalize()) != diff_id.encoded() {
        return Err(Error::DiffIdMismatch);
    }
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
    hash: &mut Sha256,
    size: &mut u64,
    max: u64,
    cancelled: &impl Fn() -> bool,
) -> Result<(), Error> {
    let mut buffer = [0; BUFFER_SIZE];
    loop {
        check_cancel(cancelled)?;
        let limit = (max - *size).min(BUFFER_SIZE as u64 - 1) as usize + 1;
        let result = reader.read(&mut buffer[..limit]);
        check_cancel(cancelled)?;
        let n = match result {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break;
        }
        if n as u64 > max - *size {
            return Err(Error::Limit("uncompressed bytes"));
        }
        *size += n as u64;
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    Ok(())
}

fn charge(total: &mut u64, amount: u64, limits: Limits) -> Result<(), Error> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= limits.max_metadata_bytes)
        .ok_or(Error::Limit("metadata bytes"))?;
    Ok(())
}

// Decode every byte, including the sign bit below the base-256 marker. Never
// truncate a wide field to the low eight bytes as some convenience APIs do.
fn number(field: &[u8]) -> Result<i128, Error> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut n = if field[0] & 0x40 != 0 { -1i128 } else { 0 };
        for (i, byte) in field.iter().enumerate() {
            let (base, digit) = if i == 0 {
                (128, byte & 0x7f)
            } else {
                (256, *byte)
            };
            n = n
                .checked_mul(base)
                .and_then(|n| n.checked_add(digit as i128))
                .ok_or(Error::Invalid("base-256 overflow"))?;
        }
        return Ok(n);
    }
    let mut n = 0i128;
    let mut digits = false;
    let mut ended = false;
    for &b in field {
        match b {
            b'0'..=b'7' if !ended => {
                digits = true;
                n = n
                    .checked_mul(8)
                    .and_then(|n| n.checked_add((b - b'0') as i128))
                    .ok_or(Error::Invalid("octal overflow"))?;
            }
            0 => ended = true,
            b' ' => {
                if digits {
                    ended = true;
                }
            }
            _ => return Err(Error::Invalid("non-octal or ambiguous tar numeric field")),
        }
    }
    Ok(n)
}
fn unsigned(field: &[u8]) -> Result<u64, Error> {
    u64::try_from(number(field)?).map_err(|_| Error::Invalid("negative or overflowing tar number"))
}
fn decimal(bytes: &[u8]) -> Result<u64, Error> {
    if bytes.is_empty() {
        return Err(Error::Invalid("empty decimal"));
    }
    bytes.iter().try_fold(0u64, |n, b| {
        if !b.is_ascii_digit() {
            return Err(Error::Invalid("invalid decimal"));
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add((b - b'0') as u64))
            .ok_or(Error::Invalid("decimal overflow"))
    })
}
fn timestamp(bytes: &[u8]) -> Result<Timestamp, Error> {
    let negative = bytes.starts_with(b"-");
    let bytes = if negative { &bytes[1..] } else { bytes };
    let dot = bytes.iter().position(|b| *b == b'.');
    let (whole, fraction) = match dot {
        Some(i) => (&bytes[..i], &bytes[i + 1..]),
        None => (bytes, &b""[..]),
    };
    if dot.is_some() && fraction.is_empty() || !fraction.iter().all(u8::is_ascii_digit) {
        return Err(Error::Invalid("invalid timestamp fraction"));
    }
    let seconds = decimal(whole)?;
    let end = fraction
        .iter()
        .rposition(|b| *b != b'0')
        .map_or(0, |i| i + 1);
    Ok(Timestamp {
        negative: negative && (seconds != 0 || end != 0),
        seconds,
        fraction: fraction[..end].to_vec(),
    })
}
fn string(field: &[u8]) -> Result<&[u8], Error> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    if field[end..].iter().any(|b| *b != 0) {
        return Err(Error::Invalid("nonzero bytes after tar string terminator"));
    }
    Ok(&field[..end])
}
fn framing(offset: u64, length: u64, size: u64) -> Result<(u64, u64), Error> {
    let end = offset
        .checked_add(length)
        .ok_or(Error::Invalid("tar size overflow"))?;
    let next = end
        .checked_add((512 - length % 512) % 512)
        .filter(|n| *n <= size)
        .ok_or(Error::Invalid("truncated tar payload"))?;
    Ok((end, next))
}
fn pax(
    payload: &[u8],
    records: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    metadata: &mut u64,
    limits: Limits,
) -> Result<(), Error> {
    let mut rest = payload;
    while !rest.is_empty() {
        charge(metadata, 128, limits)?;
        let space = rest
            .iter()
            .position(|b| *b == b' ')
            .ok_or(Error::Invalid("PAX record length"))?;
        let len = usize::try_from(decimal(&rest[..space])?)
            .map_err(|_| Error::Invalid("PAX length overflow"))?;
        if len <= space + 2 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err(Error::Invalid("PAX record framing"));
        }
        let record = &rest[space + 1..len - 1];
        let eq = record
            .iter()
            .position(|b| *b == b'=')
            .ok_or(Error::Invalid("PAX assignment"))?;
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        if key.is_empty() || key.iter().any(|b| matches!(b, 0 | b'\n')) {
            return Err(Error::Invalid("PAX key"));
        }
        if key.starts_with(b"GNU.sparse.") || matches!(key, b"SCHILY.realsize" | b"SUN.holesdata") {
            return Err(Error::Invalid("sparse PAX extension"));
        }
        if let Some(name) = key.strip_prefix(b"SCHILY.xattr.") {
            if name.is_empty() {
                return Err(Error::Invalid("empty xattr name"));
            }
        } else if !matches!(
            key,
            b"path"
                | b"linkpath"
                | b"size"
                | b"uid"
                | b"gid"
                | b"mtime"
                | b"atime"
                | b"ctime"
                | b"uname"
                | b"gname"
                | b"comment"
        ) {
            return Err(Error::Invalid("unsupported PAX key or xattr encoding"));
        }
        // Empty values delete an earlier override, restoring the raw-header value.
        // For xattrs/informational records they remove the attribute entirely.
        if value.is_empty() {
            records.remove(key);
        } else {
            records.insert(key.to_vec(), value.to_vec());
        }
        rest = &rest[len..];
    }
    Ok(())
}
fn effective<'a>(
    raw: &'a [u8],
    pax: Option<&'a Vec<u8>>,
    gnu: Option<&'a Vec<u8>>,
) -> Result<&'a [u8], Error> {
    if let (Some(p), Some(g)) = (pax, gnu)
        && p != g
    {
        return Err(Error::Invalid("conflicting PAX and GNU text"));
    }
    Ok(pax.or(gnu).map_or(raw, Vec::as_slice))
}

fn inspect(
    file: &mut File,
    size: u64,
    limits: Limits,
    cancelled: &impl Fn() -> bool,
) -> Result<Vec<Entry>, Error> {
    if size > limits.max_uncompressed_bytes {
        return Err(Error::Limit("uncompressed bytes"));
    }
    let mut entries = Vec::new();
    let mut paths = BTreeSet::new();
    let mut metadata = 0;
    let mut headers = 0usize;
    let mut offset = 0u64;
    let mut zero_blocks = 0u64;
    let mut pending = false;
    let mut records = BTreeMap::new();
    let mut long_name = None;
    let mut long_link = None;
    while offset < size {
        check_cancel(cancelled)?;
        offset = offset
            .checked_add(512)
            .filter(|n| *n <= size)
            .ok_or(Error::Invalid("partial tar block"))?;
        let mut block = [0u8; 512];
        file.read_exact(&mut block)?;
        if block == [0; 512] {
            zero_blocks += 1;
            continue;
        }
        if zero_blocks != 0 {
            return Err(Error::Invalid("nonzero data after tar end marker"));
        }
        if headers >= limits.max_entries {
            return Err(Error::Limit("entry count"));
        }
        headers += 1;
        charge(&mut metadata, 512, limits)?;
        let checksum: u64 = block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum();
        if unsigned(&block[148..156])? != checksum {
            return Err(Error::Invalid("tar header checksum"));
        }
        let gnu = &block[257..265] == b"ustar  \0";
        if !gnu && &block[257..265] != b"ustar\x0000" {
            return Err(Error::Invalid("unsupported tar header format"));
        }
        let raw_size = unsigned(&block[124..136])?;
        let flag = block[156];
        if flag == b'S' {
            return Err(Error::Invalid("GNU sparse entry"));
        }
        if gnu {
            if block[369..].iter().any(|b| *b != 0) {
                return Err(Error::Invalid("GNU sparse or reserved fields"));
            }
        } else if block[500..].iter().any(|b| *b != 0) {
            return Err(Error::Invalid("USTAR reserved bytes"));
        }
        if matches!(flag, b'x' | b'g' | b'L' | b'K') {
            if flag == b'g' {
                return Err(Error::Invalid(
                    "global PAX unsupported (including semantic fields)",
                ));
            }
            let (end, next) = framing(offset, raw_size, size)?;
            charge(
                &mut metadata,
                raw_size
                    .checked_mul(2)
                    .ok_or(Error::Limit("metadata bytes"))?,
                limits,
            )?;
            let len =
                usize::try_from(raw_size).map_err(|_| Error::Limit("extension allocation"))?;
            let mut payload = vec![0; len];
            file.read_exact(&mut payload)?;
            if flag == b'x' {
                pax(&payload, &mut records, &mut metadata, limits)?;
            } else {
                let text = string(&payload)?;
                if text.is_empty() {
                    return Err(Error::Invalid("empty GNU long text"));
                }
                let target = if flag == b'L' {
                    &mut long_name
                } else {
                    &mut long_link
                };
                *target = Some(text.to_vec());
            }
            pending = true;
            check_padding(file, end, next)?;
            offset = next;
            continue;
        }
        let kind = match flag {
            0 | b'0' => EntryKind::File,
            b'1' => EntryKind::Hardlink,
            b'2' => EntryKind::Symlink,
            b'5' => EntryKind::Directory,
            _ => return Err(Error::Invalid("unsupported tar entry type")),
        };
        let mut length = records
            .get(b"size".as_slice())
            .map_or(Ok(raw_size), |v| decimal(v))?;
        if kind == EntryKind::Hardlink {
            length = 0;
        } else if kind != EntryKind::File && length != 0 {
            return Err(Error::Invalid("payload on non-regular entry"));
        }
        let (end, next) = framing(offset, length, size)?;
        let raw_name = string(&block[..100])?;
        let prefix = if gnu {
            &b""[..]
        } else {
            string(&block[345..500])?
        };
        charge(
            &mut metadata,
            (raw_name.len() + prefix.len() + 1) as u64,
            limits,
        )?;
        let mut raw_path = Vec::new();
        if !prefix.is_empty() {
            raw_path.extend_from_slice(prefix);
            raw_path.push(b'/');
        }
        raw_path.extend_from_slice(raw_name);
        let name = effective(
            &raw_path,
            records.get(b"path".as_slice()),
            long_name.as_ref(),
        )?;
        let link = effective(
            string(&block[157..257])?,
            records.get(b"linkpath".as_slice()),
            long_link.as_ref(),
        )?;
        charge(
            &mut metadata,
            (name.len() as u64)
                .checked_mul(2)
                .and_then(|n| n.checked_add(link.len() as u64))
                .ok_or(Error::Limit("metadata bytes"))?,
            limits,
        )?;
        let path = canonical_path(name, kind)?;
        if link.contains(&0)
            || matches!(kind, EntryKind::Symlink | EntryKind::Hardlink) != !link.is_empty()
        {
            return Err(Error::Invalid(
                "missing link target or link text on non-link",
            ));
        }
        validate_whiteout(&path, kind, length)?;
        if !paths.insert(path.clone()) {
            return Err(Error::Invalid("duplicate normalized tar path"));
        }
        let mode = u32::try_from(unsigned(&block[100..108])?)
            .map_err(|_| Error::Invalid("mode overflow"))?;
        if mode > 0o7777 {
            return Err(Error::Invalid("unsupported tar mode bits"));
        }
        if unsigned(&block[329..337])? != 0 || unsigned(&block[337..345])? != 0 {
            return Err(Error::Invalid("device numbers on unsupported entry"));
        }
        let uid = records
            .get(b"uid".as_slice())
            .map_or_else(|| unsigned(&block[108..116]), |v| decimal(v))?;
        let gid = records
            .get(b"gid".as_slice())
            .map_or_else(|| unsigned(&block[116..124]), |v| decimal(v))?;
        // Decimal fractions and xattr names are copied into the public metadata.
        for (key, value) in &records {
            if matches!(key.as_slice(), b"mtime" | b"atime" | b"ctime") {
                charge(&mut metadata, value.len() as u64, limits)?;
            }
            if let Some(name) = key.strip_prefix(b"SCHILY.xattr.") {
                charge(&mut metadata, name.len() as u64, limits)?;
            }
        }
        let mtime = records.get(b"mtime".as_slice()).map_or_else(
            || Timestamp::integer(number(&block[136..148])?),
            |v| timestamp(v),
        )?;
        let time =
            |key: &[u8], range: std::ops::Range<usize>| -> Result<Option<Timestamp>, Error> {
                if let Some(v) = records.get(key) {
                    return timestamp(v).map(Some);
                }
                if gnu {
                    return Timestamp::integer(number(&block[range])?).map(Some);
                }
                Ok(None)
            };
        let atime = time(b"atime", 345..357)?;
        let ctime = time(b"ctime", 357..369)?;
        let uname = records
            .get(b"uname".as_slice())
            .map_or(string(&block[265..297])?, Vec::as_slice);
        let gname = records
            .get(b"gname".as_slice())
            .map_or(string(&block[297..329])?, Vec::as_slice);
        charge(&mut metadata, (uname.len() + gname.len()) as u64, limits)?;
        let mut entry = Entry {
            path,
            link_target: if link.is_empty() {
                None
            } else {
                Some(link.to_vec())
            },
            kind,
            data_offset: offset,
            size: length,
            mode,
            uid,
            gid,
            mtime,
            atime,
            ctime,
            uname: uname.to_vec(),
            gname: gname.to_vec(),
            xattrs: BTreeMap::new(),
            pax_records: BTreeMap::new(),
        };
        for (key, value) in std::mem::take(&mut records) {
            if let Some(name) = key.strip_prefix(b"SCHILY.xattr.") {
                entry.xattrs.insert(name.to_vec(), value);
            } else if key == b"comment" {
                entry.pax_records.insert(key, value);
            }
        }
        long_name = None;
        long_link = None;
        pending = false;
        check_padding(file, end, next)?;
        offset = next;
        entries.push(entry);
    }
    if pending {
        return Err(Error::Invalid("dangling tar extensions"));
    }
    if zero_blocks < 2 {
        return Err(Error::Invalid("missing two-block tar end marker"));
    }
    Ok(entries)
}
fn check_padding(file: &mut File, end: u64, next: u64) -> Result<(), Error> {
    file.seek(SeekFrom::Start(end))?;
    let mut padding = [0; 512];
    let len = (next - end) as usize;
    file.read_exact(&mut padding[..len])?;
    if padding[..len].iter().any(|b| *b != 0) {
        return Err(Error::Invalid("nonzero tar entry padding"));
    }
    Ok(())
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
                (&entry.path[..], entry.uid, entry.gid, entry.mtime.seconds),
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
        for invalid in [
            corrupt,
            bad_size,
            encoded[..n - 1].to_vec(),
            encoded[..n / 2].to_vec(),
            suffix,
        ] {
            assert!(f.verify(&invalid, true, &digest(&bytes), limits()).is_err());
            f.clean();
        }
    }
    #[test]
    fn concatenated_gzip_splits_headers_payload_and_padding() {
        let f = Fixture::new();
        let bytes = sample();
        // Boundaries inside the tar header, payload and end padding, plus empty
        // leading/intermediate/trailing members. No member is a standalone tar.
        let cuts = [
            0,
            17,
            17,
            513,
            BUFFER_SIZE + 29,
            bytes.len() - 13,
            bytes.len(),
        ];
        let mut encoded = gzip(&[]);
        for part in cuts.windows(2) {
            encoded.extend(gzip(&bytes[part[0]..part[1]]));
        }
        encoded.extend(gzip(&[]));
        let mut layer = f.verify(&encoded, true, &digest(&bytes), limits()).unwrap();
        assert_eq!(layer.diff_id(), &digest(&bytes));
        assert_eq!(layer.size(), bytes.len() as u64);
        assert_eq!(layer.entries().len(), 1);
        assert_eq!(layer.entries()[0].path, b"data");
        let mut readback = Vec::new();
        layer.read_to_end(&mut readback).unwrap();
        assert_eq!(readback, bytes);
        let input = ShortReads {
            inner: Cursor::new(&encoded),
            calls: 0,
        };
        assert!(spool(input, true, &digest(&bytes), &f.spool, limits(), &|| false).is_ok());
        assert!(matches!(
            f.verify(&encoded, true, &digest(&bytes[..17]), limits()),
            Err(Error::DiffIdMismatch)
        ));
        let mut l = limits();
        l.max_uncompressed_bytes = bytes.len() as u64 - 1;
        assert!(matches!(
            f.verify(&encoded, true, &digest(&bytes), l),
            Err(Error::Limit("uncompressed bytes"))
        ));
        l.max_uncompressed_bytes += 1;
        assert!(f.verify(&encoded, true, &digest(&bytes), l).is_ok());
        drop(layer);
        f.clean();
    }
    #[test]
    fn concatenated_gzip_rejects_later_corruption_truncation_and_junk() {
        let f = Fixture::new();
        let bytes = sample();
        let first = gzip(&bytes[..513]);
        let later = gzip(&bytes[513..]);
        for offset in [8, 4] {
            let mut bad = later.clone();
            let n = bad.len();
            bad[n - offset] ^= 1; // CRC and ISIZE independently.
            assert!(matches!(
                f.verify(
                    &[first.as_slice(), &bad].concat(),
                    true,
                    &digest(&bytes),
                    limits()
                ),
                Err(Error::Io(_))
            ));
        }
        for cut in [1, 9, 10, later.len() / 2, later.len() - 8, later.len() - 1] {
            assert!(matches!(
                f.verify(
                    &[first.as_slice(), &later[..cut]].concat(),
                    true,
                    &digest(&bytes),
                    limits()
                ),
                Err(Error::Io(_))
            ));
        }
        for suffix in [b"\0".as_slice(), b"not a gzip member", b"\x1f\x8b"] {
            let bad = [first.as_slice(), &later, suffix].concat();
            assert!(matches!(
                f.verify(&bad, true, &digest(&bytes), limits()),
                Err(Error::Io(_))
            ));
        }
        f.clean();
    }
    #[test]
    fn concatenated_gzip_header_budget_is_aggregate_including_empty_members() {
        let f = Fixture::new();
        let bytes = sample();
        let first = gzip(&bytes);
        let empty = gzip(&[]);
        let encoded = [first.as_slice(), &empty, &empty].concat();
        let mut l = limits();
        for cap in [0, 9, 10, 19, 20, 29] {
            l.max_gzip_header_bytes = cap;
            assert!(matches!(
                f.verify(&encoded, true, &digest(&bytes), l),
                Err(Error::Limit("gzip header bytes"))
            ));
        }
        l.max_gzip_header_bytes = 30;
        assert!(f.verify(&encoded, true, &digest(&bytes), l).is_ok());
        for flag in [8, 16] {
            let mut huge = empty.clone();
            huge[3] |= flag; // FNAME or FCOMMENT in a later member.
            huge.splice(10..10, std::iter::repeat_n(b'x', 5000).chain([0]));
            assert!(matches!(
                f.verify(
                    &[first.as_slice(), &huge].concat(),
                    true,
                    &digest(&bytes),
                    limits()
                ),
                Err(Error::Limit("gzip header bytes"))
            ));
        }
        // Each individual header fits 30 bytes, but their sum does not.
        let mut named = empty;
        named[3] |= 8;
        named.splice(10..10, b"long-enough-name\0".iter().copied());
        assert!(matches!(
            f.verify(
                &[first.as_slice(), &named].concat(),
                true,
                &digest(&bytes),
                l
            ),
            Err(Error::Limit("gzip header bytes"))
        ));
        f.clean();
    }
    #[test]
    fn concatenated_gzip_cancellation_at_every_check() {
        let f = Fixture::new();
        let bytes = sample();
        let mut later = gzip(&bytes[513..]);
        later[3] |= 8;
        later.splice(10..10, b"later-name\0".iter().copied());
        let encoded = [gzip(&bytes[..513]), gzip(&[]), later].concat();
        let checks = Cell::new(0);
        let count = || {
            checks.set(checks.get() + 1);
            false
        };
        drop(
            spool(
                encoded.as_slice(),
                true,
                &digest(&bytes),
                &f.spool,
                limits(),
                &count,
            )
            .unwrap(),
        );
        // Sweep headers, empty-member transitions, payload and tar inspection.
        for stop in 1..=checks.get() {
            let calls = Cell::new(0);
            let cancel = || {
                calls.set(calls.get() + 1);
                calls.get() >= stop
            };
            assert!(
                matches!(
                    spool(
                        encoded.as_slice(),
                        true,
                        &digest(&bytes),
                        &f.spool,
                        limits(),
                        &cancel
                    ),
                    Err(Error::Cancelled)
                ),
                "check {stop}"
            );
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
    fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
        let body = [key, b"=", value, b"\n"].concat();
        let mut len = body.len() + 2;
        loop {
            let next = len.to_string().len() + 1 + body.len();
            if next == len {
                break;
            }
            len = next;
        }
        [format!("{len} ").as_bytes(), &body].concat()
    }
    fn extension(kind: u8, payload: Vec<u8>) -> (tar::Header, Vec<u8>) {
        (
            header("extension", kind, payload.len() as u64, None),
            payload,
        )
    }
    fn binary(field: &mut [u8], value: u64) {
        field.fill(0);
        let len = field.len();
        field[len - 8..].copy_from_slice(&value.to_be_bytes());
        field[0] |= 0x80;
    }
    #[test]
    fn pax_size_overrides_only_ordinary_entry_and_preserves_sentinel() {
        let f = Fixture::new();
        let bytes = archive(vec![
            extension(b'x', pax_record(b"size", b"513")),
            extension(b'x', pax_record(b"uid", b"999")),
            (header("overridden", b'0', 0, None), vec![7; 513]),
            (header("sentinel", b'0', 1, None), vec![42]),
        ]);
        let mut layer = f.verify(&bytes, false, &digest(&bytes), limits()).unwrap();
        assert_eq!(layer.entries()[0].size, 513);
        assert_eq!(layer.entries()[0].uid, 999);
        assert_eq!(layer.entries()[1].path, b"sentinel");
        let offset = layer.entries()[1].data_offset;
        layer.seek(SeekFrom::Start(offset)).unwrap();
        let mut one = [0];
        layer.read_exact(&mut one).unwrap();
        assert_eq!(one, [42]);
    }
    #[test]
    fn pax_binary_xattrs_exact_signed_times_and_deletion() {
        let f = Fixture::new();
        let payload = [
            pax_record(b"SCHILY.xattr.user.bin", b"a\n\0=b"),
            pax_record(b"SCHILY.xattr.user.removed", b"value"),
            pax_record(b"SCHILY.xattr.user.removed", b""),
            pax_record(b"path", b"old"),
            pax_record(b"path", b"new"),
            pax_record(b"uid", b"555"),
            pax_record(b"uid", b""),
            pax_record(b"mtime", b"-0.000000000123400"),
        ]
        .concat();
        let bytes = archive(vec![
            extension(b'x', payload),
            (header("raw", b'0', 0, None), vec![]),
        ]);
        let layer = f.verify(&bytes, false, &digest(&bytes), limits()).unwrap();
        let e = &layer.entries()[0];
        assert_eq!(e.path, b"new");
        assert_eq!(e.uid, 123);
        assert_eq!(e.xattrs.get(b"user.bin".as_slice()).unwrap(), b"a\n\0=b");
        assert_eq!(e.xattrs.len(), 1);
        assert_eq!(
            e.mtime,
            Timestamp {
                negative: true,
                seconds: 0,
                fraction: b"0000000001234".to_vec()
            }
        );
        assert_eq!(timestamp(b"-12.5").unwrap().seconds, 12);
        assert_eq!(timestamp(b"0.000").unwrap(), Timestamp::integer(0).unwrap());
    }
    #[test]
    fn gnu_layout_long_records_and_hardlinks_preserve_targets() {
        let f = Fixture::new();
        let mut h = tar::Header::new_gnu();
        h.set_path("short").unwrap();
        h.set_size(999);
        h.set_mode(0o644);
        h.set_uid(1);
        h.set_gid(2);
        h.set_mtime(3);
        h.set_entry_type(tar::EntryType::Link);
        h.set_link_name("rawtarget").unwrap();
        h.as_mut_bytes()[345..357].copy_from_slice(b"00000000004\0");
        h.as_mut_bytes()[357..369].copy_from_slice(b"00000000005\0");
        h.set_cksum();
        let name = vec![b'n'; 300];
        let target = b"lower/or/forward";
        let bytes = archive(vec![
            extension(b'L', [name.as_slice(), b"\0"].concat()),
            extension(b'K', [target.as_slice(), b"\0"].concat()),
            (h, vec![]),
            (header("sentinel", b'0', 0, None), vec![]),
        ]);
        let layer = f.verify(&bytes, false, &digest(&bytes), limits()).unwrap();
        let e = &layer.entries()[0];
        assert_eq!(e.kind, EntryKind::Hardlink);
        assert_eq!(e.size, 0);
        assert_eq!(e.path, name);
        assert_eq!(e.link_target.as_deref(), Some(target.as_slice()));
        assert_eq!(e.atime.as_ref().unwrap().seconds, 4);
        assert_eq!(e.ctime.as_ref().unwrap().seconds, 5);
        assert_eq!(layer.entries()[1].path, b"sentinel");
    }
    #[test]
    fn mixed_extensions_agree_or_fail_and_effective_paths_are_validated() {
        let f = Fixture::new();
        for (gnu, pax_path, good) in [
            ("same", "same", true),
            ("first", "second", false),
            ("../bad", "../bad", false),
            (".wh.bad", ".wh.bad", false),
        ] {
            let bytes = archive(vec![
                extension(b'L', [gnu.as_bytes(), b"\0"].concat()),
                extension(b'x', pax_record(b"path", pax_path.as_bytes())),
                (header("raw", b'0', 1, None), vec![1]),
            ]);
            assert_eq!(
                f.verify(&bytes, false, &digest(&bytes), limits()).is_ok(),
                good
            );
        }
        let bytes = archive(vec![
            (header("same", b'0', 0, None), vec![]),
            extension(b'x', pax_record(b"path", b"./same")),
            (header("different", b'0', 0, None), vec![]),
        ]);
        assert!(matches!(
            f.verify(&bytes, false, &digest(&bytes), limits()),
            Err(Error::Invalid("duplicate normalized tar path"))
        ));
    }
    #[test]
    fn base256_checks_entire_field_and_signed_time() {
        assert_eq!(number(&[0xff; 12]).unwrap(), -1);
        assert_eq!(number(&[0xff; 17]).unwrap(), -1);
        let mut huge = [0u8; 17];
        huge[0] = 0x81;
        assert!(matches!(
            number(&huge),
            Err(Error::Invalid("base-256 overflow"))
        ));
        let mut high = [0u8; 12];
        high[0] = 0x80;
        high[1] = 1;
        assert!(unsigned(&high).is_err());
        let f = Fixture::new();
        let mut h = header("binary", b'0', 0, None);
        binary(&mut h.as_mut_bytes()[108..116], 1u64 << 40);
        h.as_mut_bytes()[136..148].fill(0xff);
        h.set_cksum();
        let bytes = archive(vec![(h, vec![])]);
        let layer = f.verify(&bytes, false, &digest(&bytes), limits()).unwrap();
        assert_eq!(layer.entries()[0].uid, 1u64 << 40);
        assert_eq!(layer.entries()[0].mtime, Timestamp::integer(-1).unwrap());
        let mut h = header("bad", b'0', 0, None);
        h.as_mut_bytes()[124..136].copy_from_slice(&high);
        h.set_cksum();
        let bytes = archive(vec![(h, vec![])]);
        assert!(f.verify(&bytes, false, &digest(&bytes), limits()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn inspect_large_sparse_backing_file_without_hashing_payload() {
        // Tests framing only. verify() still reads/hashes every byte; this sparse
        // backing file is not a sparse tar entry and does not mint VerifiedLayer.
        let mut file = tempfile::tempfile().unwrap();
        let length = (1u64 << 33) + 513;
        let mut h = header("large", b'0', 0, None);
        binary(&mut h.as_mut_bytes()[124..136], length);
        h.set_cksum();
        file.write_all(h.as_bytes()).unwrap();
        let next = 512 + length.div_ceil(512) * 512;
        file.seek(SeekFrom::Start(next)).unwrap();
        file.write_all(header("sentinel", b'0', 0, None).as_bytes())
            .unwrap();
        file.write_all(&[0; 1024]).unwrap();
        file.rewind().unwrap();
        let size = next + 1536;
        let mut l = limits();
        l.max_uncompressed_bytes = size;
        let entries = inspect(&mut file, size, l, &|| false).unwrap();
        assert_eq!(entries[0].size, length);
        assert_eq!(entries[1].path, b"sentinel");
        assert_eq!(entries[1].data_offset, next + 512);
    }
    #[test]
    fn extensions_are_bounded_even_when_overwritten_and_reject_semantic_loss() {
        let f = Fixture::new();
        let repeated = [
            pax_record(b"comment", b"a"),
            pax_record(b"comment", b"b"),
            pax_record(b"comment", b""),
        ]
        .concat();
        let bytes = archive(vec![
            extension(b'x', repeated.clone()),
            (header("raw", b'0', 0, None), vec![]),
        ]);
        let mut l = limits();
        l.max_metadata_bytes = 512 + repeated.len() as u64 * 2 + 128 * 2;
        assert!(matches!(
            f.verify(&bytes, false, &digest(&bytes), l),
            Err(Error::Limit("metadata bytes"))
        ));
        l = limits();
        l.max_entries = 1;
        assert!(matches!(
            f.verify(&bytes, false, &digest(&bytes), l),
            Err(Error::Limit("entry count"))
        ));
        for key in [
            b"GNU.sparse.size".as_slice(),
            b"SCHILY.realsize",
            b"SUN.holesdata",
            b"LIBARCHIVE.xattr.user.foo",
            b"SCHILY.acl.access",
            b"unknown",
        ] {
            let bytes = archive(vec![
                extension(b'x', pax_record(key, b"1")),
                (header("raw", b'0', 0, None), vec![]),
            ]);
            assert!(f.verify(&bytes, false, &digest(&bytes), limits()).is_err());
        }
        for kind in [b'x', b'g', b'L', b'K'] {
            let payload = if kind == b'x' || kind == b'g' {
                pax_record(b"uid", b"1")
            } else {
                b"text\0".to_vec()
            };
            let bytes = archive(vec![extension(kind, payload)]);
            assert!(f.verify(&bytes, false, &digest(&bytes), limits()).is_err());
        }
        for payload in [
            b"99 path=a\n".as_slice(),
            b"9 path=a!",
            b"0 path=a\n",
            b"12 path=a\n",
        ] {
            let bytes = archive(vec![
                extension(b'x', payload.to_vec()),
                (header("raw", b'0', 0, None), vec![]),
            ]);
            assert!(f.verify(&bytes, false, &digest(&bytes), limits()).is_err());
        }
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
                &mut Sha256::new(),
                &mut 0,
                3,
                &|| false
            ),
            Err(Error::Io(_))
        ));
        let mut input = Cursor::new(vec![0; BUFFER_SIZE * 2]);
        let mut output = Vec::new();
        assert!(matches!(
            copy_hash(
                &mut input,
                &mut output,
                &mut Sha256::new(),
                &mut 0,
                10,
                &|| false
            ),
            Err(Error::Limit(_))
        ));
        assert_eq!(input.position(), 11);
        assert!(output.is_empty());
    }
}
