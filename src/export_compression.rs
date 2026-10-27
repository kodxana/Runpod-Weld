//! Bounded encoding of newly generated layer bytes. Inherited blobs bypass this module.
//!
//! The caller owns an unpublished spool and must discard it on any error. Only
//! `finish` returns hashes suitable for verification/publication. No paths or
//! publication capabilities enter this module. Payload writes are at most 64 KiB;
//! flate2's pinned miniz backend also keeps bounded internal compression state.

use crate::{
    export::Error,
    oci::{Descriptor, Sha256Digest},
};
use flate2::{GzBuilder, write::GzEncoder};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

const CHUNK: usize = 64 * 1024;

/// Gzip uses the fixed level-one CPU profile; existing exports remain uncompressed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Compression {
    #[default]
    Uncompressed,
    Gzip,
}

impl Compression {
    /// Conservative bound for the pinned miniz backend, without intermediate flushes.
    ///
    /// Automatic blocks have at least 31 KiB of input. Literals cost <=15 bits
    /// each; matches cost <=48 bits for >=3 bytes. Each block gets 512 bytes for
    /// dynamic headers/EOB/alignment, plus a final block and 18 gzip framing bytes.
    /// This is deliberately looser than a zlib-specific compressBound formula.
    /// Feed measured tar estimates, not workload ceilings. Checked on overflow.
    pub(crate) fn max_encoded_size(self, raw: u64) -> Result<u64, Error> {
        match self {
            Self::Uncompressed => Ok(raw),
            Self::Gzip => (raw / (31 * 1024) + 1)
                .checked_mul(512)
                .and_then(|overhead| raw.checked_mul(2)?.checked_add(overhead))
                .and_then(|n| n.checked_add(18))
                .ok_or(Error::Limit("export space estimate")),
        }
    }
}

/// Coexisting payload bytes when verification finishes before base blobs are copied.
/// Use actual byte counts after encoding, or conservative measured estimates before it.
/// Directory/JSON overhead remains the caller's separate responsibility.
pub(crate) fn payload_peak(stored: u64, raw: u64, inherited: u64) -> Result<u64, Error> {
    stored
        .checked_add(raw.max(inherited))
        .ok_or(Error::Limit("export space estimate"))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// All tar bytes, including headers, padding, and end markers.
    pub(crate) max_uncompressed_bytes: u64,
    /// All stored bytes, including gzip header and trailer. Also capped at i64::MAX.
    pub(crate) max_blob_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct EncodedLayer {
    pub(crate) descriptor: Descriptor,
    pub(crate) diff_id: Sha256Digest,
    pub(crate) uncompressed_bytes: u64,
}

struct Sink<'a, W, C> {
    writer: W,
    hash: Sha256,
    size: u64,
    max: u64,
    cancelled: &'a C,
    failed: bool,
}

impl<W: Write, C: Fn() -> bool> Sink<'_, W, C> {
    fn check(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("layer writer already failed"));
        }
        if (self.cancelled)() {
            self.failed = true;
            return Err(io::Error::other(Error::Cancelled));
        }
        Ok(())
    }

    fn track<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if result
            .as_ref()
            .is_err_and(|e| e.kind() != io::ErrorKind::Interrupted)
        {
            self.failed = true;
        }
        result
    }
}

impl<W: Write, C: Fn() -> bool> Write for Sink<'_, W, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        let bytes = &bytes[..bytes.len().min(CHUNK)];
        if bytes.len() as u64 > self.max.saturating_sub(self.size) {
            self.failed = true;
            return Err(io::Error::other(Error::Limit("compressed layer bytes")));
        }
        let result = self.writer.write(bytes);
        let n = self.track(result)?;
        if n == 0 && !bytes.is_empty() {
            self.failed = true;
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.hash.update(&bytes[..n]);
        self.size += n as u64;
        self.check()?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.writer.flush();
        self.track(result)?;
        self.check()
    }
}

enum Encoding<'a, W: Write, C: Fn() -> bool> {
    Raw(Sink<'a, W, C>),
    Gzip(GzEncoder<Sink<'a, W, C>>),
}

impl<'a, W: Write, C: Fn() -> bool> Encoding<'a, W, C> {
    fn sink(&mut self) -> &mut Sink<'a, W, C> {
        match self {
            Self::Raw(sink) => sink,
            Self::Gzip(encoder) => encoder.get_mut(),
        }
    }
}

/// Streaming tar sink. Drop/failed finish never produces a publishable descriptor.
pub(crate) struct LayerWriter<'a, W: Write, C: Fn() -> bool> {
    encoding: Encoding<'a, W, C>,
    hash: Sha256,
    size: u64,
    max: u64,
}

impl<'a, W: Write, C: Fn() -> bool> LayerWriter<'a, W, C> {
    pub(crate) fn new(
        writer: W,
        compression: Compression,
        limits: Limits,
        cancelled: &'a C,
    ) -> Self {
        let sink = Sink {
            writer,
            hash: Sha256::new(),
            size: 0,
            max: limits.max_blob_bytes.min(i64::MAX as u64),
            cancelled,
            failed: false,
        };
        let encoding = match compression {
            Compression::Uncompressed => Encoding::Raw(sink),
            Compression::Gzip => Encoding::Gzip(
                GzBuilder::new()
                    .mtime(0)
                    .operating_system(255)
                    .write(sink, flate2::Compression::new(1)),
            ),
        };
        Self {
            encoding,
            hash: Sha256::new(),
            size: 0,
            max: limits.max_uncompressed_bytes,
        }
    }

    /// Finish gzip framing, check cancellation, and return independent stored/raw hashes.
    /// Terminal write errors and any flush/finalization error prevent success.
    pub(crate) fn finish(mut self) -> io::Result<(W, EncodedLayer)> {
        self.encoding.sink().check()?;
        let (mut sink, compression) = match self.encoding {
            Encoding::Raw(sink) => (sink, Compression::Uncompressed),
            Encoding::Gzip(mut encoder) => {
                if let Err(error) = encoder.try_finish() {
                    // GzEncoder retries finalization in Drop, including after an
                    // interrupted footer write. Never let that retry write more.
                    encoder.get_mut().failed = true;
                    return Err(error);
                }
                (encoder.finish()?, Compression::Gzip)
            }
        };
        sink.flush()?;
        let descriptor = Descriptor {
            media_type: match compression {
                Compression::Uncompressed => "application/vnd.oci.image.layer.v1.tar",
                Compression::Gzip => "application/vnd.oci.image.layer.v1.tar+gzip",
            }
            .into(),
            digest: format!("sha256:{:x}", sink.hash.finalize()),
            size: i64::try_from(sink.size)
                .map_err(|_| io::Error::other(Error::Limit("OCI size")))?,
            annotations: Default::default(),
            extensions: Default::default(),
        };
        let diff_id = match compression {
            Compression::Uncompressed => descriptor.digest.parse(),
            Compression::Gzip => format!("sha256:{:x}", self.hash.finalize()).parse(),
        }
        .map_err(io::Error::other)?;
        Ok((
            sink.writer,
            EncodedLayer {
                descriptor,
                diff_id,
                uncompressed_bytes: self.size,
            },
        ))
    }
}

impl<W: Write, C: Fn() -> bool> Write for LayerWriter<'_, W, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.encoding.sink().check()?;
        let bytes = &bytes[..bytes.len().min(CHUNK)];
        if bytes.len() as u64 > self.max.saturating_sub(self.size) {
            self.encoding.sink().failed = true;
            return Err(io::Error::other(Error::Limit("uncompressed layer bytes")));
        }
        let result = match &mut self.encoding {
            Encoding::Raw(sink) => sink.write(bytes),
            Encoding::Gzip(encoder) => encoder.write(bytes),
        };
        let n = self.encoding.sink().track(result)?;
        // Stored and raw bytes are identical without gzip; hash that path once.
        if matches!(self.encoding, Encoding::Gzip(_)) {
            self.hash.update(&bytes[..n]);
        }
        self.size += n as u64;
        self.encoding.sink().check()?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.encoding.sink().check()?;
        let result = match &mut self.encoding {
            Encoding::Raw(sink) => sink.flush(),
            Encoding::Gzip(encoder) => encoder.flush(),
        };
        if result.is_err() {
            self.encoding.sink().failed = true;
        }
        result?;
        self.encoding.sink().check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_reject_overflow_before_writing() {
        for compression in [Compression::Uncompressed, Compression::Gzip] {
            let mut output = Vec::new();
            let mut writer = LayerWriter::new(
                &mut output,
                compression,
                Limits {
                    max_uncompressed_bytes: u64::MAX,
                    max_blob_bytes: u64::MAX,
                },
                &|| false,
            );
            writer.size = u64::MAX;
            assert!(writer.write_all(b"x").is_err());
            assert!(writer.finish().is_err());
            assert!(output.is_empty());
        }
        let mut sink = Sink {
            writer: Vec::new(),
            hash: Sha256::new(),
            size: i64::MAX as u64,
            max: i64::MAX as u64,
            cancelled: &|| false,
            failed: false,
        };
        assert!(sink.write_all(b"x").is_err());
        assert!(sink.writer.is_empty());
    }
}
