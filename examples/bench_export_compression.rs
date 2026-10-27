//! Linux-only, offline CPU/I/O comparison of the internal streaming layer writer.
//! Usage: bench_export_compression [payload MiB=64] [iterations=3]

#[cfg(target_os = "linux")]
pub use rpweld::{export, oci};
#[cfg(target_os = "linux")]
#[path = "../src/export_compression.rs"]
mod export_compression;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use export_compression::{Compression, LayerWriter, Limits, payload_peak};
    use rpweld::layer;
    use std::{
        fs,
        io::{self, Read, Seek, SeekFrom, Write},
        os::unix::fs::MetadataExt,
        path::Path,
        time::Instant,
    };

    fn cpu_seconds() -> io::Result<f64> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes usage on success, checked before assume_init.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful getrusage call initialized this value.
        let usage = unsafe { usage.assume_init() };
        Ok((usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as f64
            + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1_000_000.0)
    }

    // Observe anonymous verification spools as well as named blobs. This benchmark
    // owns these directories and runs serially; other processes' files are excluded.
    fn allocated_bytes_under(directory: &Path) -> io::Result<u64> {
        let mut seen = std::collections::BTreeSet::new();
        let mut bytes = 0;
        for entry in fs::read_dir("/proc/self/fd")? {
            let path = entry?.path();
            let Ok(target) = fs::read_link(&path) else {
                continue;
            };
            if !target.starts_with(directory) {
                continue;
            }
            let metadata = fs::metadata(&path)?;
            if seen.insert((metadata.dev(), metadata.ino())) {
                bytes += metadata.blocks() * 512;
            }
        }
        Ok(bytes)
    }

    struct Payload {
        remaining: u64,
        position: u64,
        random: bool,
        state: u64,
    }
    impl Read for Payload {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            const TEXT: &[u8] = b"package=example version=1.2.3 architecture=amd64\nimport module\ndef function(argument):\n    return argument + 1\n";
            let n = bytes.len().min(self.remaining.min(65536) as usize);
            for b in &mut bytes[..n] {
                *b = if self.random {
                    self.state ^= self.state << 13;
                    self.state ^= self.state >> 7;
                    self.state ^= self.state << 17;
                    self.state as u8
                } else {
                    TEXT[self.position as usize % TEXT.len()]
                };
                self.position += 1;
            }
            self.remaining -= n as u64;
            Ok(n)
        }
    }

    let args: Vec<_> = std::env::args().collect();
    let mib: u64 = args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(64);
    let iterations: usize = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(3);
    if !(1..=1024).contains(&mib) || !(1..=20).contains(&iterations) {
        return Err("payload MiB must be 1..=1024, iterations 1..=20".into());
    }
    let payload_bytes = mib * 1024 * 1024;
    let fixture_dir = tempfile::tempdir_in("/var/tmp")?;
    for (name, random) in [("compressible-text", false), ("incompressible-bytes", true)] {
        // Generation is deliberately outside the measurement. The raw tar is a
        // stand-in for source filesystem reads and excluded from export temp peak.
        let mut source = tempfile::tempfile_in(fixture_dir.path())?;
        {
            let mut tar = tar::Builder::new(&mut source);
            let mut header = tar::Header::new_ustar();
            header.set_mode(0o644);
            header.set_size(payload_bytes);
            header.set_mtime(0);
            tar.append_data(
                &mut header,
                "representative-payload",
                Payload {
                    remaining: payload_bytes,
                    position: 0,
                    random,
                    state: 0x1234_5678_9abc_def0,
                },
            )?;
            tar.finish()?;
        }
        source.sync_all()?;
        let raw_size = source.metadata()?.len();
        for iteration in 1..=iterations {
            // Alternate order to expose cache/order effects rather than always
            // giving one mode the warmer source page cache.
            let modes = if iteration % 2 == 1 {
                [Compression::Uncompressed, Compression::Gzip]
            } else {
                [Compression::Gzip, Compression::Uncompressed]
            };
            for mode in modes {
                let output = tempfile::tempdir_in("/var/tmp")?;
                let store = oci::BlobStore::open(output.path())?;
                let blob_dir = output.path().join("blobs/sha256");
                let mut pending = tempfile::NamedTempFile::new_in(&blob_dir)?;
                source.seek(SeekFrom::Start(0))?;
                let cpu = cpu_seconds()?;
                let wall = Instant::now();
                let mut writer = LayerWriter::new(
                    pending.as_file_mut(),
                    mode,
                    Limits {
                        max_uncompressed_bytes: raw_size,
                        max_blob_bytes: mode.max_encoded_size(raw_size)?,
                    },
                    &|| false,
                );
                let mut buffer = [0; 65536];
                loop {
                    let count = source.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    writer.write_all(&buffer[..count])?;
                }
                let (_, encoded) = writer.finish()?;
                pending.as_file().sync_all()?;
                let encode_wall_ms = wall.elapsed().as_secs_f64() * 1000.0;
                let encode_cpu_ms = (cpu_seconds()? - cpu) * 1000.0;
                assert_eq!(raw_size, encoded.uncompressed_bytes);
                // Benchmark-owned destination, then the real BlobStore+layer verifier.
                // Production publication additionally verifies before persisting.
                let blob =
                    pending.persist_noclobber(blob_dir.join(&encoded.descriptor.digest[7..]))?;
                let cpu = cpu_seconds()?;
                let wall = Instant::now();
                let verified = layer::verify(
                    &store,
                    &encoded.descriptor,
                    &encoded.diff_id,
                    output.path(),
                    layer::Limits {
                        max_blob_bytes: mode.max_encoded_size(raw_size)?,
                        max_uncompressed_bytes: raw_size,
                        max_entries: 10,
                        max_metadata_bytes: 65536,
                        max_gzip_header_bytes: 10,
                    },
                    || false,
                )?;
                let verify_wall_ms = wall.elapsed().as_secs_f64() * 1000.0;
                let verify_cpu_ms = (cpu_seconds()? - cpu) * 1000.0;
                let physical_peak = allocated_bytes_under(output.path())?;
                let stored_size = encoded.descriptor.size as u64;
                println!(
                    "{}",
                    serde_json::json!({
                        "fixture": name, "iteration": iteration, "mode": format!("{mode:?}"),
                        "raw_tar_bytes": raw_size, "stored_bytes": stored_size,
                        "encode_wall_ms": encode_wall_ms, "encode_cpu_ms": encode_cpu_ms,
                        "verify_wall_ms": verify_wall_ms, "verify_cpu_ms": verify_cpu_ms,
                        "temporary_payload_peak_bytes": payload_peak(stored_size, verified.size(), 0)?,
                        "observed_allocated_peak_bytes": physical_peak,
                        "stored_allocated_bytes": blob.metadata()?.blocks() * 512,
                    })
                );
                drop(verified);
                drop(blob);
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("bench_export_compression requires Linux");
    std::process::exit(1);
}
