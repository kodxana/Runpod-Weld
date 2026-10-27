//! Isolated internal-module harness until the parent wires the production exporter.
pub use rpweld::{export, oci};
#[path = "../src/export_compression.rs"]
mod export_compression;

use export_compression::{Compression, EncodedLayer, LayerWriter, Limits, payload_peak};
use flate2::read::GzDecoder;
use rpweld::{image, layer, rootfs};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    fs,
    io::{self, Read, Write},
    rc::Rc,
};

const CHUNK: usize = 65536;

fn random_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn encode(bytes: &[u8], mode: Compression, chunk: usize) -> (Vec<u8>, EncodedLayer) {
    let mut writer = LayerWriter::new(
        Vec::new(),
        mode,
        Limits {
            max_uncompressed_bytes: bytes.len() as u64,
            max_blob_bytes: mode.max_encoded_size(bytes.len() as u64).unwrap(),
        },
        &|| false,
    );
    for part in bytes.chunks(chunk) {
        writer.write_all(part).unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn deterministic_bytes_header_descriptor_and_diff_id_across_chunk_sizes() {
    assert_eq!(Compression::default(), Compression::Uncompressed);
    for input in [
        Vec::new(),
        vec![42; CHUNK * 3 + 1],
        random_bytes(CHUNK * 3 + 1),
    ] {
        for mode in [Compression::Uncompressed, Compression::Gzip] {
            let (expected, metadata) = encode(&input, mode, CHUNK);
            assert_eq!(metadata.descriptor.size, expected.len() as i64);
            assert_eq!(
                metadata.descriptor.digest,
                format!("sha256:{:x}", Sha256::digest(&expected))
            );
            assert_eq!(
                metadata.diff_id.as_str(),
                format!("sha256:{:x}", Sha256::digest(&input))
            );
            assert_eq!(metadata.uncompressed_bytes, input.len() as u64);
            assert!(metadata.descriptor.annotations.is_empty());
            assert!(metadata.descriptor.extensions.is_empty());
            for chunk in [1, 511, CHUNK + 37] {
                let (repeated, result) = encode(&input, mode, chunk);
                assert_eq!(repeated, expected, "mode={mode:?} chunk={chunk}");
                assert_eq!(result.descriptor, metadata.descriptor);
                assert_eq!(result.diff_id, metadata.diff_id);
            }
            if mode == Compression::Gzip {
                assert_eq!(&expected[..10], &[31, 139, 8, 0, 0, 0, 0, 0, 4, 255]);
                assert_eq!(
                    metadata.descriptor.media_type,
                    "application/vnd.oci.image.layer.v1.tar+gzip"
                );
                let mut decoded = Vec::new();
                GzDecoder::new(expected.as_slice())
                    .read_to_end(&mut decoded)
                    .unwrap();
                assert_eq!(decoded, input);
            } else {
                assert_eq!(expected, input);
                assert_eq!(metadata.descriptor.digest, metadata.diff_id.as_str());
                assert_eq!(
                    metadata.descriptor.media_type,
                    "application/vnd.oci.image.layer.v1.tar"
                );
            }
        }
    }
}

#[test]
fn independent_limits_include_gzip_framing_and_fail_closed() {
    for input in [Vec::new(), vec![42; CHUNK + 1], random_bytes(CHUNK + 1)] {
        for mode in [Compression::Uncompressed, Compression::Gzip] {
            let (expected, _) = encode(&input, mode, CHUNK);
            let exact = Limits {
                max_uncompressed_bytes: input.len() as u64,
                max_blob_bytes: expected.len() as u64,
            };
            let mut writer = LayerWriter::new(Vec::new(), mode, exact, &|| false);
            writer.write_all(&input).unwrap();
            assert_eq!(writer.finish().unwrap().0, expected);
            let cases = [
                Limits {
                    max_blob_bytes: exact.max_blob_bytes.saturating_sub(1),
                    ..exact
                },
                Limits {
                    max_uncompressed_bytes: exact.max_uncompressed_bytes.saturating_sub(1),
                    ..exact
                },
            ];
            for limits in cases {
                if limits.max_blob_bytes == exact.max_blob_bytes
                    && limits.max_uncompressed_bytes == exact.max_uncompressed_bytes
                {
                    continue;
                }
                let mut output = Vec::new();
                let mut writer = LayerWriter::new(&mut output, mode, limits, &|| false);
                let wrote = writer.write_all(&input);
                if wrote.is_err() {
                    assert!(writer.flush().is_err());
                    assert!(writer.write_all(b"x").is_err());
                }
                assert!(writer.finish().is_err());
                assert!(output.len() as u64 <= limits.max_blob_bytes);
            }
        }
    }
}

#[test]
fn measured_bound_and_phase_peak_are_checked_at_boundaries() {
    for raw in [0, 1, 31743, 31744, 31745, 65536, 1 << 20] {
        assert_eq!(
            Compression::Uncompressed.max_encoded_size(raw).unwrap(),
            raw
        );
        for bytes in [random_bytes(raw as usize), vec![255; raw as usize]] {
            let (output, _) = encode(&bytes, Compression::Gzip, CHUNK);
            assert!(output.len() as u64 <= Compression::Gzip.max_encoded_size(raw).unwrap());
        }
    }
    assert_eq!(
        Compression::Uncompressed
            .max_encoded_size(u64::MAX)
            .unwrap(),
        u64::MAX
    );
    // Find the exact last representable checked estimate, without allocating payload.
    let (mut low, mut high) = (0, u64::MAX);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if Compression::Gzip.max_encoded_size(middle).is_ok() {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    assert!(Compression::Gzip.max_encoded_size(low).is_ok());
    assert!(Compression::Gzip.max_encoded_size(low + 1).is_err());
    assert!(Compression::Gzip.max_encoded_size(u64::MAX).is_err());
    assert_eq!(payload_peak(10, 100, 40).unwrap(), 110);
    assert_eq!(payload_peak(10, 40, 100).unwrap(), 110);
    assert_eq!(payload_peak(u64::MAX, 0, 0).unwrap(), u64::MAX);
    assert!(payload_peak(u64::MAX, 1, 0).is_err());
    assert!(payload_peak(u64::MAX, 0, 1).is_err());
}

#[derive(Clone, Default)]
struct ObservedWriter {
    bytes: Rc<RefCell<Vec<u8>>>,
    largest_write: Rc<Cell<usize>>,
}
impl Write for ObservedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.largest_write
            .set(self.largest_write.get().max(bytes.len()));
        self.bytes.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn every_cancellation_boundary_including_footer_and_finish_is_sticky() {
    let input = random_bytes(CHUNK * 2 + 1);
    for mode in [Compression::Uncompressed, Compression::Gzip] {
        let limits = Limits {
            max_uncompressed_bytes: input.len() as u64,
            max_blob_bytes: 4 * CHUNK as u64,
        };
        let calls = Cell::new(0);
        let counter = || {
            calls.set(calls.get() + 1);
            false
        };
        let mut writer = LayerWriter::new(Vec::new(), mode, limits, &counter);
        writer.write_all(&input).unwrap();
        writer.finish().unwrap();
        for stop in 1..=calls.get() {
            let observed = ObservedWriter::default();
            let count = Cell::new(0);
            // One-shot cancellation must remain terminal even after it clears.
            let cancelled = || {
                count.set(count.get() + 1);
                count.get() == stop
            };
            let mut writer = LayerWriter::new(observed.clone(), mode, limits, &cancelled);
            let result = writer.write_all(&input);
            if result.is_err() {
                let size = observed.bytes.borrow().len();
                assert!(writer.flush().is_err());
                assert!(writer.write_all(b"ignored").is_err());
                assert!(writer.finish().is_err());
                assert_eq!(
                    observed.bytes.borrow().len(),
                    size,
                    "drop after cancellation wrote data"
                );
            } else {
                assert!(writer.finish().is_err(), "mode={mode:?} stop={stop}");
            }
            assert!(observed.largest_write.get() <= CHUNK);
        }
    }
}

#[test]
fn source_and_destination_writes_are_chunked_and_partial_writes_are_hashed() {
    struct ShortWriter {
        bytes: Vec<u8>,
        interrupted: bool,
        interrupt: Rc<Cell<bool>>,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.interrupted = !self.interrupted;
            if self.interrupted && self.interrupt.get() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = bytes.len().min(7);
            self.bytes.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let input = random_bytes(CHUNK * 3);
    for mode in [Compression::Uncompressed, Compression::Gzip] {
        let limits = Limits {
            max_uncompressed_bytes: input.len() as u64,
            max_blob_bytes: 8 * CHUNK as u64,
        };
        let observed = ObservedWriter::default();
        let mut writer = LayerWriter::new(observed.clone(), mode, limits, &|| false);
        let n = writer.write(&input).unwrap();
        assert!(n <= CHUNK);
        writer.write_all(&input[n..]).unwrap();
        let (_, metadata) = writer.finish().unwrap();
        assert!(observed.largest_write.get() <= CHUNK);
        assert_eq!(
            metadata.descriptor.digest,
            format!("sha256:{:x}", Sha256::digest(&*observed.bytes.borrow()))
        );
        // Interrupt only the write phase; finish is terminal on every error.
        let interrupt = Rc::new(Cell::new(true));
        let mut writer = LayerWriter::new(
            ShortWriter {
                bytes: Vec::new(),
                interrupted: false,
                interrupt: interrupt.clone(),
            },
            mode,
            limits,
            &|| false,
        );
        writer.write_all(&input).unwrap();
        interrupt.set(false);
        let (output, metadata) = writer.finish().unwrap();
        assert_eq!(
            metadata.descriptor.digest,
            format!("sha256:{:x}", Sha256::digest(&output.bytes))
        );
        assert_eq!(
            metadata.diff_id.as_str(),
            format!("sha256:{:x}", Sha256::digest(&input))
        );
        if mode == Compression::Uncompressed {
            assert_eq!(output.bytes, input);
            assert_eq!(metadata.descriptor.digest, metadata.diff_id.as_str());
        } else {
            assert_eq!(output.bytes, encode(&input, mode, CHUNK).0);
        }
    }
}

#[test]
fn interrupted_footer_is_terminal_and_drop_does_not_retry_writes() {
    struct FooterFailure {
        output: ObservedWriter,
        failed_at: Rc<Cell<usize>>,
    }
    impl Write for FooterFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() == 8 && self.failed_at.get() == 0 {
                self.failed_at.set(self.output.bytes.borrow().len());
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.output.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let observed = ObservedWriter::default();
    let failed_at = Rc::new(Cell::new(0));
    let sink = FooterFailure {
        output: observed.clone(),
        failed_at: failed_at.clone(),
    };
    let mut writer = LayerWriter::new(
        sink,
        Compression::Gzip,
        Limits {
            max_uncompressed_bytes: 100,
            max_blob_bytes: 1000,
        },
        &|| false,
    );
    writer.write_all(b"hello").unwrap();
    assert_eq!(
        writer.finish().err().unwrap().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(failed_at.get() >= 10);
    assert_eq!(observed.bytes.borrow().len(), failed_at.get());
}

#[test]
fn failed_owned_spools_are_removed_without_publishing_blobs() {
    let temp = tempfile::tempdir().unwrap();
    let store = oci::BlobStore::open(temp.path()).unwrap();
    let blob_dir = temp.path().join("blobs/sha256");
    let input = random_bytes(2 * CHUNK);
    for mode in [Compression::Uncompressed, Compression::Gzip] {
        for cancel in [true, false] {
            let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                let mut spool = tempfile::NamedTempFile::new_in(&blob_dir)?;
                let count = Cell::new(0);
                let cancelled = || {
                    count.set(count.get() + 1);
                    cancel && count.get() == 7
                };
                let mut writer = LayerWriter::new(
                    spool.as_file_mut(),
                    mode,
                    Limits {
                        max_uncompressed_bytes: if cancel {
                            input.len() as u64
                        } else {
                            CHUNK as u64
                        },
                        max_blob_bytes: 4 * CHUNK as u64,
                    },
                    &cancelled,
                );
                writer.write_all(&input)?;
                let (_, encoded) = writer.finish()?;
                // This path is unreachable for these failed exports. The parent
                // uses publish_export instead of ingest for the already-owned spool.
                use std::io::{Seek, SeekFrom};
                spool.seek(SeekFrom::Start(0))?;
                store.ingest(
                    spool.as_file_mut(),
                    &encoded.descriptor,
                    4 * CHUNK as u64,
                    || false,
                )?;
                Ok(())
            })();
            assert!(result.is_err());
            assert_eq!(fs::read_dir(&blob_dir).unwrap().count(), 0);
            assert!(!temp.path().join("index.json").exists());
        }
    }
}

#[test]
fn terminal_write_flush_and_finish_errors_never_resume_on_drop() {
    struct Broken {
        observed: ObservedWriter,
        fail: Rc<Cell<bool>>,
        flush: bool,
        zero: bool,
    }
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail.get() {
                if self.zero {
                    return Ok(0);
                }
                return Err(io::Error::other("injected"));
            }
            self.observed.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.flush {
                Err(io::Error::other("injected flush"))
            } else {
                Ok(())
            }
        }
    }
    for mode in [Compression::Uncompressed, Compression::Gzip] {
        for (flush, zero) in [(false, false), (false, true), (true, false)] {
            let observed = ObservedWriter::default();
            let fail = Rc::new(Cell::new(!flush));
            let sink = Broken {
                observed: observed.clone(),
                fail: fail.clone(),
                flush,
                zero,
            };
            let mut writer = LayerWriter::new(
                sink,
                mode,
                Limits {
                    max_uncompressed_bytes: 1 << 20,
                    max_blob_bytes: 1 << 20,
                },
                &|| false,
            );
            if flush {
                writer.write_all(b"hello").unwrap();
                assert!(writer.flush().is_err());
            } else {
                assert!(writer.write_all(b"hello").is_err());
            }
            let length = observed.bytes.borrow().len();
            fail.set(false);
            assert!(writer.write_all(b"next").is_err());
            assert!(writer.flush().is_err());
            assert!(writer.finish().is_err());
            assert_eq!(observed.bytes.borrow().len(), length);
        }
        let observed = ObservedWriter::default();
        let fail = Rc::new(Cell::new(false));
        let sink = Broken {
            observed: observed.clone(),
            fail: fail.clone(),
            flush: false,
            zero: false,
        };
        let mut writer = LayerWriter::new(
            sink,
            mode,
            Limits {
                max_uncompressed_bytes: 1 << 20,
                max_blob_bytes: 1 << 20,
            },
            &|| false,
        );
        writer.write_all(b"hello").unwrap();
        fail.set(true);
        if mode == Compression::Gzip {
            assert!(writer.finish().is_err());
        } else {
            writer.finish().unwrap();
        }
    }
}

fn verification_limits() -> layer::Limits {
    layer::Limits {
        max_blob_bytes: 1 << 20,
        max_uncompressed_bytes: 1 << 20,
        max_entries: 100,
        max_metadata_bytes: 1 << 20,
        max_gzip_header_bytes: 10,
    }
}

#[test]
fn corruption_truncation_wrong_diff_id_and_bad_crc_are_rejected() {
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(5);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "file", &b"hello"[..]).unwrap();
    let raw = tar.into_inner().unwrap();
    let (compressed, result) = encode(&raw, Compression::Gzip, CHUNK);
    let directory = tempfile::tempdir().unwrap();
    let store = oci::BlobStore::open(directory.path()).unwrap();
    let spool = directory.path().join("spool");
    fs::create_dir(&spool).unwrap();
    for change in 0..4 {
        let mut bytes = compressed.clone();
        match change {
            0 => bytes[10] ^= 0xff,
            1 => {
                bytes.pop();
            }
            2 => {
                let crc = bytes.len() - 8;
                bytes[crc] ^= 1;
            }
            _ => bytes.push(42),
        }
        assert!(
            store
                .ingest(bytes.as_slice(), &result.descriptor, 1 << 20, || false)
                .is_err()
        );
        let mut descriptor = result.descriptor.clone();
        descriptor.size = bytes.len() as i64;
        descriptor.digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        store
            .ingest(bytes.as_slice(), &descriptor, 1 << 20, || false)
            .unwrap();
        assert!(
            layer::verify(
                &store,
                &descriptor,
                &result.diff_id,
                &spool,
                verification_limits(),
                || false
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(&spool).unwrap().count(), 0);
    }
    store
        .ingest(compressed.as_slice(), &result.descriptor, 1 << 20, || false)
        .unwrap();
    assert!(matches!(
        layer::verify(
            &store,
            &result.descriptor,
            &result.descriptor.digest.parse().unwrap(),
            &spool,
            verification_limits(),
            || false
        ),
        Err(layer::Error::DiffIdMismatch)
    ));
    let mut limits = verification_limits();
    limits.max_gzip_header_bytes = 9;
    assert!(
        layer::verify(
            &store,
            &result.descriptor,
            &result.diff_id,
            &spool,
            limits,
            || false
        )
        .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn exported_tar_replays_identically_with_metadata_and_independent_owned_blobs() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    let temp = tempfile::tempdir_in("/tmp").unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), random_bytes(CHUNK + 1)).unwrap();
    fs::set_permissions(source.join("file"), fs::Permissions::from_mode(0o751)).unwrap();
    fs::hard_link(source.join("file"), source.join("hardlink")).unwrap();
    symlink("file", source.join("symlink")).unwrap();
    fs::create_dir(source.join("empty")).unwrap();
    let file = std::ffi::CString::new(source.join("file").as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: file is NUL terminated and the value is valid for the specified size.
    assert_eq!(
        unsafe {
            libc::lsetxattr(
                file.as_ptr(),
                c"user.weld".as_ptr(),
                b"value".as_ptr().cast(),
                5,
                0,
            )
        },
        0
    );
    let layout = temp.path().join("raw");
    export::export_layout(
        &source,
        &layout,
        &serde_json::json!({"os":"linux", "architecture":"amd64"}),
        export::Limits {
            max_layer_bytes: 1 << 20,
            max_entries: 100,
            max_metadata_bytes: 1 << 20,
        },
        || false,
    )
    .unwrap();
    let metadata = image::load_layout(
        &layout,
        None,
        image::Limits {
            max_metadata_bytes: 1 << 20,
            max_total_metadata_bytes: 4 << 20,
            max_descriptors: 100,
            max_layer_bytes: 1 << 20,
            max_total_layer_bytes: 1 << 20,
        },
        || false,
    )
    .unwrap();
    let original_descriptor = metadata.layers[0].clone();
    let original_store = oci::BlobStore::open(&layout).unwrap();
    let mut original_file = original_store
        .open_verified(&original_descriptor, 1 << 20, || false)
        .unwrap();
    let mut raw = Vec::new();
    original_file.read_to_end(&mut raw).unwrap();
    let (gzip, encoded) = encode(&raw, Compression::Gzip, CHUNK);
    assert_eq!(encoded.diff_id, metadata.diff_ids[0]);
    let compressed_layout = temp.path().join("gzip");
    fs::create_dir(&compressed_layout).unwrap();
    let compressed_store = oci::BlobStore::open(&compressed_layout).unwrap();
    compressed_store
        .ingest(gzip.as_slice(), &encoded.descriptor, 1 << 20, || false)
        .unwrap();
    // Inherited descriptors/bytes are copied intact by the caller, with fresh inodes.
    compressed_store
        .ingest(raw.as_slice(), &original_descriptor, 1 << 20, || false)
        .unwrap();
    let inherited_file = compressed_store
        .open_verified(&original_descriptor, 1 << 20, || false)
        .unwrap();
    assert_ne!(
        inherited_file.metadata().unwrap().ino(),
        original_file.metadata().unwrap().ino()
    );
    assert_eq!(original_descriptor, metadata.layers[0]);
    let a = temp.path().join("replayed-raw");
    fs::create_dir(&a).unwrap();
    let b = temp.path().join("replayed-gzip");
    fs::create_dir(&b).unwrap();
    for (store, descriptor, root) in [
        (&original_store, &original_descriptor, &a),
        (&compressed_store, &encoded.descriptor, &b),
    ] {
        let mut verified = layer::verify(
            store,
            descriptor,
            &encoded.diff_id,
            temp.path(),
            verification_limits(),
            || false,
        )
        .unwrap();
        assert_eq!(verified.size(), encoded.uncompressed_bytes);
        rootfs::apply_layer(root, &mut verified, || false).unwrap();
    }
    for path in ["", "file", "hardlink", "symlink", "empty"] {
        let left = fs::symlink_metadata(a.join(path)).unwrap();
        let right = fs::symlink_metadata(b.join(path)).unwrap();
        let fields = |m: &fs::Metadata| {
            (
                m.mode(),
                m.uid(),
                m.gid(),
                m.size(),
                m.nlink(),
                m.mtime(),
                m.mtime_nsec(),
                m.atime(),
                m.atime_nsec(),
            )
        };
        assert_eq!(fields(&left), fields(&right), "{path}");
    }
    assert_eq!(
        fs::read(a.join("file")).unwrap(),
        fs::read(b.join("file")).unwrap()
    );
    assert_eq!(
        fs::read_link(a.join("symlink")).unwrap(),
        fs::read_link(b.join("symlink")).unwrap()
    );
    assert_eq!(
        fs::metadata(b.join("file")).unwrap().ino(),
        fs::metadata(b.join("hardlink")).unwrap().ino()
    );
    let target = std::ffi::CString::new(b.join("file").as_os_str().as_encoded_bytes()).unwrap();
    let mut attr = [0; 5];
    // SAFETY: target is NUL terminated and attr is writable for its specified length.
    assert_eq!(
        unsafe {
            libc::lgetxattr(
                target.as_ptr(),
                c"user.weld".as_ptr(),
                attr.as_mut_ptr().cast(),
                attr.len(),
            )
        },
        5
    );
    assert_eq!(&attr, b"value");
    fs::write(
        compressed_layout
            .join("blobs/sha256")
            .join(&original_descriptor.digest[7..]),
        b"mutated public copy",
    )
    .unwrap();
    original_store
        .open_verified(&original_descriptor, 1 << 20, || false)
        .unwrap();
}
