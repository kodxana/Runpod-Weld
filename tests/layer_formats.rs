//! Independent fixtures: Python tarfile, never Rust tar::Builder.
use rpweld::{
    layer::{self, EntryKind, Limits, VerifiedLayer},
    oci::{BlobStore, Descriptor, Sha256Digest},
};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

fn limits() -> Limits {
    Limits {
        max_blob_bytes: 32768,
        max_uncompressed_bytes: 32768,
        max_entries: 32,
        max_metadata_bytes: 65536,
        max_gzip_header_bytes: 1024,
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/layers")
        .join(format!("{name}.tar"));
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() <= 32768);
    bytes
}

fn verify(bytes: &[u8], limits: Limits) -> Result<VerifiedLayer, layer::Error> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    let store = BlobStore::open(&path).unwrap();
    let spool = path.join("spool");
    std::fs::create_dir(&spool).unwrap();
    let digest: Sha256Digest = format!("sha256:{:x}", Sha256::digest(bytes))
        .parse()
        .unwrap();
    let descriptor = Descriptor {
        media_type: "application/vnd.oci.image.layer.v1.tar".into(),
        digest: digest.to_string(),
        size: bytes.len() as i64,
        annotations: Default::default(),
        extensions: Default::default(),
    };
    store
        .ingest(bytes, &descriptor, bytes.len() as u64, || false)
        .unwrap();
    let result = layer::verify(&store, &descriptor, &digest, &spool, limits, || false);
    if let Ok(layer) = &result {
        assert_eq!(layer.diff_id(), &digest);
        assert_eq!(layer.size(), bytes.len() as u64);
    }
    result
}

fn payload(layer: &mut VerifiedLayer, index: usize, expected: &[u8]) {
    let entry = &layer.entries()[index];
    assert_eq!(entry.kind, EntryKind::File);
    assert_eq!(entry.size, expected.len() as u64);
    let offset = entry.data_offset;
    assert_eq!(offset % 512, 0);
    assert!(offset + entry.size <= layer.size());
    layer.seek(SeekFrom::Start(offset)).unwrap();
    let mut actual = vec![0; expected.len()];
    layer.read_exact(&mut actual).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn python_pax_long_paths_links_high_ids_and_signed_fractional_mtime() {
    let mut layer = verify(&fixture("pax"), limits()).unwrap();
    let entries = layer.entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries[0].path,
        format!("deep/{}", "p".repeat(140)).as_bytes()
    );
    assert_eq!((entries[0].uid, entries[0].gid), (1 << 40, (1 << 40) + 7));
    assert!(entries[0].mtime.negative);
    assert_eq!(entries[0].mtime.seconds, 1);
    assert_eq!(entries[0].mtime.fraction, b"250000001");
    assert_eq!(entries[1].path, b"symlink");
    assert_eq!(entries[1].kind, EntryKind::Symlink);
    assert_eq!(
        entries[1].link_target.as_deref(),
        Some(format!("../{}", "t".repeat(140)).as_bytes())
    );
    assert_eq!(entries[1].size, 0);
    assert!(entries[1].mtime.negative);
    assert_eq!(entries[1].mtime.seconds, 0);
    assert_eq!(entries[1].mtime.fraction, b"000000001");
    assert_eq!(entries[2].path, b"sentinel");
    payload(&mut layer, 0, b"PAX payload");
    payload(&mut layer, 2, b"SENTINEL");
}

#[test]
fn python_gnu_ordinary_longname_longlink_and_base256_ids() {
    let mut layer = verify(&fixture("gnu"), limits()).unwrap();
    let entries = layer.entries();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].path, b"ordinary");
    assert!(entries[0].mtime.negative);
    assert_eq!(entries[0].mtime.seconds, 2);
    assert!(entries[0].mtime.fraction.is_empty());
    assert_eq!(
        entries[1].path,
        format!("deep/{}", "p".repeat(140)).as_bytes()
    );
    assert_eq!((entries[1].uid, entries[1].gid), (1 << 40, (1 << 40) + 7));
    assert_eq!(entries[2].path, b"symlink");
    assert_eq!(entries[2].kind, EntryKind::Symlink);
    assert_eq!(
        entries[2].link_target.as_deref(),
        Some(format!("../{}", "t".repeat(140)).as_bytes())
    );
    assert_eq!(entries[3].path, b"sentinel");
    payload(&mut layer, 0, b"GNU");
    payload(&mut layer, 1, b"LONG");
    payload(&mut layer, 3, b"SENTINEL");
}

#[test]
fn hardlinks_preserve_forward_backward_and_lower_layer_references() {
    let mut layer = verify(&fixture("hardlinks"), limits()).unwrap();
    assert_eq!(layer.entries().len(), 4);
    for (index, path, target) in [
        (0, "forward", "later"),
        (1, "lower", "lower-layer/file"),
        (3, "backward", "later"),
    ] {
        let entry = &layer.entries()[index];
        assert_eq!(entry.path, path.as_bytes());
        assert_eq!(entry.link_target.as_deref(), Some(target.as_bytes()));
        assert_eq!(entry.kind, EntryKind::Hardlink);
        assert_eq!(entry.size, 0);
    }
    assert_eq!(layer.entries()[2].path, b"later");
    payload(&mut layer, 2, b"TARGET");
}

#[test]
fn pax_effective_size_controls_payload_and_next_header_offset() {
    let mut layer = verify(&fixture("pax-size"), limits()).unwrap();
    assert_eq!(layer.entries().len(), 2);
    assert_eq!(layer.entries()[0].path, b"effective");
    assert_eq!(layer.entries()[0].data_offset, 1536);
    assert_eq!(layer.entries()[1].path, b"sentinel");
    assert_eq!(layer.entries()[1].data_offset, 3072);
    payload(&mut layer, 0, &[b'A'; 513]);
    payload(&mut layer, 1, b"SENTINEL");
}

#[test]
fn pax_binary_xattr_is_length_delimited_not_line_or_nul_delimited() {
    let mut layer = verify(&fixture("pax-binary-xattr"), limits()).unwrap();
    assert_eq!(layer.entries().len(), 1);
    assert_eq!(layer.entries()[0].path, b"sentinel");
    assert_eq!(layer.entries()[0].xattrs.len(), 1);
    assert_eq!(
        layer.entries()[0]
            .xattrs
            .get(b"user.binary".as_slice())
            .map(Vec::as_slice),
        Some(b"line1\nline2\0key=value\xff".as_slice())
    );
    payload(&mut layer, 0, b"SENTINEL");
}

#[test]
fn malformed_pax_record_lengths_and_delimiters_are_rejected() {
    for suffix in [
        "zero",
        "short",
        "overrun",
        "nondigit",
        "overflow",
        "no-newline",
        "no-equals",
    ] {
        let name = format!("bad-pax-{suffix}");
        assert!(
            matches!(
                verify(&fixture(&name), limits()),
                Err(layer::Error::Invalid(_))
            ),
            "{name}"
        );
    }
}

#[test]
fn dangling_extensions_global_semantics_and_sparse_are_explicitly_rejected() {
    for name in [
        "dangling-x",
        "dangling-L",
        "dangling-K",
        "global-semantic",
        "pax-sparse",
        "gnu-sparse",
    ] {
        assert!(
            matches!(
                verify(&fixture(name), limits()),
                Err(layer::Error::Invalid(_))
            ),
            "{name}"
        );
    }
}

#[test]
fn base256_must_check_all_twelve_bytes_for_overflow() {
    for name in ["base256-overflow-size", "base256-overflow-mtime"] {
        assert!(
            matches!(
                verify(&fixture(name), limits()),
                Err(layer::Error::Invalid(_))
            ),
            "{name}"
        );
    }
}

#[test]
fn extension_bytes_count_toward_metadata_budget() {
    let bytes = fixture("metadata-flood");
    let mut layer = verify(&bytes, limits()).unwrap();
    assert_eq!(layer.entries().len(), 1);
    payload(&mut layer, 0, b"SENTINEL");
    let mut bounded = limits();
    bounded.max_metadata_bytes = 4096;
    assert!(matches!(
        verify(&bytes, bounded),
        Err(layer::Error::Limit("metadata bytes"))
    ));
}

// Independent, strict framing reader for fixture expectations only. Never parses
// production output; makes the exact timestamp/xattr contract reviewable.
fn first_pax(bytes: &[u8]) -> Vec<(&[u8], &[u8])> {
    assert_eq!(bytes[156], b'x');
    let size_text = std::str::from_utf8(&bytes[124..135]).unwrap().trim();
    let size = usize::from_str_radix(size_text, 8).unwrap();
    let mut body = &bytes[512..512 + size];
    let mut records = Vec::new();
    while !body.is_empty() {
        let space = body.iter().position(|b| *b == b' ').unwrap();
        let length: usize = std::str::from_utf8(&body[..space])
            .unwrap()
            .parse()
            .unwrap();
        let record = &body[space + 1..length];
        assert_eq!(record.last(), Some(&b'\n'));
        let equals = record.iter().position(|b| *b == b'=').unwrap();
        records.push((&record[..equals], &record[equals + 1..record.len() - 1]));
        body = &body[length..];
    }
    records
}

#[test]
fn raw_fixture_metadata_expectations_and_hashes() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/layers/manifest.json")).unwrap();
    let mut total = 0;
    for (name, expected) in manifest["fixtures"].as_object().unwrap() {
        let bytes = fixture(name);
        total += bytes.len();
        assert_eq!(bytes.len() as u64, expected["bytes"].as_u64().unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            expected["sha256"].as_str().unwrap()
        );
    }
    assert!(total <= 131072);
    let pax = fixture("pax");
    assert!(first_pax(&pax).contains(&(&b"mtime"[..], &b"-1.250000001"[..])));
    let binary = fixture("pax-binary-xattr");
    assert_eq!(
        first_pax(&binary),
        vec![(
            &b"SCHILY.xattr.user.binary"[..],
            &b"line1\nline2\0key=value\xff"[..]
        )]
    );
    let sized = fixture("pax-size");
    assert!(first_pax(&sized).contains(&(&b"size"[..], &b"513"[..])));
    assert_eq!(&sized[1024 + 124..1024 + 136], b"00000000001\0");
}
