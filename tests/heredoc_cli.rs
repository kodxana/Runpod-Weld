//! Independent CLI/OCI assertions; Docker oracle provenance is in fixtures/heredoc/README.md.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::io::Read;
use std::os::unix::{fs::MetadataExt, process::CommandExt};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const COPY: &str = include_str!("fixtures/heredoc/Dockerfile.copy");
const RUN: &str = include_str!("fixtures/heredoc/Dockerfile.run");

struct Fixture {
    temp: tempfile::TempDir,
    context: PathBuf,
    number: usize,
}

impl Fixture {
    fn new(source: &str) -> Self {
        // /tmp is native Linux in the supported WSL setup; never use the checkout on DrvFS.
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let context = temp.path().join("context");
        fs::create_dir(&context).unwrap();
        fs::write(context.join("Dockerfile"), source).unwrap();
        fs::write(context.join(".dockerignore"), "ignored\n").unwrap();
        Self {
            temp,
            context,
            number: 0,
        }
    }

    fn source(&self, source: &str) {
        fs::write(self.context.join("Dockerfile"), source).unwrap();
    }

    fn build(&mut self, base: Option<&Path>, extra: &[&str]) -> (Output, PathBuf, PathBuf) {
        self.number += 1;
        let out = self.temp.path().join(format!("out-{}", self.number));
        let work = self.temp.path().join(format!("work-{}", self.number));
        let log = self.temp.path().join(format!("log-{}", self.number));
        let binary = std::env::var_os("RPWELD_TEST_BINARY")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_rpweld").into());
        let mut command = Command::new(binary);
        command
            .env("RPWELD_HOME", self.temp.path().join("store"))
            .env("HOME", self.temp.path())
            .current_dir(self.temp.path())
            .args([
                "build",
                "-t",
                "test/heredoc:latest",
                "--platform",
                "linux/amd64",
                "--no-host-dns",
                "--run-timeout-seconds",
                "20",
            ])
            .arg("--output")
            .arg(&out)
            .arg("--work-dir")
            .arg(&work)
            .args(extra);
        if let Some(base) = base {
            command
                .arg("--base")
                .arg(format!("alpine={}", base.display()));
        }
        command
            .arg(&self.context)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > Duration::from_secs(120) {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                child.wait().unwrap();
                panic!(
                    "heredoc build deadline: {}",
                    fs::read_to_string(&log).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        (
            Output {
                status,
                stdout: Vec::new(),
                stderr: fs::read(log).unwrap(),
            },
            out,
            work.join("rootfs"),
        )
    }
}

fn success(result: &Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn cached(result: &Output) -> bool {
    let log = String::from_utf8_lossy(&result.stderr);
    log.contains("CACHED (verified local stage)") || log.contains("CACHED instruction")
}

fn manifest(layout: &Path) -> serde_json::Value {
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(layout.join("index.json")).unwrap()).unwrap();
    let digest = index["manifests"][0]["digest"].as_str().unwrap();
    serde_json::from_slice(&fs::read(layout.join("blobs").join(digest.replace(':', "/"))).unwrap())
        .unwrap()
}

// Read emitted layer tar records without using production import/replay helpers.
fn exported_file(layout: &Path, name: &str) -> (Vec<u8>, u32, u64, u64, u64) {
    let mut found = None;
    for layer in manifest(layout)["layers"].as_array().unwrap() {
        let digest = layer["digest"].as_str().unwrap();
        let bytes = fs::read(layout.join("blobs").join(digest.replace(':', "/"))).unwrap();
        let input: Box<dyn Read> = if bytes.starts_with(&[0x1f, 0x8b]) {
            Box::new(flate2::read::GzDecoder::new(&bytes[..]))
        } else {
            Box::new(&bytes[..])
        };
        for entry in tar::Archive::new(input).entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry
                .path()
                .unwrap()
                .components()
                .eq(Path::new(name).components())
            {
                let h = entry.header();
                let metadata = (
                    h.mode().unwrap() & 0o7777,
                    h.uid().unwrap(),
                    h.gid().unwrap(),
                    h.mtime().unwrap(),
                );
                let mut contents = Vec::new();
                entry.read_to_end(&mut contents).unwrap();
                found = Some((contents, metadata.0, metadata.1, metadata.2, metadata.3));
            }
        }
    }
    found.unwrap_or_else(|| panic!("missing exported file {name}"))
}

#[derive(Debug, PartialEq, Eq)]
struct ExportedEntry {
    kind: u8,
    link: Option<PathBuf>,
    bytes: Vec<u8>,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
    pax: BTreeMap<String, Vec<u8>>,
}

fn inline_export(layout: &Path) -> (BTreeMap<PathBuf, ExportedEntry>, serde_json::Value) {
    let manifest = manifest(layout);
    let blob =
        |digest: &str| fs::read(layout.join("blobs").join(digest.replace(':', "/"))).unwrap();
    let mut entries = BTreeMap::new();
    for layer in manifest["layers"].as_array().unwrap() {
        let bytes = blob(layer["digest"].as_str().unwrap());
        let input: Box<dyn Read> = if bytes.starts_with(&[0x1f, 0x8b]) {
            Box::new(flate2::read::GzDecoder::new(&bytes[..]))
        } else {
            Box::new(&bytes[..])
        };
        for entry in tar::Archive::new(input).entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().into_owned();
            let mut observed = ExportedEntry {
                kind: entry.header().entry_type().as_byte(),
                link: entry.link_name().unwrap().map(|p| p.into_owned()),
                bytes: Vec::new(),
                mode: entry.header().mode().unwrap() & 0o7777,
                uid: entry.header().uid().unwrap(),
                gid: entry.header().gid().unwrap(),
                mtime: entry.header().mtime().unwrap(),
                pax: BTreeMap::new(),
            };
            if let Some(pax) = entry.pax_extensions().unwrap() {
                for attribute in pax {
                    let attribute = attribute.unwrap();
                    observed.pax.insert(
                        attribute.key().unwrap().to_owned(),
                        attribute.value_bytes().to_vec(),
                    );
                }
            }
            entry.read_to_end(&mut observed.bytes).unwrap();
            if path == Path::new(".") {
                // Only the generated file promises fixed times. Root metadata otherwise stays checked.
                observed.mtime = 0;
                observed.pax.remove("atime");
                observed.pax.remove("mtime");
            }
            assert!(
                entries.insert(path, observed).is_none(),
                "unexpected duplicate export path"
            );
        }
    }
    assert_eq!(
        entries.keys().cloned().collect::<Vec<_>>(),
        [PathBuf::from("."), PathBuf::from("file")]
    );
    let root = &entries[Path::new(".")];
    assert_eq!(
        (root.kind, root.mode, root.uid, root.gid),
        (b'5', 0o755, 0, 0)
    );
    assert!(root.link.is_none() && root.bytes.is_empty());
    let file = &entries[Path::new("file")];
    assert_eq!(
        (file.kind, file.mode, file.uid, file.gid, file.mtime),
        (b'0', 0o644, 0, 0, 0)
    );
    assert!(file.link.is_none());
    for time in ["atime", "mtime"] {
        assert_eq!(
            file.pax.get(time).map(Vec::as_slice),
            Some(b"0.000000000".as_slice())
        );
    }
    let mut config: serde_json::Value =
        serde_json::from_slice(&blob(manifest["config"]["digest"].as_str().unwrap())).unwrap();
    // Layer hashes encode the excluded root timestamps; every other config field must match.
    config["rootfs"].as_object_mut().unwrap().remove("diff_ids");
    (entries, config)
}

fn assert_copy(out: &Path, crlf: bool) {
    for (name, bytes, mode, uid, gid) in [
        (
            "expanded",
            "\"environment\" 'environment' $VALUE\n",
            0o644,
            0,
            0,
        ),
        ("literal", "\"$VALUE\" '${VALUE}' \\$VALUE\n", 0o644, 0, 0),
        ("mixed", "$VALUE\n", 0o644, 0, 0),
        ("tabs", "first\n  second\n", 0o644, 0, 0),
        ("owned", "owned\n", 0o751, 1234, 2345),
    ] {
        let bytes = if crlf {
            bytes.replace('\n', "\r\n")
        } else {
            bytes.to_owned()
        };
        let observed = exported_file(out, name);
        assert_eq!(observed, (bytes.into_bytes(), mode, uid, gid, 0), "{name}");
    }
}

#[test]
fn copy_quotes_dollars_tabs_metadata_crlf_and_cached_export() {
    for crlf in [false, true] {
        let source = if crlf {
            COPY.replace('\n', "\r\n")
        } else {
            COPY.to_owned()
        };
        let mut f = Fixture::new(&source);
        for attempt in 0..3 {
            let (r, out, _) = f.build(None, if attempt == 2 { &["--no-cache"] } else { &[] });
            success(&r);
            assert_eq!(
                cached(&r),
                attempt == 1,
                "{}",
                String::from_utf8_lossy(&r.stderr)
            );
            assert_copy(&out, crlf);
        }
    }
}

#[test]
fn copy_cache_tracks_body_quoting_args_and_not_ignored_context() {
    let original = "FROM scratch\nARG VALUE=one\nCOPY <<EOF /file\n$VALUE\nEOF\n";
    let mut f = Fixture::new(original);
    let (r, first, _) = f.build(None, &[]);
    success(&r);
    fs::write(f.context.join("ignored"), "unrelated context change").unwrap();
    let (r, warm, _) = f.build(None, &[]);
    success(&r);
    assert!(cached(&r), "repeat must actually replay managed cache");
    assert_eq!(exported_file(&first, "file"), exported_file(&warm, "file"));
    for (source, expected) in [
        (original.replace("$VALUE", "changed"), "changed\n"),
        (original.replace("<<EOF", "<<'EOF'"), "$VALUE\n"),
        (original.replace("VALUE=one", "VALUE=two"), "two\n"),
    ] {
        f.source(&source);
        let (r, out, _) = f.build(None, &[]);
        success(&r);
        assert_eq!(exported_file(&out, "file").0, expected.as_bytes());
        let (r, fresh, _) = f.build(None, &["--no-cache"]);
        success(&r);
        assert!(!cached(&r));
        assert_eq!(
            inline_export(&out),
            inline_export(&fresh),
            "inline file bytes, metadata and image config must match; only root timestamps are dynamic"
        );
    }
}

#[test]
fn crlf_headers_and_delimiters_do_not_change_body_bytes() {
    for (source, expected) in [
        (
            "FROM scratch\r\nCOPY <<EOF /file\r\nbody\nEOF\r\n",
            "body\n",
        ),
        ("FROM scratch\nCOPY <<EOF /file\nbody\r\nEOF\n", "body\r\n"),
    ] {
        let mut f = Fixture::new(source);
        let (r, out, _) = f.build(None, &[]);
        success(&r);
        assert_eq!(exported_file(&out, "file").0, expected.as_bytes());
    }
}

#[test]
fn populated_inline_cache_cannot_bypass_tighter_byte_budget() {
    let mut f = Fixture::new(&format!(
        "FROM scratch\nCOPY <<EOF /large\n{}\nEOF\n",
        "x".repeat(32768)
    ));
    for attempt in 0..2 {
        let (r, _, _) = f.build(None, &[]);
        success(&r);
        assert_eq!(cached(&r), attempt == 1);
    }
    for no_cache in [false, true] {
        let mut args = vec!["--max-rootfs-bytes", "16384"];
        if no_cache {
            args.push("--no-cache");
        }
        let (r, out, _) = f.build(None, &args);
        assert!(!r.status.success(), "inline COPY budget was bypassed");
        assert!(!out.join("index.json").exists());
        let error = String::from_utf8_lossy(&r.stderr).to_lowercase();
        assert!(
            error.contains("budget") || error.contains("limit"),
            "{error}"
        );
    }
}

#[test]
fn missing_delimiter_and_following_instruction_keep_physical_line_numbers() {
    for (source, line) in [
        ("FROM scratch\n\nCOPY <<EOF /file\nbody\n", 3),
        (
            "FROM scratch\nCOPY <<EOF /file\nbody\nEOF\nBOGUS value\n",
            5,
        ),
    ] {
        let mut f = Fixture::new(source);
        let (r, out, _) = f.build(None, &[]);
        assert!(!r.status.success());
        assert!(!out.join("index.json").exists());
        let error = String::from_utf8_lossy(&r.stderr);
        assert!(error.contains(&format!("line {line}")), "{error}");
    }
}

#[test]
fn intentional_unsupported_profile_rejects_before_export() {
    // Docker accepts several of these. Rejection is our bounded contract, not parity.
    for instruction in [
        "RUN <<EOF\n#!/bin/sh\necho hello\nEOF\n",
        "RUN cat <<EOF\nhello\nEOF\n",
        "RUN 3<<EOF\nhello\nEOF\n",
        "RUN <<A <<B\na\nA\nb\nB\n",
        "COPY <<A <<B /\na\nA\nb\nB\n",
        "COPY local <<EOF /\nhello\nEOF\n",
        "ADD <<EOF /file\nhello\nEOF\n",
        "ONBUILD COPY <<EOF /file\nhello\nEOF\n",
        "COPY <<EOF /file\n${VALUE:-fallback}\nEOF\n",
    ] {
        let mut f = Fixture::new(&format!("FROM scratch\n{instruction}"));
        fs::write(f.context.join("local"), "local").unwrap();
        let (r, out, _) = f.build(None, &[]);
        let error = String::from_utf8_lossy(&r.stderr).to_lowercase();
        assert!(!r.status.success(), "unexpectedly accepted {instruction}");
        assert!(!out.join("index.json").exists());
        assert!(
            error.contains("unsupported") || error.contains("not supported"),
            "must reject grammar explicitly: {error}"
        );
    }
}

#[test]
#[ignore = "requires root, native Linux filesystem and RPWELD_TEST_LAYOUT"]
fn run_shell_user_expansion_cache_body_change_and_crlf_oracle() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let base = fs::canonicalize(
        std::env::var_os("RPWELD_TEST_LAYOUT").expect("local Alpine OCI required"),
    )
    .unwrap();
    let mut f = Fixture::new(RUN);
    for attempt in 0..3 {
        let (r, out, root) = f.build(
            Some(&base),
            if attempt == 2 { &["--no-cache"] } else { &[] },
        );
        success(&r);
        assert_eq!(cached(&r), attempt == 1);
        assert_eq!(
            exported_file(&out, "tmp/result").0,
            b"environment\n$VALUE\n1234\n2345\nstrict\nenvironment\n"
        );
        let metadata = fs::metadata(root.join("tmp/result")).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (1234, 2345));
        assert_eq!(exported_file(&out, "tmp/root-result").0, b"restored\n");
    }
    f.source(&RUN.replace("restored", "changed"));
    let (r, out, _) = f.build(Some(&base), &[]);
    success(&r);
    assert_eq!(exported_file(&out, "tmp/root-result").0, b"changed\n");
    f.source(&RUN.replace('\n', "\r\n"));
    let (r, out, _) = f.build(Some(&base), &[]);
    assert!(
        !r.status.success(),
        "this CRLF shell case fails in the pinned Docker oracle"
    );
    assert!(!out.join("index.json").exists());
}
