#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    temp: tempfile::TempDir,
    mount: CString,
}

impl Fixture {
    fn new(inodes: u32) -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0
        );
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("limited")).unwrap();
        fs::create_dir(temp.path().join("context")).unwrap();
        let mount = CString::new(temp.path().join("limited").as_os_str().as_bytes()).unwrap();
        let options = CString::new(format!("size=512m,nr_inodes={inodes},mode=0700")).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    mount.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    options.as_ptr().cast(),
                )
            },
            0
        );
        Self { temp, mount }
    }

    fn path(&self, path: &str) -> PathBuf {
        self.temp.path().join(path)
    }

    fn build(&self, source: &str, root_limit: u64) -> Output {
        self.build_at(source, root_limit, "limited/work", "output", || {})
    }

    fn build_at(
        &self,
        source: &str,
        root_limit: u64,
        work: &str,
        output: &str,
        mut observe: impl FnMut(),
    ) -> Output {
        fs::write(self.path("context/Dockerfile"), source).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        command
            .env("HOME", self.temp.path())
            .env("RPWELD_HOME", self.path("store"))
            .args([
                "build",
                "-t",
                "test/resource-engine",
                "--no-cache",
                "--no-host-dns",
                "--export-mode",
                "layered",
                "--max-layer-bytes",
                "419430400",
                "--metadata-budget",
                "67108864",
                "--max-entries",
                "100000",
                "--max-rootfs-bytes",
            ])
            .arg(root_limit.to_string())
            .arg("--work-dir")
            .arg(self.path(work))
            .arg("--output")
            .arg(self.path(output));
        if self.path("base").exists() {
            command
                .arg("--base")
                .arg(format!("local={}", self.path("base").display()));
        }
        let stdout = self.path("stdout");
        let stderr = self.path("stderr");
        let mut child = command
            .arg(self.path("context"))
            .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        let start = Instant::now();
        let status = loop {
            observe();
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > Duration::from_secs(30) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "bounded fixture timed out: {}",
                    fs::read_to_string(stderr).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: fs::read(stdout).unwrap(),
            stderr: fs::read(stderr).unwrap(),
        }
    }

    fn base(&self, entries: &[(&str, u8, u64, Option<&str>)]) {
        let mut tar = tar::Builder::new(tempfile::tempfile().unwrap());
        for &(path, kind, size, link) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_path(path).unwrap();
            header.set_entry_type(tar::EntryType::new(kind));
            header.set_size(size);
            header.set_mode(0o755);
            if let Some(link) = link {
                header.set_link_name(link).unwrap();
            }
            header.set_cksum();
            tar.append(&header, std::io::repeat(0).take(size)).unwrap();
        }
        let mut tar = tar.into_inner().unwrap();
        tar.seek(SeekFrom::Start(0)).unwrap();
        let mut digest = Sha256::new();
        std::io::copy(&mut tar, &mut digest).unwrap();
        let diff = format!("sha256:{:x}", digest.finalize());
        tar.seek(SeekFrom::Start(0)).unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::copy(&mut tar, &mut gzip).unwrap();
        let layer = self.blob(
            "application/vnd.oci.image.layer.v1.tar+gzip",
            &gzip.finish().unwrap(),
        );
        let config = self.blob(
            "application/vnd.oci.image.config.v1+json",
            &serde_json::to_vec(
                &serde_json::json!({"architecture":"amd64","os":"linux","config":{},
                "rootfs":{"type":"layers","diff_ids":[diff]}}),
            )
            .unwrap(),
        );
        let manifest = self.blob("application/vnd.oci.image.manifest.v1+json", &serde_json::to_vec(
            &serde_json::json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
                "config":config,"layers":[layer]})).unwrap());
        fs::write(
            self.path("base/oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            self.path("base/index.json"),
            serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"manifests":[manifest]}))
                .unwrap(),
        )
        .unwrap();
    }

    fn blob(&self, media: &str, bytes: &[u8]) -> serde_json::Value {
        let digest = format!("{:x}", Sha256::digest(bytes));
        fs::create_dir_all(self.path("base/blobs/sha256")).unwrap();
        fs::write(self.path("base/blobs/sha256").join(&digest), bytes).unwrap();
        serde_json::json!({"mediaType":media,"digest":format!("sha256:{digest}"),"size":bytes.len()})
    }

    fn plain_layer(&self, entries: &[(&str, u8, u64, Option<&str>)]) -> serde_json::Value {
        let mut tar = tar::Builder::new(tempfile::NamedTempFile::new_in(self.temp.path()).unwrap());
        for &(path, kind, size, link) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_path(path).unwrap();
            header.set_entry_type(tar::EntryType::new(kind));
            header.set_size(size);
            header.set_mode(0o755);
            if let Some(link) = link {
                header.set_link_name(link).unwrap();
            }
            header.set_cksum();
            tar.append(&header, std::io::repeat(0).take(size)).unwrap();
        }
        let mut tar = tar.into_inner().unwrap();
        tar.seek(SeekFrom::Start(0)).unwrap();
        let mut digest = Sha256::new();
        let size = std::io::copy(&mut tar, &mut digest).unwrap();
        let digest = format!("{:x}", digest.finalize());
        fs::create_dir_all(self.path("base/blobs/sha256")).unwrap();
        tar.persist(self.path("base/blobs/sha256").join(&digest))
            .unwrap();
        serde_json::json!({"mediaType":"application/vnd.oci.image.layer.v1.tar",
            "digest":format!("sha256:{digest}"),"size":size})
    }

    fn plain_base(&self, layers: &[serde_json::Value]) {
        let ids: Vec<_> = layers.iter().map(|layer| layer["digest"].clone()).collect();
        self.base_layers(layers, &ids);
    }

    fn base_layers(&self, layers: &[serde_json::Value], ids: &[serde_json::Value]) {
        let history: Vec<_> = (0..layers.len())
            .map(|i| serde_json::json!({"created_by":format!("fixture layer {i}")}))
            .collect();
        let config = self.blob(
            "application/vnd.oci.image.config.v1+json",
            &serde_json::to_vec(
                &serde_json::json!({"architecture":"amd64","os":"linux","config":{},
                "rootfs":{"type":"layers","diff_ids":ids},"history":history}),
            )
            .unwrap(),
        );
        let manifest = self.blob("application/vnd.oci.image.manifest.v1+json", &serde_json::to_vec(
            &serde_json::json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
                "config":config,"layers":layers})).unwrap());
        fs::write(
            self.path("base/oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            self.path("base/index.json"),
            serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"manifests":[manifest]}))
                .unwrap(),
        )
        .unwrap();
    }

    fn available(&self) -> u64 {
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: mount is a valid C path and stat points to writable storage.
        assert_eq!(
            unsafe { libc::statvfs(self.mount.as_ptr(), stat.as_mut_ptr()) },
            0
        );
        // SAFETY: successful statvfs initialized stat.
        let stat = unsafe { stat.assume_init() };
        stat.f_bavail * stat.f_frsize
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::umount2(self.mount.as_ptr(), libc::MNT_DETACH) },
            0
        );
    }
}

fn log(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
#[ignore = "requires root and CAP_SYS_ADMIN; disposable 512 MiB tmpfs"]
fn copy_reserves_prepared_allocation_before_creating_destination() {
    let fixture = Fixture::new(16384);
    fs::File::create(fixture.path("context/payload"))
        .unwrap()
        .set_len(300 << 20)
        .unwrap();
    let output = fixture.build(
        "FROM scratch\nCOPY payload /new/parents/payload\n",
        400 << 20,
    );
    assert!(!output.status.success(), "{}", log(&output));
    assert!(
        !fixture.path("limited/work/rootfs/new").exists(),
        "COPY mutated destination: {}",
        log(&output)
    );
    assert!(
        log(&output).contains("COPY prepared allocation")
            && log(&output).contains("additional/reserved bytes"),
        "{}",
        log(&output)
    );
    assert!(!fixture.path("output").exists());
}

#[test]
#[ignore = "requires root and CAP_SYS_ADMIN; disposable 512 MiB tmpfs"]
fn layered_baseline_reserves_unique_hardlink_payload() {
    let fixture = Fixture::new(16384);
    fixture.base(&[
        ("payload", b'0', 60 << 20, None),
        ("alias1", b'1', 0, Some("payload")),
        ("alias2", b'1', 0, Some("payload")),
        ("alias3", b'1', 0, Some("payload")),
    ]);
    let output = fixture.build("FROM local\nLABEL changed=yes\n", 400 << 20);
    assert!(output.status.success(), "{}", log(&output));
    let root = fixture.path("limited/work/rootfs");
    let original = fs::metadata(root.join("payload")).unwrap();
    for name in ["alias1", "alias2", "alias3"] {
        assert_eq!(fs::metadata(root.join(name)).unwrap().ino(), original.ino());
    }
}

#[test]
#[ignore = "requires root and CAP_SYS_ADMIN; disposable 2048-inode tmpfs"]
fn replay_reserves_shared_implicit_parents_once() {
    let fixture = Fixture::new(2048);
    let paths: Vec<_> = (0..200)
        .map(|i| format!("a/b/c/d/e/f/g/h/i/j/{i}"))
        .collect();
    let entries: Vec<_> = paths
        .iter()
        .map(|path| (path.as_str(), b'0', 0, None))
        .collect();
    fixture.base(&entries);
    let output = fixture.build("FROM local\n", 400 << 20);
    assert!(output.status.success(), "{}", log(&output));
    assert_eq!(
        fs::read_dir(fixture.path("limited/work/rootfs/a/b/c/d/e/f/g/h/i/j"))
            .unwrap()
            .count(),
        200
    );
}

#[test]
#[ignore = "requires root and CAP_SYS_ADMIN; disposable 512 MiB tmpfs"]
fn baseline_reuses_initial_replay_without_allocating_intermediate_roots() {
    let fixture = Fixture::new(16384);
    let first = fixture.plain_layer(&[("old", b'0', 120 << 20, None)]);
    let second = fixture.plain_layer(&[
        (".wh.old", b'0', 0, None),
        ("payload", b'0', 60 << 20, None),
        ("alias1", b'1', 0, Some("payload")),
        ("alias2", b'1', 0, Some("payload")),
        ("alias3", b'1', 0, Some("payload")),
    ]);
    fixture.plain_base(&[first, second]);
    let mut minimum = fixture.available();
    let output = fixture.build_at(
        "FROM local\nLABEL changed=yes\n",
        400 << 20,
        "limited/work",
        "output",
        || minimum = minimum.min(fixture.available()),
    );
    eprintln!(
        "baseline minimum free bytes: {minimum}; reserve: {}",
        256 << 20
    );
    let root = fixture.path("limited/work/rootfs");
    assert!(!root.join("old").exists());
    let payload = fs::metadata(root.join("payload")).unwrap();
    assert_eq!(payload.len(), 60 << 20, "initial replay must complete");
    for name in ["alias1", "alias2", "alias3"] {
        assert_eq!(fs::metadata(root.join(name)).unwrap().ino(), payload.ino());
    }
    assert!(output.status.success(), "{}", log(&output));
    assert!(minimum >= 256 << 20, "baseline crossed reserve: {minimum}");
    assert!(log(&output).contains("Capturing verified base filesystem (no replay)"));
    assert!(fixture.path("output/index.json").is_file());
    let mut remaining: Vec<_> = fs::read_dir(fixture.path("limited/work"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    remaining.sort();
    assert_eq!(
        remaining,
        ["rootfs", "spool", "state"],
        "capture must not create a second replay"
    );
}

#[test]
#[ignore = "requires root and CAP_SYS_ADMIN; disposable 512 MiB tmpfs"]
fn regression_export_inherits_duplicate_blobs_without_temporary_copy() {
    let fixture = Fixture::new(16384);
    let layer = fixture.plain_layer(&[("base", b'0', 60 << 20, None)]);
    fixture.plain_base(&[layer.clone(), layer.clone()]);
    let mut filler = fs::File::create(fixture.path("limited/filler")).unwrap();
    std::io::copy(&mut std::io::repeat(0).take(112 << 20), &mut filler).unwrap();
    assert_eq!(fixture.available(), 400 << 20);
    fs::File::create(fixture.path("context/delta"))
        .unwrap()
        .set_len(60 << 20)
        .unwrap();
    let mut minimum = fixture.available();
    let output = fixture.build_at(
        "FROM local\nCOPY delta /delta\n",
        400 << 20,
        "work",
        "limited/output",
        || minimum = minimum.min(fixture.available()),
    );
    eprintln!(
        "duplicate export minimum free bytes: {minimum}; reserve: {}",
        256 << 20
    );
    assert!(output.status.success(), "{}", log(&output));
    assert!(
        minimum >= 256 << 20,
        "duplicate inheritance crossed reserve: {minimum}"
    );
    let read_blob = |descriptor: &serde_json::Value| {
        let encoded = descriptor["digest"]
            .as_str()
            .unwrap()
            .strip_prefix("sha256:")
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(fixture.path("limited/output/blobs/sha256").join(encoded)).unwrap(),
        )
        .unwrap()
    };
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.path("limited/output/index.json")).unwrap())
            .unwrap();
    let manifest = read_blob(&index["manifests"][0]);
    assert_eq!(manifest["layers"].as_array().unwrap().len(), 3);
    assert_eq!(manifest["layers"][0], layer);
    assert_eq!(manifest["layers"][1], layer);
    let config = read_blob(&manifest["config"]);
    assert_eq!(config["rootfs"]["diff_ids"].as_array().unwrap().len(), 3);
    assert_eq!(config["rootfs"]["diff_ids"][0], layer["digest"]);
    assert_eq!(config["rootfs"]["diff_ids"][1], layer["digest"]);
    assert_eq!(config["history"].as_array().unwrap().len(), 3);
    for i in 0..2 {
        assert_eq!(
            config["history"][i],
            serde_json::json!({"created_by":format!("fixture layer {i}")})
        );
    }
}

#[test]
#[ignore = "requires root and CAP_SYS_ADMIN; disposable 512 MiB tmpfs"]
fn baseline_reuses_verified_gzip_without_a_second_decompression() {
    let fixture = Fixture::new(16384);
    let plain = [
        fixture.plain_layer(&[("first", b'0', 120 << 20, None)]),
        fixture.plain_layer(&[("second", b'0', 60 << 20, None)]),
    ];
    let ids: Vec<_> = plain.iter().map(|layer| layer["digest"].clone()).collect();
    let compressed: Vec<_> = plain
        .iter()
        .map(|layer| {
            let encoded = layer["digest"]
                .as_str()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap();
            let mut file = fs::File::open(fixture.path("base/blobs/sha256").join(encoded)).unwrap();
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            std::io::copy(&mut file, &mut gzip).unwrap();
            fixture.blob(
                "application/vnd.oci.image.layer.v1.tar+gzip",
                &gzip.finish().unwrap(),
            )
        })
        .collect();
    fixture.base_layers(&compressed, &ids);
    let mut minimum = fixture.available();
    let output = fixture.build_at(
        "FROM local\nLABEL changed=yes\n",
        400 << 20,
        "limited/work",
        "output",
        || minimum = minimum.min(fixture.available()),
    );
    eprintln!(
        "gzip baseline minimum free bytes: {minimum}; reserve: {}",
        256 << 20
    );
    assert!(output.status.success(), "{}", log(&output));
    let root = fixture.path("limited/work/rootfs");
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        2,
        "initial replay must be retained"
    );
    for (name, size) in [("first", 120 << 20), ("second", 60 << 20)] {
        let mut file = fs::File::open(root.join(name)).unwrap();
        assert_eq!(file.metadata().unwrap().len(), size);
        let mut digest = Sha256::new();
        std::io::copy(&mut file, &mut digest).unwrap();
        let mut expected = Sha256::new();
        std::io::copy(&mut std::io::repeat(0).take(size), &mut expected).unwrap();
        assert_eq!(
            digest.finalize(),
            expected.finalize(),
            "retained {name} changed"
        );
    }
    assert!(fixture.path("output/index.json").is_file());
    let mut remaining: Vec<_> = fs::read_dir(fixture.path("limited/work"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    remaining.sort();
    assert_eq!(
        remaining,
        ["rootfs", "spool", "state"],
        "capture must not create a second replay"
    );
    assert!(
        minimum >= 256 << 20,
        "gzip baseline crossed reserve: {minimum}; {}",
        log(&output)
    );
    assert!(
        log(&output).contains("Capturing verified base filesystem (no replay)"),
        "{}",
        log(&output)
    );
    assert!(
        !log(&output).contains("Layer(Cancelled)"),
        "{}",
        log(&output)
    );
}
