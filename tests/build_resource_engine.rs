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
            .arg(self.path("limited/work"))
            .arg("--output")
            .arg(self.path("output"));
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
