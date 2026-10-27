#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    temp: tempfile::TempDir,
    context: PathBuf,
    secret: PathBuf,
    store: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let context = temp.path().join("context");
        fs::create_dir(&context).unwrap();
        fs::copy("/bin/busybox", context.join("busybox")).unwrap();
        let secret = temp.path().join("secret");
        fs::write(&secret, b"mount-only-private-marker-58293").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        let store = temp.path().join("store");
        Self {
            temp,
            context,
            secret,
            store,
        }
    }
    fn command(&self, name: &str, source: &str, managed: bool) -> Command {
        fs::write(
            self.context.join("Dockerfile"),
            format!("FROM scratch\nCOPY busybox /bin/sh\nCOPY busybox /bin/busybox\n{source}\n"),
        )
        .unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        cmd.env("RPWELD_HOME", &self.store)
            .args(["build", "--no-host-dns", "--secret"])
            .arg(format!("id=token,src={}", self.secret.display()));
        if managed {
            cmd.args(["-t", "mount-test:local"]);
        } else {
            cmd.arg("--cache-mount-dir")
                .arg(self.temp.path().join("packages"));
        }
        cmd.arg("--work-dir")
            .arg(self.temp.path().join(format!("work-{name}")))
            .arg("--output")
            .arg(self.temp.path().join(format!("out-{name}")))
            .arg(&self.context);
        cmd
    }
    fn run(&self, name: &str, source: &str, managed: bool) -> Output {
        let output = self.command(name, source, managed).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
}

fn assert_no_bytes(path: &Path, needle: &[u8]) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let m = fs::symlink_metadata(entry.path()).unwrap();
        if m.is_dir() {
            assert_no_bytes(&entry.path(), needle);
        } else if m.is_file() {
            assert!(
                !fs::read(entry.path())
                    .unwrap()
                    .windows(needle.len())
                    .any(|w| w == needle),
                "secret marker leaked into {}",
                entry.path().display()
            );
        }
    }
}

#[test]
#[ignore = "requires root, static /bin/busybox, chroot and ptrace"]
fn injected_secret_user_mutation_output_suppression_and_checkpoints() {
    let f = Fixture::new();
    for (name, mode) in [("plain", ""), ("quiet", "--progress=quiet")] {
        let source = "USER 1234:2345\nRUN --mount=type=secret,id=token,required=true,uid=1234,gid=2345,mode=0600 /bin/busybox cat /run/secrets/token; echo modified > /run/secrets/token\nUSER 0\nRUN test ! -e /run/secrets/token";
        let mut cmd = f.command(name, source, true);
        if !mode.is_empty() {
            cmd.arg(mode).arg("--no-cache");
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let marker = fs::read(&f.secret).unwrap();
        assert!(!output.stdout.windows(marker.len()).any(|w| w == marker));
        assert!(!output.stderr.windows(marker.len()).any(|w| w == marker));
        assert!(String::from_utf8_lossy(&output.stderr).contains("stdout/stderr suppressed"));
        assert_no_bytes(&f.temp.path().join(format!("work-{name}")), &marker);
        assert_no_bytes(&f.temp.path().join(format!("out-{name}")), &marker);
        assert_no_bytes(&f.store, &marker);
    }
}

#[test]
#[ignore = "requires root, static /bin/busybox, chroot and ptrace"]
fn managed_cache_default_reuse_no_cache_and_export_exclusion() {
    let f = Fixture::new();
    f.run("one", "RUN --mount=type=cache,id=npm,target=/cache echo retained > /cache/pkg; echo image > /image", true);
    assert!(f.store.join("run-cache-v1/owner.json").is_file());
    let output = f.command("two", "RUN --mount=type=cache,id=npm,target=/cache,sharing=locked test -f /cache/pkg; echo changed > /cache/pkg", true).arg("--no-cache").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!f.temp.path().join("work-two/rootfs/cache").exists());
    for name in ["one", "two"] {
        assert_no_bytes(&f.temp.path().join(format!("out-{name}")), b"retained\n");
    }
    f.run("three", "RUN --mount=type=cache,id=npm,target=/cache test \"$(/bin/busybox cat /cache/pkg)\" = changed", true);
}

#[test]
#[ignore = "requires root, static /bin/busybox, chroot and ptrace"]
fn failed_and_cancelled_secret_runs_restore_before_return() {
    let f = Fixture::new();
    let failed = f
        .command(
            "failure",
            "RUN --mount=type=secret,id=token echo changed > /run/secrets/token; exit 8",
            false,
        )
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(!f.temp.path().join("work-failure/rootfs/run").exists());
    let mut cmd = f.command(
        "cancel",
        "RUN --mount=type=secret,id=token echo ready > /started; /bin/busybox sleep 60",
        false,
    );
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let started = f.temp.path().join("work-cancel/rootfs/started");
    let begin = Instant::now();
    while !started.exists() {
        assert!(begin.elapsed() < Duration::from_secs(15));
        assert!(child.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    // SAFETY: unreaped direct child reserves the PID until wait below.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    assert!(!child.wait().unwrap().success());
    assert!(!f.temp.path().join("work-cancel/rootfs/run").exists());
    assert_no_bytes(
        &f.temp.path().join("work-cancel"),
        &fs::read(&f.secret).unwrap(),
    );
    assert!(!f.temp.path().join("out-cancel").exists());
}

#[test]
#[ignore = "requires root, static /bin/busybox, chroot and ptrace"]
fn secret_changes_do_not_fingerprint_bytes_but_required_presence_is_rechecked() {
    let f = Fixture::new();
    let source = "RUN --mount=type=secret,id=token,required=true test -s /run/secrets/token; echo fixed > /result";
    f.run("first", source, true);
    fs::write(&f.secret, b"different-private-marker-71824").unwrap();
    let output = f.run("second", source, true);
    let log = String::from_utf8_lossy(&output.stderr);
    assert!(log.contains("CACHED instruction"), "{log}");
    assert!(
        !log.contains("stdout/stderr suppressed"),
        "secret RUN should be cached: {log}"
    );
    assert_no_bytes(&f.store, &fs::read(&f.secret).unwrap());
    let mut command = Command::new(env!("CARGO_BIN_EXE_rpweld"));
    let output = command
        .env("RPWELD_HOME", &f.store)
        .args(["build", "-t", "mount-test:local", "--no-host-dns"])
        .arg(&f.context)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("required RUN secret source is missing")
    );
}
