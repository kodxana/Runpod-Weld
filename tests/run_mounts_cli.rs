#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
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
    fn automatic(&self, dockerfile: &str, cache: Option<&Path>) -> Output {
        fs::write(self.context.join("Dockerfile"), dockerfile).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        cmd.env("RPWELD_HOME", &self.store)
            .args(["build", "--no-host-dns", "--no-cache"]);
        if let Some(cache) = cache {
            cmd.arg("--cache-mount-dir").arg(cache);
        } else {
            cmd.args(["-t", "mount-test:local"]);
        }
        cmd.arg(&self.context).output().unwrap()
    }
    fn cleanup(&self, id: &str, dry_run: bool) -> serde_json::Value {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        cmd.env("RPWELD_HOME", &self.store)
            .args(["builds", "rm", id, "--json"]);
        if dry_run {
            cmd.arg("--dry-run");
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

#[test]
#[ignore = "requires root, static /bin/busybox, chroot and ptrace"]
fn custom_cache_refuses_older_cleanup_owned_work_and_stages() {
    let f = Fixture::new();
    f.run(
        "external-one",
        "RUN --mount=type=cache,id=custom,target=/cache echo retained > /cache/value",
        false,
    );
    let output = f.automatic("FROM scratch AS tools\nCOPY busybox /tool\nFROM scratch\nCOPY --from=tools /tool /bin/sh\n", None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let older = fs::read_dir(&f.store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.join("build-record.json").is_file())
        .unwrap();
    let id = older.file_name().unwrap().to_str().unwrap();
    assert!(older.join("stages/stage-0-work").is_dir());
    fs::create_dir(older.join("work/nested")).unwrap();
    let alias = f.temp.path().join("older-work-alias");
    symlink(older.join("work"), &alias).unwrap();
    let source = "FROM scratch\nCOPY busybox /bin/sh\nRUN --mount=type=cache,id=custom,target=/cache echo retained > /cache/value\n";
    let paths = [
        older.join("work/packages"),
        older.join("work/nested/packages"),
        older.join("stages/stage-0-work/packages"),
        older.join("image/packages"),
        alias.join("aliased-packages"),
    ];
    let results: Vec<_> = paths.iter().map(|p| f.automatic(source, Some(p))).collect();
    // Exercise the actual CLI maintenance protocol, not merely a path predicate.
    let plan = f.cleanup(id, true);
    for component in ["work", "stages/stage-0-work"] {
        let selected = format!("{id}/{component}");
        assert!(
            plan["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["path"] == selected),
            "{plan}"
        );
    }
    f.cleanup(id, false);
    assert!(!older.join("work").exists());
    assert!(!older.join("stages/stage-0-work").exists());
    for (path, result) in paths.iter().zip(results) {
        assert!(
            !result.status.success(),
            "accepted cleanup-owned cache {}; cleanup subsequently removed it: {}",
            path.display(),
            !path.exists()
        );
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("cleanup-owned"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    // An external private namespace survives cleanup and needs no store lease.
    f.run(
        "external-two",
        "RUN --mount=type=cache,id=custom,target=/cache test -f /cache/value",
        false,
    );
}

#[test]
#[ignore = "requires root and static /bin/busybox"]
fn custom_cache_keeps_current_work_output_and_credential_guards() {
    let f = Fixture::new();
    let work = f.temp.path().join("work-current");
    fs::create_dir(&work).unwrap();
    let alias = f.temp.path().join("current-work-alias");
    symlink(&work, &alias).unwrap();
    for cache in [
        work.join("packages"),
        alias.join("packages"),
        f.temp.path().join("out-current/packages"),
    ] {
        let output = f
            .command("current", "RUN true", true)
            .arg("--cache-mount-dir")
            .arg(&cache)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("must be disjoint"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!cache.exists());
    }
    let credentials = f.temp.path().join("credentials");
    fs::create_dir(&credentials).unwrap();
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700)).unwrap();
    let auth = credentials.join("auth.json");
    fs::write(&auth, b"{}").unwrap();
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
    for (option, path) in [("--authfile", &auth), ("--cert-dir", &credentials)] {
        let output = f
            .command("credentials", "RUN true", true)
            .arg("--cache-mount-dir")
            .arg(&credentials)
            .arg(option)
            .arg(path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("credentials and certificates must be disjoint"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&auth).unwrap(), b"{}");
        assert!(!credentials.join("owner.json").exists());
    }
}

#[test]
#[ignore = "requires root, static /bin/busybox, chroot and ptrace"]
fn cache_preserves_special_modes_numeric_ownership_and_nonroot_reuse() {
    let f = Fixture::new();
    f.run("modes-create", "RUN --mount=type=cache,id=modes,target=/cache /bin/busybox mkdir /cache/group /cache/sticky; /bin/busybox chown 1234:2345 /cache/group /cache/sticky; /bin/busybox chmod 2775 /cache/group; /bin/busybox chmod 1777 /cache/sticky", false);
    let data = fs::read_dir(f.temp.path().join("packages"))
        .unwrap()
        .map(|e| e.unwrap().path().join("data"))
        .find(|p| p.is_dir())
        .unwrap();
    for (name, mode) in [("group", 0o2775), ("sticky", 0o1777)] {
        let meta = fs::metadata(data.join(name)).unwrap();
        assert_eq!(
            (meta.mode() & 0o7777, meta.uid(), meta.gid()),
            (mode, 1234, 2345)
        );
    }
    f.run("modes-reuse", "USER 3456:2345\nRUN --mount=type=cache,id=modes,target=/cache test \"$(/bin/busybox stat -c %a /cache/group)\" = 2775 && test \"$(/bin/busybox stat -c %a /cache/sticky)\" = 1777 && echo group > /cache/group/child && echo sticky > /cache/sticky/child", false);
    let meta = fs::metadata(data.join("group/child")).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (3456, 2345));
    assert_eq!(fs::metadata(data.join("sticky/child")).unwrap().uid(), 3456);
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
