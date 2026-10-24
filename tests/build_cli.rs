#[cfg(target_os = "linux")]
use std::fs;
use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rpweld"))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "requires root and RPWELD_TEST_LAYOUT pointing to a unique Alpine OCI image"]
fn run_worker_is_independent_of_launch_directory() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let layout = fs::canonicalize(std::env::var_os("RPWELD_TEST_LAYOUT").unwrap()).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    let dockerfile = context.join("Dockerfile");
    fs::write(&dockerfile, "FROM alpine\nRUN printf ok > /weld-marker\n").unwrap();
    for (index, cwd) in [temp.path(), std::path::Path::new("/")].iter().enumerate() {
        let work = temp.path().join(format!("work-{index}"));
        let result = cli()
            .current_dir(cwd)
            .arg("build")
            .arg("-f")
            .arg(&dockerfile)
            .arg("--base")
            .arg(format!("alpine={}", layout.display()))
            .arg("--work-dir")
            .arg(&work)
            .arg("--output")
            .arg(temp.path().join(format!("output-{index}")))
            .arg(&context)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(work.join("rootfs/weld-marker")).unwrap(), b"ok");
    }
}

#[test]
fn flags_are_validated_before_source_is_opened() {
    let result = cli()
        .args([
            "build",
            "-f",
            "does-not-exist",
            "--output",
            "out",
            "--work-dir",
            "work",
            "--metadata-budget",
            "0",
            ".",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("invalid positive budget"));
}

#[test]
fn help_explains_experimental_limits() {
    let result = cli().args(["build", "--help"]).output().unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    for expected in [
        "single stage",
        "--base-ref",
        "no memory or disk quota",
        "No COPY",
        "not a sandbox",
    ] {
        assert!(text.contains(expected), "{expected}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn fifo_dockerfile_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fifo");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let mut child = cli()
        .arg("build")
        .arg("-f")
        .arg(&path)
        .args(["--output", "out", "--work-dir", "work", "."])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > std::time::Duration::from_secs(5) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("FIFO open blocked");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("regular Dockerfile"));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn scratch_build_and_local_reference_binding() {
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    let dockerfile = context.join("Dockerfile");
    fs::write(
        &dockerfile,
        "FROM scratch\nARG VALUE=default\nENV VALUE=$VALUE\nWORKDIR /app\nCMD [\"/hello\"]\n",
    )
    .unwrap();
    let output = temp.path().join("output");
    let work = temp.path().join("work");
    let result = cli()
        .arg("build")
        .arg("-f")
        .arg(&dockerfile)
        .arg("--output")
        .arg(&output)
        .arg("--work-dir")
        .arg(&work)
        .args(["--build-arg", "VALUE=override"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(work.join("rootfs/app").is_dir());
    let index_path = output.join("index.json");
    let mut index: serde_json::Value =
        serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
    index["manifests"][0]["annotations"] =
        serde_json::json!({"org.opencontainers.image.ref.name":"selected"});
    fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();
    fs::write(&dockerfile, "FROM local:test\nWORKDIR /next\n").unwrap();
    let result = cli()
        .arg("build")
        .arg("-f")
        .arg(&dockerfile)
        .arg("--output")
        .arg(temp.path().join("second-output"))
        .arg("--work-dir")
        .arg(temp.path().join("second-work"))
        .arg("--base")
        .arg(format!("local:test={}", output.display()))
        .args(["--base-ref", "local:test=selected"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(temp.path().join("second-work/rootfs/next").is_dir());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn unsupported_copy_does_not_create_build_directories() {
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context");
    fs::create_dir(&context).unwrap();
    let dockerfile = context.join("Dockerfile");
    fs::write(&dockerfile, "FROM scratch\nCOPY a /a\n").unwrap();
    let output = temp.path().join("output");
    let work = temp.path().join("work");
    let result = cli()
        .arg("build")
        .arg("-f")
        .arg(dockerfile)
        .arg("--output")
        .arg(&output)
        .arg("--work-dir")
        .arg(&work)
        .arg(context)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("COPY unsupported"));
    assert!(!work.exists());
    assert!(!output.exists());
}
