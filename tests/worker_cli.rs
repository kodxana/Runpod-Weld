use std::process::Command;

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root, cc -static and child ptrace"]
fn build_output_prefixes_complete_without_stdout_lock_deadlock() {
    use std::{
        fs,
        time::{Duration, Instant},
    };
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let tmp = tempfile::tempdir().unwrap();
    let context = tmp.path().join("context");
    fs::create_dir(&context).unwrap();
    let c = tmp.path().join("probe.c");
    fs::write(
        &c,
        r#"#include <unistd.h>
#include <errno.h>
int main(void) {
    if (access("/dev/sysgenid", F_OK) != 0 && errno != ENOENT) return 2;
    if (write(1, "hello-out\r\npartial\n", 19) != 19) return 3;
    if (write(2, "hello-err\rtail", 14) != 14) return 4;
    return 0;
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-static", "-O2", "-o"])
            .arg(context.join("probe"))
            .arg(c)
            .status()
            .unwrap()
            .success()
    );
    fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY probe /bin/sh\nRUN ignored\n",
    )
    .unwrap();
    for mode in ["auto", "plain", "quiet"] {
        let out = tmp.path().join(format!("{mode}.out"));
        let err = tmp.path().join(format!("{mode}.err"));
        let mut child = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .args(["build", "--no-cache", "--progress", mode, "--output"])
            .arg(tmp.path().join(format!("image-{mode}")))
            .arg("--work-dir")
            .arg(tmp.path().join(format!("work-{mode}")))
            .arg(&context)
            .stdout(fs::File::create(&out).unwrap())
            .stderr(fs::File::create(&err).unwrap())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if start.elapsed() > Duration::from_secs(15) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("RUN output forwarding hung");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = fs::read_to_string(out).unwrap();
        let stderr = fs::read_to_string(err).unwrap();
        assert!(status.success(), "{stderr}");
        assert!(stdout.contains("hello-out") && stderr.contains("hello-err"));
        assert_eq!(
            stdout.contains("[stage 1 instruction 3 RUN stdout] hello-out"),
            mode != "quiet"
        );
        assert_eq!(
            stderr.contains("[stage 1 instruction 3 RUN stderr] hello-err"),
            mode != "quiet"
        );
        if mode == "quiet" {
            assert!(stdout.starts_with("hello-out\r\npartial\n"));
            // The existing trusted-RUN diagnostic remains visible in quiet mode.
            assert!(stderr.ends_with("hello-err\rtail"));
            assert!(!stderr.contains("[weld]"));
        } else {
            assert!(!stdout.contains('\r') && !stderr.contains('\r'));
            assert!(stdout.contains("[stage 1 instruction 3 RUN stdout] partial\n"));
            assert!(stderr.contains("[stage 1 instruction 3 RUN stderr] tail\n"));
        }
    }
}

#[test]
fn hidden_worker_rejects_invalid_input_before_starting_work() {
    for arguments in [
        vec!["__trace-worker"],
        vec![
            "__trace-worker",
            "/nonexistent/weld-root",
            "/nonexistent/weld-state",
            "0",
            "exit 0",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("rpweld: runner error:"));
    }
}
