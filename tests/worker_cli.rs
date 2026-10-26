use std::process::Command;

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root, cc -static and child ptrace"]
fn blocked_run_stdout_is_cancelled_and_reaped_without_closing_the_consumer() {
    use std::{
        fs,
        os::fd::AsRawFd,
        process::Stdio,
        time::{Duration, Instant},
    };
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let tmp = tempfile::tempdir().unwrap();
    let context = tmp.path().join("context");
    fs::create_dir(&context).unwrap();
    let c = tmp.path().join("flood.c");
    fs::write(
        &c,
        r#"#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    int fd = open("/pids", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0 || dprintf(fd, "%d\n", getpid()) < 0) return 2;
    char block[8192]; memset(block, 'x', sizeof block);
    if (argc > 2 && strstr(argv[2], "complete") != NULL) {
        close(fd);
        return write(1, block, sizeof block) == sizeof block ? 0 : 3;
    }
    pid_t child = fork();
    if (child < 0) return 4;
    if (child == 0) {
        if (setsid() < 0 || dprintf(fd, "%d\n", getpid()) < 0) return 5;
    }
    close(fd);
    for (;;) if (write(1, block, sizeof block) < 0) return 6;
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
    for (mode, cancel, command) in [
        ("plain", false, "flood"),
        ("plain", true, "flood"),
        ("plain", false, "complete"),
        ("quiet", false, "flood"),
        ("quiet", true, "flood"),
    ] {
        fs::write(
            context.join("Dockerfile"),
            format!("FROM scratch\nCOPY probe /bin/sh\nRUN {command}\n"),
        )
        .unwrap();
        let run = tempfile::tempdir_in(tmp.path()).unwrap();
        let work = run.path().join("work");
        let error = run.path().join("stderr");
        let mut child = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .args([
                "build",
                "--no-cache",
                "--progress",
                mode,
                "--run-timeout-seconds",
                if cancel { "60" } else { "1" },
                "--output",
            ])
            .arg(run.path().join("image"))
            .arg("--work-dir")
            .arg(&work)
            .arg(&context)
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&error).unwrap())
            .spawn()
            .unwrap();
        // Keep the read end open, deliberately do not drain it, and force backpressure.
        let consumer = child.stdout.take().unwrap();
        assert!(unsafe { libc::fcntl(consumer.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) } >= 4096);
        let start = Instant::now();
        let mut signalled = false;
        let mut saw_full_pipe = false;
        let mut saw_exited_command = false;
        let status = loop {
            let mut available = 0;
            assert_eq!(
                unsafe { libc::ioctl(consumer.as_raw_fd(), libc::FIONREAD, &mut available) },
                0
            );
            saw_full_pipe |= available >= 4096;
            let pids: Vec<i32> = fs::read_to_string(work.join("rootfs/pids"))
                .unwrap_or_default()
                .lines()
                .filter_map(|s| s.parse().ok())
                .collect();
            if command == "complete" && saw_full_pipe && pids.len() == 1 {
                saw_exited_command |= unsafe { libc::kill(pids[0], 0) } == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            }
            if cancel && saw_full_pipe && pids.len() == 2 && !signalled {
                assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
                signalled = true;
            }
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > Duration::from_secs(12) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "{mode} cancel={cancel} command={command}: undrained stdout prevented shutdown: {}",
                    fs::read_to_string(&error).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            saw_full_pipe && !status.success(),
            "{mode} {command}: {status}"
        );
        assert_eq!(signalled, cancel);
        if command == "complete" {
            assert!(
                saw_exited_command,
                "command must exit before its blocked output drains"
            );
        }
        let pids: Vec<i32> = fs::read_to_string(work.join("rootfs/pids"))
            .unwrap()
            .lines()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(pids.len(), if command == "complete" { 1 } else { 2 });
        for pid in pids {
            assert_eq!(
                unsafe { libc::kill(pid, 0) },
                -1,
                "descendant {pid} survived {mode} cancellation/timeout"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
        assert!(!run.path().join("image/index.json").exists());
        drop(consumer);
    }
}

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
