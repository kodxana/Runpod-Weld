use std::process::Command;

#[cfg(target_os = "linux")]
fn raw_pty() -> (std::fs::File, std::fs::File) {
    use std::os::fd::FromRawFd;
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut termios = std::mem::MaybeUninit::uninit();
    assert_eq!(unsafe { libc::tcgetattr(slave, termios.as_mut_ptr()) }, 0);
    let mut termios = unsafe { termios.assume_init() };
    unsafe { libc::cfmakeraw(&mut termios) };
    assert_eq!(
        unsafe { libc::tcsetattr(slave, libc::TCSANOW, &termios) },
        0
    );
    for fd in [master, slave] {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root, cc -static and child ptrace"]
fn blocked_run_stdout_is_cancelled_and_reaped_without_closing_the_consumer() {
    use std::{
        fs,
        io::Read,
        os::fd::{AsRawFd, OwnedFd},
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
static void output_gate(int argc, char **argv) {
    if (argc > 2 && strstr(argv[2], "managed") != NULL)
        while (access("/output-ready", F_OK) != 0) usleep(1000);
}
int main(int argc, char **argv) {
    int fd = open("/pids", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0 || dprintf(fd, "%d\n", getpid()) < 0) return 2;
    char block[8192]; memset(block, 'x', sizeof block);
    if (argc > 2 && strstr(argv[2], "complete") != NULL) {
        close(fd);
        output_gate(argc, argv);
        return write(1, block, sizeof block) == sizeof block ? 0 : 3;
    }
    pid_t child = fork();
    if (child < 0) return 4;
    if (child == 0) {
        if (setsid() < 0 || dprintf(fd, "%d\n", getpid()) < 0) return 5;
    }
    close(fd);
    output_gate(argc, argv);
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
    for (((mode, cancel, command), pty), managed) in [
        ("plain", false, "flood"),
        ("plain", true, "flood"),
        ("plain", false, "complete"),
        ("quiet", false, "flood"),
        ("quiet", true, "flood"),
    ]
    .into_iter()
    .flat_map(|case| [false, true].map(|pty| (case, pty)))
    .filter(|((_, _, command), pty)| !pty || *command != "complete")
    .flat_map(|case| [false, true].map(|managed| (case, managed)))
    {
        fs::write(
            context.join("Dockerfile"),
            format!(
                "FROM scratch\nCOPY probe /bin/sh\nRUN {command}{}\n",
                if managed { " managed" } else { "" }
            ),
        )
        .unwrap();
        let run = tempfile::tempdir_in(tmp.path()).unwrap();
        let work = run.path().join("work");
        let error = run.path().join("stderr");
        let (writer, reader) = if pty {
            let (writer, reader) = raw_pty();
            if mode != "quiet" {
                let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
                assert_eq!(
                    unsafe {
                        libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    },
                    0
                );
            }
            (Some(writer), Some(reader))
        } else {
            (None, None)
        };
        let original_flags = writer
            .as_ref()
            .map(|fd| unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) });
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        cmd.env("RPWELD_HOME", run.path().join("store"));
        cmd.arg("build");
        if managed {
            cmd.args(["-t", "test/managed-output"]);
        }
        let mut child = cmd
            .args([
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
            .stdout(
                writer
                    .as_ref()
                    .map_or_else(Stdio::piped, |fd| Stdio::from(fd.try_clone().unwrap())),
            )
            .stderr(fs::File::create(&error).unwrap())
            .spawn()
            .unwrap();
        // Keep the original peer open and undrained throughout cancellation/reaping.
        let consumer =
            reader.unwrap_or_else(|| fs::File::from(OwnedFd::from(child.stdout.take().unwrap())));
        if !pty {
            assert!(unsafe { libc::fcntl(consumer.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) } >= 4096);
        }
        let start = Instant::now();
        let mut signalled = false;
        let mut saw_full_pipe = false;
        let mut saw_exited_command = false;
        let mut output_released = !managed;
        let status = loop {
            let mut available = 0;
            assert_eq!(
                unsafe { libc::ioctl(consumer.as_raw_fd(), libc::FIONREAD, &mut available) },
                0
            );
            saw_full_pipe |= output_released && available >= if pty { 4095 } else { 4096 };
            let pids: Vec<i32> = fs::read_to_string(work.join("rootfs/pids"))
                .unwrap_or_default()
                .lines()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !output_released && pids.len() == if command == "complete" { 1 } else { 2 } {
                // Drain only the managed CLI preamble before the probe may write.
                // Partial records can block a pipe with less than PIPE_BUF free;
                // after this gate the consumer stays open and entirely undrained.
                (&consumer)
                    .read_exact(&mut vec![0; available as usize])
                    .unwrap();
                fs::write(work.join("rootfs/output-ready"), b"").unwrap();
                output_released = true;
            }
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
                    "{mode} pty={pty} cancel={cancel} command={command}: undrained stdout prevented shutdown: {}",
                    fs::read_to_string(&error).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            saw_full_pipe && !status.success(),
            "{mode} managed={managed} pty={pty} {command}: {status}; {}",
            fs::read_to_string(&error).unwrap()
        );
        assert_eq!(
            writer
                .as_ref()
                .map(|fd| unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) }),
            original_flags
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
        io::{ErrorKind, Read},
        os::fd::AsRawFd,
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
#include <fcntl.h>
int main(void) {
    int fd = creat("/executed", 0600);
    if (fd < 0) return 5;
    close(fd);
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
    for ((mode, destination), managed) in ["auto", "plain", "quiet"]
        .into_iter()
        .flat_map(|mode| {
            ["file", "master-nonblocking", "master-blocking", "slave"]
                .map(|destination| (mode, destination))
        })
        .flat_map(|case| [false, true].map(|managed| (case, managed)))
    {
        let run = tempfile::tempdir_in(tmp.path()).unwrap();
        let out = run.path().join("stdout");
        let err = run.path().join("stderr");
        let work = run.path().join("work");
        let image = run.path().join("image");
        let (writer, mut peer) = if destination == "file" {
            (fs::File::create(&out).unwrap(), None)
        } else {
            let (master, slave) = raw_pty();
            let (writer, reader) = if destination == "slave" {
                (slave, master)
            } else {
                (master, slave)
            };
            // Only the test's caller sets flags; the builder must preserve them.
            let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
            if destination == "master-nonblocking" {
                assert_eq!(
                    unsafe {
                        libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    },
                    0
                );
            }
            let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(
                unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
            (writer, Some(reader))
        };
        let original_flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        cmd.env("RPWELD_HOME", run.path().join("store"));
        cmd.arg("build");
        if managed {
            cmd.args(["-t", "test/managed-output"]);
        }
        let mut child = cmd
            .args(["--no-cache", "--progress", mode, "--output"])
            .arg(&image)
            .arg("--work-dir")
            .arg(&work)
            .arg(&context)
            .stdout(writer.try_clone().unwrap())
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
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
            original_flags
        );
        // Reading the original peer proves terminal identity; cloned /dev/ptmx
        // masters have identical device metadata but route bytes elsewhere.
        let stdout = if let Some(peer) = &mut peer {
            let mut bytes = Vec::new();
            let error = peer.read_to_end(&mut bytes).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::WouldBlock);
            String::from_utf8(bytes).unwrap()
        } else {
            fs::read_to_string(out).unwrap()
        };
        let stderr = fs::read_to_string(err).unwrap();
        if destination == "master-blocking" && mode != "quiet" {
            assert!(
                !status.success(),
                "{mode}: blocking master must fail before RUN"
            );
            assert!(
                stderr.contains("PTY master") && stderr.contains("--progress quiet"),
                "{stderr}"
            );
            assert!(!work.join("rootfs/executed").exists());
            assert!(!image.join("index.json").exists());
            continue;
        }
        assert!(status.success(), "{mode} {destination}: {stderr}");
        assert!(
            stdout.contains("hello-out") && stderr.contains("hello-err"),
            "{mode} {destination}: original destination lost RUN bytes: {stdout:?}"
        );
        assert!(work.join("rootfs/executed").exists());
        assert_eq!(
            stdout.contains("[stage 1 instruction 3 RUN stdout] hello-out"),
            mode != "quiet"
        );
        assert_eq!(
            stderr.contains("[stage 1 instruction 3 RUN stderr] hello-err"),
            mode != "quiet"
        );
        if mode == "quiet" {
            if managed {
                assert!(stdout.contains("hello-out\r\npartial\n"));
            } else {
                assert!(stdout.starts_with("hello-out\r\npartial\n"));
            }
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
