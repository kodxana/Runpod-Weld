//! Bounded phase reporting from existing cooperative work/cancellation checks.
use std::{
    cell::{Cell, RefCell},
    time::{Duration, Instant},
};

const INTERVAL: Duration = Duration::from_secs(10);

/// Bounded line framing for subprocess output, including CR progress redraws.
/// Preserve payload bytes; quiet mode bypasses this formatter entirely.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn forward_output(
    mut input: impl std::io::Read,
    mut output: impl std::io::Write,
    label: &str,
) -> std::io::Result<()> {
    let mut chunk = [0u8; 8192];
    let mut line = Vec::with_capacity(8192);
    let mut after_cr = false;
    let emit = |line: &mut Vec<u8>, output: &mut dyn std::io::Write| -> std::io::Result<()> {
        let mut record = format!("[{label}] ").into_bytes();
        record.extend_from_slice(line);
        record.push(b'\n');
        output.write_all(&record)?;
        output.flush()?;
        line.clear();
        Ok(())
    };
    loop {
        let n = match input.read(&mut chunk) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if n == 0 {
            break;
        }
        for &b in &chunk[..n] {
            if b == b'\n' && after_cr {
                after_cr = false;
                continue;
            }
            after_cr = b == b'\r';
            if b == b'\r' || b == b'\n' {
                emit(&mut line, &mut output)?;
            } else {
                line.push(b);
                if line.len() == 8192 {
                    emit(&mut line, &mut output)?;
                }
            }
        }
    }
    if !line.is_empty() {
        emit(&mut line, &mut output)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) use linux::RunOutput;

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs::{File, OpenOptions},
        io::{self, Write},
        os::{
            fd::{AsRawFd, BorrowedFd},
            unix::fs::OpenOptionsExt,
        },
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    /// Interruptible pipe/socket writes without holding Rust's global stdio locks.
    pub(crate) struct RunOutput {
        file: File,
        socket: bool,
        stop: Arc<AtomicBool>,
    }

    impl RunOutput {
        pub(crate) fn new(fd: BorrowedFd<'_>, stop: Arc<AtomicBool>) -> io::Result<Self> {
            let owned = fd.try_clone_to_owned()?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(owned.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let kind = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
            let file = if matches!(kind, libc::S_IFIFO | libc::S_IFCHR) {
                // dup shares file-status flags with the caller; reopen instead of
                // changing O_NONBLOCK on an inherited pipe/terminal description.
                OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
                    .open(format!("/proc/self/fd/{}", owned.as_raw_fd()))?
            } else {
                File::from(owned) // Preserve a regular file's offset and append mode.
            };
            Ok(Self {
                file,
                socket: kind == libc::S_IFSOCK,
                stop,
            })
        }
    }

    impl Write for RunOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            loop {
                let n = unsafe {
                    if self.socket {
                        libc::send(
                            self.file.as_raw_fd(),
                            bytes.as_ptr().cast(),
                            bytes.len(),
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    } else {
                        libc::write(self.file.as_raw_fd(), bytes.as_ptr().cast(), bytes.len())
                    }
                };
                if n >= 0 {
                    return Ok(n as usize);
                }
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != io::ErrorKind::WouldBlock {
                    return Err(error);
                }
                if self.stop.load(Ordering::Acquire) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "RUN output consumer did not drain before cancellation/timeout",
                    ));
                }
                let mut fd = libc::pollfd {
                    fd: self.file.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut fd, 1, 25) } < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

thread_local! {
    static ACTIVE: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static NEXT_ID: Cell<u64> = const { Cell::new(0) };
}

/// Count progress only: layer sizes and processing times are not uniform.
pub fn count_bar(done: usize, total: usize) -> String {
    let done = done.min(total);
    let filled = if total == 0 {
        0
    } else {
        ((done as u128 * 20) / total as u128) as usize
    };
    format!(
        "[{}{}] {done}/{total} layers complete",
        "#".repeat(filled),
        "-".repeat(20 - filled)
    )
}

pub struct Phase {
    enabled: bool,
    label: String,
    started: Instant,
    last: Cell<Duration>,
    finished: bool,
    detail: RefCell<String>,
    id: u64,
}

impl Phase {
    /// Labels are operation names, never Dockerfile arguments or credentials.
    pub fn start(enabled: bool, label: impl Into<String>) -> Self {
        let id = NEXT_ID.with(|next| {
            let id = next.get();
            next.set(id.wrapping_add(1));
            id
        });
        if enabled {
            ACTIVE.with(|active| active.borrow_mut().push(id));
        }
        let phase = Self {
            enabled,
            label: label.into(),
            started: Instant::now(),
            last: Cell::new(Duration::ZERO),
            finished: false,
            detail: RefCell::new(String::new()),
            id,
        };
        if enabled {
            eprintln!("[weld] {}: START", phase.label);
        }
        phase
    }

    pub fn tick(&self) {
        if self.enabled && self.is_current() && update_due(&self.last, self.started.elapsed()) {
            eprintln!(
                "[weld] {}: {} ({:.0}s elapsed)",
                self.label,
                if self.detail.borrow().is_empty() {
                    "in progress".to_owned()
                } else {
                    self.detail.borrow().clone()
                },
                self.started.elapsed().as_secs_f64()
            );
        }
    }

    fn is_current(&self) -> bool {
        ACTIVE.with(|active| active.borrow().last() == Some(&self.id))
    }

    pub fn detail(&self, detail: String) {
        *self.detail.borrow_mut() = detail;
        self.tick();
    }

    pub fn finish(mut self) {
        self.finished = true;
        if self.enabled {
            eprintln!(
                "[weld] {}: DONE {:.3}s {}",
                self.label,
                self.started.elapsed().as_secs_f64(),
                self.detail.borrow()
            );
        }
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        if self.enabled {
            ACTIVE.with(|active| active.borrow_mut().retain(|id| *id != self.id));
        }
        if self.enabled && !self.finished {
            eprintln!(
                "[weld] {}: FAILED/INTERRUPTED {:.3}s",
                self.label,
                self.started.elapsed().as_secs_f64()
            );
        }
    }
}

fn update_due(last: &Cell<Duration>, elapsed: Duration) -> bool {
    if elapsed.saturating_sub(last.get()) < INTERVAL {
        return false;
    }
    last.set(elapsed);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn pipe_and_socket_forwarding_keep_flags_and_all_bytes_until_cancelled() {
        use std::{
            fs::File,
            io::{Read, Write},
            os::{
                fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd},
                unix::net::UnixStream,
            },
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
        };
        fn pipe() -> (File, File) {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
        }
        for (socket, cancel) in [(false, false), (false, true), (true, false), (true, true)] {
            let (mut reader, writer) = if socket {
                let (reader, writer) = UnixStream::pair().unwrap();
                unsafe {
                    (
                        File::from_raw_fd(reader.into_raw_fd()),
                        File::from_raw_fd(writer.into_raw_fd()),
                    )
                }
            } else {
                pipe()
            };
            let original_flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
            let stop = Arc::new(AtomicBool::new(false));
            let mut output = RunOutput::new(writer.as_fd(), stop.clone()).unwrap();
            assert_eq!(
                unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
                original_flags
            );
            drop(writer);
            let forwarder = std::thread::spawn(move || output.write_all(&vec![b'x'; 1024 * 1024]));
            let start = Instant::now();
            loop {
                let mut available = 0;
                assert_eq!(
                    unsafe { libc::ioctl(reader.as_raw_fd(), libc::FIONREAD, &mut available) },
                    0
                );
                if available > 0 {
                    break;
                }
                assert!(start.elapsed() < Duration::from_secs(3));
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(!forwarder.is_finished());
            if cancel {
                stop.store(true, Ordering::Release);
                let start = Instant::now();
                while !forwarder.is_finished() && start.elapsed() < Duration::from_secs(2) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert!(
                    forwarder.is_finished(),
                    "blocked writer ignored cancellation"
                );
                assert_eq!(
                    forwarder.join().unwrap().unwrap_err().kind(),
                    std::io::ErrorKind::TimedOut
                );
            } else {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                forwarder.join().unwrap().unwrap();
                assert_eq!(bytes, vec![b'x'; 1024 * 1024]);
            }
        }
    }

    #[test]
    fn output_framing_handles_split_crlf_interrupts_and_write_errors() {
        use std::io::{self, Read};
        struct InterruptedBytes<'a> {
            bytes: &'a [u8],
            interrupt: bool,
        }
        impl Read for InterruptedBytes<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.bytes.read(&mut out[..1])
            }
        }
        let mut output = Vec::new();
        forward_output(
            InterruptedBytes {
                bytes: b"a\r\nb\xff",
                interrupt: false,
            },
            &mut output,
            "run",
        )
        .unwrap();
        assert_eq!(output, b"[run] a\n[run] b\xff\n");
        let error = forward_output(&b"line\n"[..], &mut [0u8; 1][..], "run").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }
    #[test]
    fn child_output_frames_crlf_partial_and_long_records() {
        let mut output = Vec::new();
        forward_output(
            &b"one\r\ntwo\rthree\nlast"[..],
            &mut output,
            "stage 1 RUN stdout",
        )
        .unwrap();
        assert_eq!(output, b"[stage 1 RUN stdout] one\n[stage 1 RUN stdout] two\n[stage 1 RUN stdout] three\n[stage 1 RUN stdout] last\n");
        output.clear();
        forward_output(&vec![b'x'; 20000][..], &mut output, "run").unwrap();
        assert_eq!(
            output
                .split(|b| *b == b'\n')
                .filter(|s| !s.is_empty())
                .count(),
            3
        );
        assert_eq!(output.iter().filter(|b| **b == b'x').count(), 20000);
    }
    #[test]
    fn child_activity_suppresses_parent_heartbeat_and_restores_it() {
        let parent = Phase::start(true, "parent");
        {
            let child = Phase::start(true, "child");
            assert!(!parent.is_current());
            assert!(child.is_current());
            let hidden = Phase::start(false, "hidden");
            assert!(child.is_current());
            hidden.finish();
            child.finish();
        }
        assert!(parent.is_current());
        parent.finish();
    }
    #[test]
    fn count_bar_is_bounded_and_explicit_about_units() {
        assert_eq!(
            count_bar(1, 2),
            "[##########----------] 1/2 layers complete"
        );
        assert_eq!(
            count_bar(3, 2),
            "[####################] 2/2 layers complete"
        );
        assert_eq!(
            count_bar(0, 0),
            "[--------------------] 0/0 layers complete"
        );
    }
    #[test]
    fn updates_are_bounded_without_bursts_after_a_long_operation() {
        let last = Cell::new(Duration::ZERO);
        assert!(!update_due(&last, Duration::from_secs(9)));
        assert!(update_due(&last, Duration::from_secs(10)));
        assert!(!update_due(&last, Duration::from_secs(10)));
        assert!(update_due(&last, Duration::from_secs(75)));
        assert!(!update_due(&last, Duration::from_secs(76)));
        assert!(update_due(&last, Duration::from_secs(85)));
    }
}
