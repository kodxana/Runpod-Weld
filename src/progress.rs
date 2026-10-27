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
pub use linux::{Output, OutputScope, OutputWriter};

/// Report through the current pinned sinks, when a CLI/build scope is active.
pub fn diagnostic(args: std::fmt::Arguments<'_>) {
    #[cfg(target_os = "linux")]
    if let Some(output) = Output::current() {
        output.diagnostic(args);
        return;
    }
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{args}");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        cell::RefCell,
        fs::{File, OpenOptions},
        io::{self, Write},
        os::{
            fd::{AsFd, AsRawFd, BorrowedFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    struct Sink {
        file: File,
        blocked: AtomicBool,
    }

    /// Pinned actual stdout/stderr objects, shared by CLI reporting and the build.
    /// Replacing fd 1/2 does not redirect these handles. The cooperative process
    /// contract excludes replacing our private descriptors or changing shared flags.
    /// This is not an OS immutability or hostile-workload boundary.
    #[derive(Clone)]
    pub struct Output(Arc<[Sink; 2]>);

    thread_local! {
        static OUTPUT: RefCell<Option<Output>> = const { RefCell::new(None) };
    }

    /// Thread-local reporting scope; keep alive through final/failure reporting.
    pub struct OutputScope {
        previous: Option<Output>,
        _thread: std::marker::PhantomData<std::rc::Rc<()>>,
    }

    impl Drop for OutputScope {
        fn drop(&mut self) {
            OUTPUT.with(|output| *output.borrow_mut() = self.previous.take());
        }
    }

    impl Output {
        pub fn capture() -> io::Result<Self> {
            Self::from_fds(io::stdout().as_fd(), io::stderr().as_fd())
        }

        fn from_fds(stdout: BorrowedFd<'_>, stderr: BorrowedFd<'_>) -> io::Result<Self> {
            let sink = |fd: BorrowedFd<'_>| -> io::Result<Sink> {
                Ok(Sink {
                    file: File::from(fd.try_clone_to_owned()?),
                    blocked: AtomicBool::new(false),
                })
            };
            Ok(Self(Arc::new([sink(stdout)?, sink(stderr)?])))
        }

        pub fn enter(&self) -> OutputScope {
            OutputScope {
                previous: OUTPUT.with(|output| output.replace(Some(self.clone()))),
                _thread: std::marker::PhantomData,
            }
        }

        pub(crate) fn current() -> Option<Self> {
            OUTPUT.with(|output| output.borrow().clone())
        }

        pub(crate) fn current_or_capture() -> io::Result<Self> {
            Self::current().map_or_else(Self::capture, Ok)
        }

        pub fn stdout(&self) -> OutputWriter {
            self.writer(0)
        }

        fn writer(&self, index: usize) -> OutputWriter {
            OutputWriter {
                output: self.clone(),
                index,
            }
        }

        pub fn diagnostic(&self, args: std::fmt::Arguments<'_>) {
            let _ = writeln!(self.writer(1), "{args}");
        }

        pub(crate) fn check(&self) -> io::Result<()> {
            self.writer(0).check()?;
            self.writer(1).check()
        }

        /// Call only with quiescent RUN/forwarding writers, before admission.
        /// An alias poisons the sink before returning, including on error unwind.
        pub(crate) fn check_payload(&self, file: &File) -> io::Result<()> {
            let result = (|| {
                let payload = file.metadata()?;
                for sink in self.0.iter() {
                    let actual = sink.file.metadata()?;
                    if (payload.dev(), payload.ino()) == (actual.dev(), actual.ino()) {
                        sink.blocked.store(true, Ordering::Release);
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                for sink in self.0.iter() {
                    sink.blocked.store(true, Ordering::Release);
                }
                return Err(error);
            }
            self.check()
        }

        pub(crate) fn inherited(&self) -> io::Result<(std::process::Stdio, std::process::Stdio)> {
            self.check()?;
            Ok((
                self.0[0].file.try_clone()?.into(),
                self.0[1].file.try_clone()?.into(),
            ))
        }

        pub(crate) fn forwarding(
            &self,
            stop: Arc<AtomicBool>,
        ) -> io::Result<(RunOutput, RunOutput)> {
            self.check()?;
            let mut out = RunOutput::new(self.0[0].file.as_fd(), stop.clone())?;
            let mut err = RunOutput::new(self.0[1].file.as_fd(), stop)?;
            out.protected = Some(self.writer(0));
            err.protected = Some(self.writer(1));
            Ok((out, err))
        }
    }

    /// Concrete writer to the pinned stdout, with sticky alias rejection.
    pub struct OutputWriter {
        output: Output,
        index: usize,
    }

    impl OutputWriter {
        fn check(&self) -> io::Result<()> {
            if self.output.0[self.index].blocked.load(Ordering::Acquire) {
                Err(io::Error::other(
                    "managed output sink aliases a protected payload; output disabled",
                ))
            } else {
                Ok(())
            }
        }
    }

    impl Write for OutputWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.check()?;
            (&self.output.0[self.index].file).write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.check()?;
            (&self.output.0[self.index].file).flush()
        }
    }

    /// Interruptible pipe/socket writes without holding Rust's global stdio locks.
    pub(crate) struct RunOutput {
        file: File,
        socket: bool,
        stop: Arc<AtomicBool>,
        protected: Option<OutputWriter>,
    }

    impl RunOutput {
        pub(crate) fn new(fd: BorrowedFd<'_>, stop: Arc<AtomicBool>) -> io::Result<Self> {
            let owned = fd.try_clone_to_owned()?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(owned.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let kind = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
            let mut pty_number = 0u32;
            let pty_master = kind == libc::S_IFCHR
                && unsafe { libc::ioctl(owned.as_raw_fd(), libc::TIOCGPTN, &mut pty_number) } == 0;
            let file = if pty_master {
                // Reopening a master allocates another PTY with identical device metadata.
                let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
                if flags < 0 {
                    return Err(io::Error::last_os_error());
                }
                if flags & libc::O_NONBLOCK == 0 {
                    // shortcut: blocking masters need quiet until forwarding can be isolated.
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "RUN progress cannot safely forward to a blocking PTY master; use --progress quiet or have the caller supply a nonblocking PTY master",
                    ));
                }
                // The caller must keep this shared description nonblocking during RUN.
                File::from(owned)
            } else if matches!(kind, libc::S_IFIFO | libc::S_IFCHR) {
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
                protected: None,
            })
        }
    }

    impl Write for RunOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            loop {
                if let Some(sink) = &self.protected {
                    sink.check()?;
                }
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{managed_control::ManagedControl, progress::Phase};
        use std::io::{Read, Seek, SeekFrom};

        fn contents(file: &File) -> Vec<u8> {
            let mut file = file.try_clone().unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            bytes
        }

        #[test]
        fn aliases_disable_phase_forwarding_quiet_and_final_writes_before_error() {
            for index in 0..2 {
                for unlinked in [false, true] {
                    let payload = tempfile::NamedTempFile::new().unwrap();
                    std::fs::write(payload.path(), b"archived payload").unwrap();
                    let read = File::open(payload.path()).unwrap();
                    let writable = OpenOptions::new()
                        .append(true)
                        .open(payload.path())
                        .unwrap();
                    let other = tempfile::tempfile().unwrap();
                    let output = if index == 0 {
                        Output::from_fds(writable.as_fd(), other.as_fd()).unwrap()
                    } else {
                        Output::from_fds(other.as_fd(), writable.as_fd()).unwrap()
                    };
                    if unlinked {
                        std::fs::remove_file(payload.path()).unwrap();
                    }
                    let scope = output.enter();
                    let cancelled = AtomicBool::new(false);
                    let control = ManagedControl::for_test(&cancelled).unwrap();
                    let (mut stdout, mut stderr) =
                        output.forwarding(Arc::new(AtomicBool::new(false))).unwrap();
                    // Existing phases retain their protected output across scope unwind.
                    let mut pending = Phase::start(false, "pending");
                    pending.enabled = true;
                    let error = control
                        .check_payload(&read.try_clone().unwrap())
                        .unwrap_err();
                    assert!(error.to_string().contains("output disabled"));
                    let mut phase = Phase::start(true, "start");
                    phase.started -= std::time::Duration::from_secs(11);
                    phase.tick();
                    phase.finish();
                    Phase::start(true, "drop");
                    crate::progress::diagnostic(format_args!("Secret RUN diagnostic"));
                    output.diagnostic(format_args!("rpweld: {error}"));
                    let writes = [
                        stdout.write_all(b"RUN stdout"),
                        stderr.write_all(b"RUN stderr"),
                    ];
                    assert!(writes[index].is_err());
                    assert!(
                        output.inherited().is_err(),
                        "quiet worker must refuse poisoned output"
                    );
                    if index == 0 {
                        assert!(writeln!(output.stdout(), "final result").is_err());
                    }
                    drop(scope);
                    drop(pending);
                    assert_eq!(
                        contents(&read),
                        b"archived payload",
                        "index={index}, unlinked={unlinked}"
                    );
                    assert!(
                        !control.cancelled(),
                        "alias state is not the atomic cancellation token"
                    );
                    cancelled.store(true, Ordering::Relaxed);
                    assert!(control.cancelled());
                }
            }
        }

        #[test]
        fn pinned_objects_survive_caller_sink_replacement_and_are_cloexec() {
            let original = tempfile::tempfile().unwrap();
            let replacement = tempfile::tempfile().unwrap();
            let caller = original.try_clone().unwrap();
            let output = Output::from_fds(caller.as_fd(), caller.as_fd()).unwrap();
            for sink in output.0.iter() {
                assert_ne!(
                    unsafe { libc::fcntl(sink.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                    0
                );
            }
            assert_eq!(
                unsafe { libc::dup2(replacement.as_raw_fd(), caller.as_raw_fd()) },
                caller.as_raw_fd()
            );
            output.check_payload(&replacement).unwrap();
            writeln!(output.stdout(), "pinned").unwrap();
            assert_eq!(contents(&original), b"pinned\n");
            assert!(contents(&replacement).is_empty());
            assert!(output.check_payload(&original).is_err());
            output.diagnostic(format_args!("alias error"));
            assert!(output.stdout().write_all(b"final").is_err());
            assert_eq!(contents(&original), b"pinned\n");
        }

        #[test]
        fn mount_cleanup_drop_respects_the_poisoned_diagnostic_sink() {
            use crate::run_mounts::{self, MountGuard};
            for blocked in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("root");
                let state = temp.path().join("state");
                std::fs::create_dir(&root).unwrap();
                std::fs::create_dir(&state).unwrap();
                let secret = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
                let mut options = run_mounts::Options::default();
                options
                    .secrets
                    .insert("token".into(), secret.path().to_owned());
                let (mounts, _) = run_mounts::parse("--mount=type=secret,id=token true").unwrap();
                let guard =
                    MountGuard::prepare(&root, &state, &mounts, &options, None, &|| false).unwrap();
                // Force the no-replace cleanup rename to fail, exercising actual Drop.
                std::fs::write(state.join("mount-discard-0"), b"collision").unwrap();
                let sink = tempfile::tempfile().unwrap();
                let output = Output::from_fds(sink.as_fd(), sink.as_fd()).unwrap();
                let _scope = output.enter();
                if blocked {
                    assert!(output.check_payload(&sink).is_err());
                }
                drop(guard);
                assert!(root.join("run/secrets/token").exists());
                let bytes = contents(&sink);
                if blocked {
                    assert!(bytes.is_empty());
                } else {
                    assert!(
                        String::from_utf8(bytes)
                            .unwrap()
                            .contains("RUN mount restoration failed")
                    );
                }
            }
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
    #[cfg(target_os = "linux")]
    output: Option<Output>,
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
            #[cfg(target_os = "linux")]
            output: Output::current(),
        };
        if enabled {
            phase.report(format_args!("[weld] {}: START", phase.label));
        }
        phase
    }

    pub fn tick(&self) {
        if self.enabled && self.is_current() && update_due(&self.last, self.started.elapsed()) {
            self.report(format_args!(
                "[weld] {}: {} ({:.0}s elapsed)",
                self.label,
                if self.detail.borrow().is_empty() {
                    "in progress".to_owned()
                } else {
                    self.detail.borrow().clone()
                },
                self.started.elapsed().as_secs_f64()
            ));
        }
    }

    fn is_current(&self) -> bool {
        ACTIVE.with(|active| active.borrow().last() == Some(&self.id))
    }

    fn report(&self, args: std::fmt::Arguments<'_>) {
        #[cfg(target_os = "linux")]
        if let Some(output) = &self.output {
            output.diagnostic(args);
            return;
        }
        diagnostic(args);
    }

    pub fn detail(&self, detail: String) {
        *self.detail.borrow_mut() = detail;
        self.tick();
    }

    pub fn finish(mut self) {
        self.finished = true;
        if self.enabled {
            self.report(format_args!(
                "[weld] {}: DONE {:.3}s {}",
                self.label,
                self.started.elapsed().as_secs_f64(),
                self.detail.borrow()
            ));
        }
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        if self.enabled {
            ACTIVE.with(|active| active.borrow_mut().retain(|id| *id != self.id));
        }
        if self.enabled && !self.finished {
            self.report(format_args!(
                "[weld] {}: FAILED/INTERRUPTED {:.3}s",
                self.label,
                self.started.elapsed().as_secs_f64()
            ));
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
    fn stream_forwarding_keeps_flags_and_all_bytes_until_cancelled() {
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
        fn pty() -> (File, File) {
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
            unsafe { (File::from_raw_fd(slave), File::from_raw_fd(master)) }
        }
        for (destination, cancel) in ["pipe", "socket", "pty-master", "pty-slave"]
            .into_iter()
            .flat_map(|destination| [false, true].map(|cancel| (destination, cancel)))
        {
            let (mut reader, writer) = if destination == "socket" {
                let (reader, writer) = UnixStream::pair().unwrap();
                unsafe {
                    (
                        File::from_raw_fd(reader.into_raw_fd()),
                        File::from_raw_fd(writer.into_raw_fd()),
                    )
                }
            } else if destination == "pipe" {
                pipe()
            } else {
                let (slave, master) = pty();
                if destination == "pty-master" {
                    (slave, master)
                } else {
                    (master, slave)
                }
            };
            if destination == "pty-master" {
                let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
                assert_eq!(
                    unsafe {
                        libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    },
                    0
                );
            }
            let original_flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
            let stop = Arc::new(AtomicBool::new(false));
            let mut output = RunOutput::new(writer.as_fd(), stop.clone()).unwrap();
            assert_eq!(
                unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
                original_flags
            );
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
                let mut bytes = vec![0; 1024 * 1024];
                reader.read_exact(&mut bytes).unwrap();
                forwarder.join().unwrap().unwrap();
                assert_eq!(bytes, vec![b'x'; 1024 * 1024]);
            }
            assert_eq!(
                unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
                original_flags,
                "{destination}: caller flags changed during forwarding"
            );
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
