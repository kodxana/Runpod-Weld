//! Experimental trusted-image runner, Linux x86_64, root supervisor with real USER credentials.
//! Usage: trace_root ROOTFS STATE_DIR TIMEOUT_SECONDS SHELL_COMMAND
//! Real chroot and real credentials; apt's sandbox is not disabled. The tracer
//! restores PR_SET_DUMPABLE after credential changes/exec, changing introspection
//! permissions. PEEKDATA is used, never process_vm_readv or memory/code patches.
//! Absolute supported /dev paths and /proc descendants expose the OUTER Pod;
//! this is not PID/device isolation or a hostile-workload security boundary.
//! Engine-owned directory fds are retained across application close/CLOEXEC requests.
//! Relative paths stay native. Exact /dev and /proc are explicitly unsupported.
//! Only the pathname syscall families below are translated; other calls stay
//! native. clone3 uses ENOSYS fallback; group stops and CLONE_UNTRACED are
//! unsupported. Trusted stable paths only: mount aliases/renames are not isolated.
//! SIGINT/SIGTERM/SIGHUP cancel. Cleanup is bounded; uninterruptible kernel tasks
//! can outlive it (EXITKILL also applies when the tracer exits). Call only in a dedicated worker process, never the builder process.

use std::{ffi::OsString, path::PathBuf};

/// Input to one dedicated, single-threaded worker process. No host environment
/// is inherited by the image command. `env` is a complete OCI-style NAME=value list.
#[derive(Debug, Clone)]
pub struct WorkerOptions {
    pub rootfs: PathBuf,
    pub state_dir: PathBuf,
    pub timeout_seconds: u64,
    pub command: OsString,
    pub working_directory: String,
    pub env: Vec<String>,
    pub user: String,
}

impl WorkerOptions {
    /// Parse arguments after the example name or hidden worker subcommand.
    /// Options follow the four legacy positional arguments. Use --clear-env
    /// before --env entries when supplying the complete merged image environment.
    pub fn from_args(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut args = args.into_iter();
        let usage = "usage: trace_root ROOTFS STATE_DIR TIMEOUT_SECONDS SHELL_COMMAND [--user SPEC] [--workdir DIR] [--clear-env] [--env NAME=value]...";
        let rootfs = args.next().ok_or(usage)?.into();
        let state_dir = args.next().ok_or(usage)?.into();
        let timeout_seconds = args
            .next()
            .ok_or(usage)?
            .to_str()
            .and_then(|s| s.parse().ok())
            .ok_or("timeout must be 1..86400 seconds")?;
        let command = args.next().ok_or(usage)?;
        let mut options = Self {
            rootfs,
            state_dir,
            timeout_seconds,
            command,
            working_directory: "/".into(),
            user: String::new(),
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                "LC_ALL=C".into(),
            ],
        };
        let mut legacy_home = true;
        while let Some(flag) = args.next() {
            match flag.to_str() {
                Some("--clear-env") => {
                    options.env.clear();
                    legacy_home = false;
                }
                Some("--user") => {
                    options.user = args
                        .next()
                        .ok_or(usage)?
                        .into_string()
                        .map_err(|_| "USER must be UTF-8")?;
                    if options.user.is_empty() {
                        return Err("--user requires a nonempty specification".into());
                    }
                }
                Some("--workdir") => {
                    options.working_directory = args
                        .next()
                        .ok_or(usage)?
                        .into_string()
                        .map_err(|_| "workdir must be UTF-8")?
                }
                Some("--env") => options.env.push(
                    args.next()
                        .ok_or(usage)?
                        .into_string()
                        .map_err(|_| "environment must be UTF-8")?,
                ),
                _ => return Err(usage.into()),
            }
        }
        if legacy_home
            && options.user.is_empty()
            && !options.env.iter().any(|e| e.starts_with("HOME="))
        {
            options.env.push("HOME=/root".into());
        }
        options.validate()?;
        Ok(options)
    }

    /// Validate before any process-wide signal, subreaper or wait state changes.
    /// Directory existence is checked by chdir in the chrooted child.
    /// Symlinks and `..` therefore use kernel chroot resolution, never host paths.
    pub fn validate(&self) -> Result<(), String> {
        crate::user::validate_user_spec(&self.user)?;
        if !(1..=86400).contains(&self.timeout_seconds) {
            return Err("timeout must be 1..86400 seconds".into());
        }
        if !self.working_directory.starts_with('/') || self.working_directory.contains('\0') {
            return Err("workdir must be an absolute image path without NUL".into());
        }
        for entry in &self.env {
            let (name, _) = entry
                .split_once('=')
                .ok_or("environment entry must be NAME=value")?;
            if name.is_empty() || entry.contains('\0') {
                return Err(
                    "environment names must be nonempty; names and values must not contain NUL"
                        .into(),
                );
            }
        }
        Ok(())
    }

    // Last assignment wins, including builder updates appended to the base Env.
    #[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
    fn environment(&self) -> Vec<&str> {
        let mut values = std::collections::BTreeMap::new();
        for entry in &self.env {
            let (name, _) = entry.split_once('=').expect("validated environment");
            values.insert(name, entry.as_str());
        }
        values.into_values().collect()
    }
}

/// Entrypoint for a hidden subcommand in a freshly spawned executable.
/// MUST run before starting threads or unrelated children. This consumes the
/// process: it changes signal/subreaper state and uses waitpid(-1). The parent
/// builder must spawn its own executable, not call this in its build process.
/// Trusted workloads only; this is not a security sandbox.
pub fn worker_main(options: WorkerOptions) -> ! {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let result = linux::run(options);
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let result: Result<i32, String> = {
        let _ = options;
        Err("trace_root requires Linux x86_64".into())
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("rpweld: runner error: {error}");
            std::process::exit(1);
        }
    }
}

/// CLI adapter; pass arguments after the executable name / hidden subcommand.
pub fn worker_entry(args: impl IntoIterator<Item = OsString>) -> ! {
    match WorkerOptions::from_args(args) {
        Ok(options) => worker_main(options),
        Err(error) => {
            eprintln!("rpweld: runner error: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use libc::*;
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
        ffi::CString,
        fs::{self, File, OpenOptions},
        mem::zeroed,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
        ptr,
        rc::Rc,
        sync::atomic::{AtomicI32, Ordering},
        time::{Duration, Instant},
    };

    type Result<T> = std::result::Result<T, String>;
    const GET_SYSCALL_INFO: c_uint = 0x420e;
    static CANCEL: AtomicI32 = AtomicI32::new(0);
    extern "C" fn cancel(signal: i32) {
        CANCEL.store(signal, Ordering::Relaxed);
    }
    fn errno() -> i32 {
        unsafe { *__errno_location() }
    }
    fn trace(request: c_uint, pid: pid_t, address: usize, data: usize) -> Result<c_long> {
        unsafe {
            *__errno_location() = 0;
            let value = ptrace(request, pid, address as *mut c_void, data as *mut c_void);
            if value == -1 && errno() != 0 {
                let cause = errno();
                let error = format!(
                    "ptrace {request:#x} pid {pid}: {}",
                    std::io::Error::last_os_error()
                );
                // The supervisor distinguishes asynchronous death from a real
                // tracing failure; formatting must not overwrite that errno.
                *__errno_location() = cause;
                Err(error)
            } else {
                Ok(value)
            }
        }
    }
    fn registers(pid: pid_t) -> Result<user_regs_struct> {
        let mut regs = unsafe { zeroed() };
        trace(PTRACE_GETREGS, pid, 0, &mut regs as *mut _ as usize)?;
        Ok(regs)
    }
    fn set_registers(pid: pid_t, regs: &user_regs_struct) -> Result<()> {
        trace(PTRACE_SETREGS, pid, 0, regs as *const _ as usize).map(|_| ())
    }
    fn string(pid: pid_t, address: u64) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // Aligned reads never cross an unmapped page beyond a terminating NUL.
        for offset in 0..4096u64 {
            let p = address
                .checked_add(offset)
                .ok_or("pathname address overflow")?;
            if offset == 0 || p % 8 == 0 {
                let word = trace(PTRACE_PEEKDATA, pid, (p & !7) as usize, 0)?.to_ne_bytes();
                for &byte in &word[(p % 8) as usize..] {
                    if byte == 0 {
                        return Ok(bytes);
                    }
                    bytes.push(byte);
                    if bytes.len() == 4096 {
                        return Err("pathname exceeds 4096 bytes".into());
                    }
                }
            }
        }
        Err("unterminated pathname".into())
    }
    fn reserved(fd: u64, dirs: [i32; 2]) -> bool {
        dirs.contains(&(fd as i32))
    }
    fn device(path: &[u8]) -> bool {
        matches!(
            path,
            b"null" | b"zero" | b"random" | b"urandom" | b"tty" | b"ptmx"
        ) || path
            .strip_prefix(b"pts/")
            .is_some_and(|p| p == b"ptmx" || (!p.is_empty() && p.iter().all(u8::is_ascii_digit)))
    }
    fn credential(n: u64) -> bool {
        [
            SYS_setuid,
            SYS_setgid,
            SYS_setreuid,
            SYS_setregid,
            SYS_setresuid,
            SYS_setresgid,
            SYS_setgroups,
            SYS_setfsuid,
            SYS_setfsgid,
            SYS_capset,
            SYS_unshare,
            SYS_setns,
        ]
        .contains(&(n as i64))
    }
    // commit_creds can reset dumpability on a shared mm. Mark mutations BEFORE
    // PTRACE_SYSCALL, not at EXIT. The single tracer performs all PEEKDATA reads
    // synchronously, with no mutation in flight and no intervening resume.
    // Only memory-reading entries and mutations wait for the gate: futex, signal
    // return, exit_group and other ordinary syscalls must remain runnable.
    // See Linux v6.12 kernel/cred.c commit_creds and fs/exec.c begin_new_exec;
    // exec installs its new mm before changing that mm's dumpability.
    // https://github.com/torvalds/linux/blob/v6.12/kernel/cred.c
    // https://github.com/torvalds/linux/blob/v6.12/fs/exec.c
    // https://man7.org/linux/man-pages/man2/ptrace.2.html
    #[derive(Default)]
    struct Mm {
        epoch: u64,
        mutations: BTreeSet<pid_t>,
        injector: Option<pid_t>,
    }
    impl Mm {
        fn idle(&self) -> bool {
            self.mutations.is_empty() && self.injector.is_none()
        }
        fn begin_mutation(&mut self, tid: pid_t) {
            assert!(self.injector.is_none());
            assert!(self.mutations.insert(tid));
            self.epoch = self.epoch.checked_add(1).expect("mm epoch overflow");
        }
        fn release(&mut self, tid: pid_t) {
            self.mutations.remove(&tid);
            if self.injector == Some(tid) {
                self.injector = None;
            }
        }
    }
    #[derive(Default)]
    struct Task {
        newborn: bool,
        tgid: pid_t,
        pidfd: Option<Rc<File>>,
        mm: Rc<RefCell<Mm>>,
        // Identity only: Linux owns the actual table and CLONE_FILES semantics.
        files: Rc<()>,
        refreshed: Option<u64>,
        held: bool,
        retired: bool,
        awaiting_death: bool,
        injection: Option<user_regs_struct>,
        entry: Option<user_regs_struct>,
        rewritten: bool,
        spoof: Option<i64>,
    }
    impl Task {
        fn child(&self, tid: pid_t, flags: u64) -> Self {
            Self {
                newborn: true,
                tgid: if flags & CLONE_THREAD as u64 != 0 {
                    self.tgid
                } else {
                    tid
                },
                pidfd: if flags & CLONE_THREAD as u64 != 0 {
                    self.pidfd.clone()
                } else {
                    None
                },
                mm: if flags & CLONE_VM as u64 != 0 {
                    self.mm.clone()
                } else {
                    Rc::default()
                },
                files: if flags & CLONE_FILES as u64 != 0 {
                    self.files.clone()
                } else {
                    Rc::new(())
                },
                ..Self::default()
            }
        }
        fn exec(&mut self, tid: pid_t) {
            *self = Self {
                tgid: tid,
                pidfd: self.pidfd.take(),
                ..Self::default()
            };
        }
        fn pin_process(&mut self) -> Result<()> {
            if self.pidfd.is_none() {
                let fd = unsafe { syscall(SYS_pidfd_open, self.tgid, 0) };
                if fd < 0 {
                    return Err(format!("pidfd_open: {}", std::io::Error::last_os_error()));
                }
                self.pidfd = Some(Rc::new(unsafe { File::from_raw_fd(fd as i32) }));
            }
            Ok(())
        }
    }
    fn mutates_dumpability(r: &user_regs_struct) -> bool {
        credential(r.orig_rax)
            || (r.orig_rax == SYS_prctl as u64 && r.rdi as i32 == PR_SET_DUMPABLE)
    }
    fn reads_memory(r: &user_regs_struct) -> bool {
        let n = r.orig_rax as i64;
        ([
            SYS_openat,
            SYS_newfstatat,
            SYS_readlinkat,
            SYS_faccessat,
            SYS_faccessat2,
            SYS_statx,
            SYS_openat2,
        ]
        .contains(&n)
            && r.rsi != 0)
            || ([
                SYS_open,
                SYS_creat,
                SYS_stat,
                SYS_lstat,
                SYS_readlink,
                SYS_access,
            ]
            .contains(&n)
                && r.rdi != 0)
    }
    fn entry_ready(task: &Task, r: &user_regs_struct) -> bool {
        let mm = task.mm.borrow();
        if reads_memory(r) {
            mm.idle()
        } else if mutates_dumpability(r) {
            mm.injector.is_none()
        } else {
            true
        }
    }
    fn spoof(task: &mut Task, regs: &mut user_regs_struct, result: i64) {
        regs.orig_rax = u64::MAX;
        task.spoof = Some(result);
    }
    // No child memory is written: stripping "/dev/" or "/proc/" only advances
    // the existing pointer. stat vs lstat and all *at flags remain distinct.
    fn remap(pid: pid_t, task: &mut Task, r: &mut user_regs_struct, dirs: [i32; 2]) -> Result<()> {
        let n = r.orig_rax as i64;
        if n == SYS_close && reserved(r.rdi, dirs) {
            spoof(task, r, 0);
            return Ok(());
        }
        if n == SYS_close_range
            && dirs
                .iter()
                .any(|&fd| (r.rdi as u32) <= fd as u32 && fd as u32 <= r.rsi as u32)
        {
            if std::env::var_os("RPWELD_TRACE_VERBOSE").is_some_and(|v| v == "1") {
                eprintln!(
                    "rpweld: debug: close_range fallback used to preserve runner file descriptors"
                );
            }
            spoof(task, r, -(ENOSYS as i64));
            return Ok(());
        }
        if (n == SYS_dup2 || n == SYS_dup3) && reserved(r.rsi, dirs) && r.rdi != r.rsi {
            return Err("dup2/dup3 would overwrite a pinned directory fd".into());
        }
        if n == SYS_fcntl && reserved(r.rdi, dirs) {
            match r.rsi as i32 {
                F_GETFD | F_GETFL | F_DUPFD | F_DUPFD_CLOEXEC => {}
                F_SETFD if r.rdx == 0 => {}
                F_SETFD if r.rdx == FD_CLOEXEC as u64 => {
                    spoof(task, r, 0);
                    return Ok(());
                }
                _ => {
                    return Err(
                        "unsupported fcntl mutation of a pinned directory fd (including CLOEXEC)"
                            .into(),
                    );
                }
            }
        }
        if n == SYS_ioctl && reserved(r.rdi, dirs) && r.rsi as u32 == FIOCLEX as u32 {
            spoof(task, r, 0);
            return Ok(());
        }
        if n == SYS_clone3 {
            spoof(task, r, -(ENOSYS as i64));
            return Ok(());
        }
        if n == SYS_clone && r.rdi & CLONE_UNTRACED as u64 != 0 {
            return Err("CLONE_UNTRACED unsupported".into());
        }
        // CLONE_FILES needs no virtual fd table here: the same two numbers are
        // protected in every task, whether Linux shares or copies its fd table.
        let at = [
            SYS_openat,
            SYS_newfstatat,
            SYS_readlinkat,
            SYS_faccessat,
            SYS_faccessat2,
            SYS_statx,
            SYS_openat2,
        ]
        .contains(&n);
        let old = [
            SYS_open,
            SYS_creat,
            SYS_stat,
            SYS_lstat,
            SYS_readlink,
            SYS_access,
        ]
        .contains(&n);
        if !at && !old {
            return Ok(());
        }
        let address = if at { r.rsi } else { r.rdi };
        if address == 0 {
            return Ok(());
        } // Let the kernel produce EFAULT.
        let path = string(pid, address)?;
        if path == b"/dev" || path == b"/proc" {
            return Err("exact /dev or /proc pathname unsupported (no scratch memory)".into());
        }
        let (fd, skip) = if let Some(tail) = path.strip_prefix(b"/dev/") {
            if !device(tail) {
                return Err(format!(
                    "unsupported outer device path: {}",
                    String::from_utf8_lossy(&path)
                ));
            }
            (dirs[0], 5)
        } else if let Some(tail) = path.strip_prefix(b"/proc/") {
            if tail.is_empty() || tail[0] == b'/' || tail.split(|&b| b == b'/').any(|p| p == b"..")
            {
                return Err(
                    "empty /proc root, repeated leading slash, or parent traversal unsupported"
                        .into(),
                );
            }
            (dirs[1], 6)
        } else {
            return Ok(());
        };
        let path_pointer = address + skip;
        if at {
            r.rdi = fd as u64;
            r.rsi = path_pointer;
            return Ok(());
        }
        match n {
            n if n == SYS_open => {
                r.orig_rax = SYS_openat as u64;
                r.r10 = r.rdx;
                r.rdx = r.rsi;
            }
            n if n == SYS_creat => {
                r.orig_rax = SYS_openat as u64;
                r.r10 = r.rsi;
                r.rdx = (O_CREAT | O_WRONLY | O_TRUNC) as u64;
            }
            n if n == SYS_stat || n == SYS_lstat => {
                r.orig_rax = SYS_newfstatat as u64;
                r.rdx = r.rsi;
                r.r10 = if n == SYS_lstat {
                    AT_SYMLINK_NOFOLLOW as u64
                } else {
                    0
                };
            }
            n if n == SYS_readlink => {
                r.orig_rax = SYS_readlinkat as u64;
                r.r10 = r.rdx;
                r.rdx = r.rsi;
            }
            n if n == SYS_access => {
                r.orig_rax = SYS_faccessat as u64;
                r.rdx = r.rsi;
            }
            _ => unreachable!(),
        }
        r.rdi = fd as u64;
        r.rsi = path_pointer;
        Ok(())
    }
    fn syscall_arguments(r: &user_regs_struct) -> [u64; 7] {
        [r.orig_rax, r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9]
    }
    fn syscall_stop(pid: pid_t, task: &mut Task, dirs: [i32; 2]) -> Result<()> {
        let mut info = [0u64; 11];
        let len = trace(GET_SYSCALL_INFO, pid, 88, info.as_mut_ptr() as usize)?;
        if len < 24 || info[0] >> 32 != 0xc000003e {
            return Err("requires native x86_64 syscall info".into());
        }
        let mut r = registers(pid)?;
        match info[0] & 255 {
            1 => {
                if r.orig_rax & 0x40000000 != 0 || r.cs != 0x33 {
                    return Err("compat/x32 syscalls unsupported".into());
                }
                if !entry_ready(task, &r) {
                    task.held = true;
                    return Ok(());
                }
                task.held = false;
                let epoch = task.mm.borrow().epoch;
                if reads_memory(&r) && task.refreshed != Some(epoch) {
                    task.mm.borrow_mut().injector = Some(pid);
                    task.injection = Some(r);
                    r.orig_rax = SYS_prctl as u64;
                    r.rdi = PR_SET_DUMPABLE as u64;
                    r.rsi = 1;
                    r.rdx = 0;
                    r.r10 = 0;
                    r.r8 = 0;
                    r.r9 = 0;
                } else {
                    if reads_memory(&r) {
                        assert!(task.mm.borrow().idle());
                        assert_eq!(task.refreshed, Some(task.mm.borrow().epoch));
                    }
                    task.entry = Some(r);
                    remap(pid, task, &mut r, dirs)?;
                    task.rewritten =
                        syscall_arguments(&r) != syscall_arguments(task.entry.as_ref().unwrap());
                    if mutates_dumpability(&r) {
                        task.mm.borrow_mut().begin_mutation(pid);
                    }
                }
                set_registers(pid, &r)?;
            }
            2 => {
                if let Some(mut saved) = task.injection.take() {
                    if r.rax != 0 || r.rip != saved.rip {
                        return Err(format!(
                            "register-only dumpability injection failed (PR_SET_DUMPABLE policy; return {}); command cannot be safely traced",
                            r.rax as i64
                        ));
                    }
                    // Replay the displaced syscall instruction, with every original
                    // argument intact. Its next ENTRY is handled normally.
                    saved.rax = saved.orig_rax;
                    saved.rip = saved.rip.checked_sub(2).ok_or("invalid syscall RIP")?;
                    set_registers(pid, &saved)?;
                    let mut mm = task.mm.borrow_mut();
                    assert_eq!(mm.injector, Some(pid));
                    assert!(mm.mutations.is_empty());
                    task.refreshed = Some(mm.epoch);
                    mm.release(pid);
                } else if let Some(saved) = task.entry.take() {
                    task.mm.borrow_mut().release(pid);
                    if saved.orig_rax == SYS_unshare as u64
                        && saved.rdi & CLONE_FILES as u64 != 0
                        && r.rax == 0
                    {
                        task.files = Rc::new(());
                    }
                    if saved.orig_rax == SYS_close_range as u64
                        && saved.rdx & CLOSE_RANGE_UNSHARE as u64 != 0
                        && r.rax == 0
                        && task.spoof.is_none()
                    {
                        task.files = Rc::new(());
                    }
                    // In particular, rt_sigreturn's kernel-restored context is final.
                    if task.rewritten {
                        r.orig_rax = saved.orig_rax;
                        r.rdi = saved.rdi;
                        r.rsi = saved.rsi;
                        r.rdx = saved.rdx;
                        r.r10 = saved.r10;
                        r.r8 = saved.r8;
                        r.r9 = saved.r9;
                        if let Some(result) = task.spoof.take() {
                            r.rax = result as u64;
                        }
                        set_registers(pid, &r)?;
                        task.rewritten = false;
                    }
                }
            }
            _ => return Err("unexpected syscall stop operation".into()),
        }
        Ok(())
    }
    struct Children {
        tasks: BTreeMap<pid_t, Task>,
    }
    impl Children {
        fn remove(&mut self, tid: pid_t) {
            if let Some(task) = self.tasks.remove(&tid) {
                task.mm.borrow_mut().release(tid);
            }
        }
        fn exec(&mut self, tid: pid_t, former_tid: pid_t) -> Result<()> {
            let group = self
                .tasks
                .get(&former_tid)
                .ok_or("exec former TID is not tracked")?
                .tgid;
            if group != tid {
                return Err("exec TID differs from tracked thread group".into());
            }
            // Retain tombstones until waitpid reaps them (or reports ECHILD),
            // including siblings already killed during another syscall/injection.
            for (&other, task) in self.tasks.iter_mut() {
                if task.tgid == group {
                    task.mm.borrow_mut().release(other);
                    task.held = false;
                    task.retired = true;
                    task.injection = None;
                    task.entry = None;
                }
            }
            let mut execer = self.tasks.remove(&former_tid).unwrap();
            execer.exec(tid);
            self.tasks.insert(tid, execer);
            Ok(())
        }
        fn cleanup(&mut self) {
            let until = Instant::now() + Duration::from_secs(3);
            // Exec tombstones may name recycled TIDs. Only retained process
            // identities are safe to signal, including shared thread groups.
            for task in self.tasks.values() {
                if let Some(fd) = &task.pidfd {
                    unsafe {
                        syscall(
                            SYS_pidfd_send_signal,
                            fd.as_raw_fd(),
                            SIGKILL,
                            ptr::null::<siginfo_t>(),
                            0,
                        );
                    }
                }
            }
            // This standalone subreaper owns every child. A ptrace terminal
            // notification can precede adoption and a second, real-parent reap.
            // Wait through ECHILD, even after the tracee map becomes empty.
            while Instant::now() < until {
                let mut status = 0;
                let pid = unsafe { waitpid(-1, &mut status, WNOHANG | __WALL) };
                if pid > 0 {
                    if WIFEXITED(status) || WIFSIGNALED(status) {
                        self.remove(pid);
                    } else if WIFSTOPPED(status) {
                        // Also covers newborns whose fork event was pending at
                        // cancellation, and the initial child if pinning failed.
                        // ptrace addresses our tracee, never a recycled PID.
                        let _ = trace(PTRACE_CONT, pid, 0, SIGKILL as usize);
                    }
                    continue;
                }
                if pid < 0 && errno() == ECHILD {
                    self.tasks.clear();
                    return;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            eprintln!(
                "rpweld: runner cleanup deadline; children remain (tracked {:?})",
                self.tasks.keys()
            );
        }
    }
    impl Drop for Children {
        fn drop(&mut self) {
            self.cleanup();
        }
    }
    fn supervise(pid: pid_t, dirs: [i32; 2], timeout: Duration) -> Result<i32> {
        let mut children = Children {
            tasks: BTreeMap::from([(
                pid,
                Task {
                    newborn: true,
                    tgid: pid,
                    ..Task::default()
                },
            )]),
        };
        children.tasks.get_mut(&pid).unwrap().pin_process()?;
        let start = Instant::now();
        let mut child_events: sigset_t = unsafe { zeroed() };
        unsafe {
            sigemptyset(&mut child_events);
            sigaddset(&mut child_events, SIGCHLD);
        }
        let mut code = 0;
        while !children.tasks.is_empty() {
            let signal = CANCEL.load(Ordering::Relaxed);
            if signal != 0 {
                eprintln!("rpweld: runner cancelled by signal {signal}");
                return Ok(128 + signal);
            }
            if start.elapsed() >= timeout {
                eprintln!("rpweld: RUN timed out");
                return Ok(124);
            }
            let pids: Vec<_> = children.tasks.keys().copied().collect();
            let mut progress = false;
            for tid in pids {
                // A previous exec event can replace/remove entries in this batch.
                if !children.tasks.contains_key(&tid) {
                    continue;
                }
                let mut status = 0;
                let result = unsafe { waitpid(tid, &mut status, WNOHANG | __WALL) };
                if result == 0 {
                    if children.tasks[&tid].held && !children.tasks[&tid].awaiting_death {
                        let task = children.tasks.get_mut(&tid).unwrap();
                        let resumed = (|| -> Result<()> {
                            syscall_stop(tid, task, dirs)?;
                            if !task.held {
                                trace(PTRACE_SYSCALL, tid, 0, 0)?;
                                progress = true;
                            }
                            Ok(())
                        })();
                        if let Err(error) = resumed {
                            if errno() != ESRCH {
                                return Err(error);
                            }
                            task.awaiting_death = true;
                        }
                    }
                    continue;
                }
                if result < 0 {
                    if errno() == EINTR {
                        continue;
                    }
                    if errno() == ECHILD {
                        if children.tasks[&tid].retired {
                            children.remove(tid);
                            progress = true;
                            continue;
                        }
                        // An execing nonleader can disappear before the leader's
                        // EXEC event is collected. Keep its identity for that event.
                        if children.tasks[&tid].entry.as_ref().is_some_and(|r| {
                            r.orig_rax == SYS_execve as u64 || r.orig_rax == SYS_execveat as u64
                        }) {
                            continue;
                        }
                        children.remove(tid);
                    }
                    return Err(format!(
                        "waitpid {tid}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                progress = true;
                if WIFEXITED(status) || WIFSIGNALED(status) {
                    children.remove(tid);
                    if tid == pid {
                        code = if WIFEXITED(status) {
                            WEXITSTATUS(status)
                        } else {
                            128 + WTERMSIG(status)
                        };
                    }
                    continue;
                }
                if !WIFSTOPPED(status) {
                    return Err("unexpected wait status".into());
                }
                let event = status >> 16;
                let sig = WSTOPSIG(status);
                let mut deliver = 0;
                // SIGKILL/exit_group can invalidate any collected stop before
                // the next ptrace. Keep gate ownership until death is reaped or
                // EXEC retires the task; ESRCH alone is not proof of an exit.
                let handled = (|| -> Result<()> {
                    if [PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE].contains(&event)
                    {
                        let mut new_pid = 0usize;
                        trace(PTRACE_GETEVENTMSG, tid, 0, &mut new_pid as *mut _ as usize)?;
                        let parent = &children.tasks[&tid];
                        let entry = parent
                            .entry
                            .as_ref()
                            .ok_or("clone event without syscall entry")?;
                        // Event type depends on exit signal, not just the syscall name.
                        let flags = if entry.orig_rax == SYS_clone as u64 {
                            entry.rdi
                        } else if entry.orig_rax == SYS_vfork as u64 {
                            (CLONE_VM | CLONE_VFORK) as u64
                        } else {
                            0
                        };
                        let child = parent.child(new_pid as pid_t, flags);
                        children.tasks.insert(new_pid as pid_t, child);
                        children
                            .tasks
                            .get_mut(&(new_pid as pid_t))
                            .unwrap()
                            .pin_process()?;
                    } else if event == PTRACE_EVENT_EXEC {
                        let mut former_tid = 0usize;
                        trace(
                            PTRACE_GETEVENTMSG,
                            tid,
                            0,
                            &mut former_tid as *mut _ as usize,
                        )?;
                        children.exec(tid, former_tid as pid_t)?;
                    } else if event != 0 {
                        return Err(format!("unsupported ptrace event {event}"));
                    } else if sig == (SIGTRAP | 0x80) {
                        syscall_stop(tid, children.tasks.get_mut(&tid).unwrap(), dirs)?;
                    } else if sig == SIGSTOP && children.tasks[&tid].newborn {
                        children.tasks.get_mut(&tid).unwrap().newborn = false;
                        trace(
                            PTRACE_SETOPTIONS,
                            tid,
                            0,
                            (PTRACE_O_EXITKILL
                                | PTRACE_O_TRACESYSGOOD
                                | PTRACE_O_TRACEEXEC
                                | PTRACE_O_TRACEFORK
                                | PTRACE_O_TRACEVFORK
                                | PTRACE_O_TRACECLONE) as usize,
                        )?;
                    } else {
                        let mut siginfo: siginfo_t = unsafe { zeroed() };
                        trace(PTRACE_GETSIGINFO, tid, 0, &mut siginfo as *mut _ as usize)
                            .map_err(|e| format!("group stops unsupported: {e}"))?;
                        deliver = sig; // Including real SIGTRAP; suppress only synthetic stops.
                    }
                    if !children.tasks[&tid].held {
                        trace(PTRACE_SYSCALL, tid, 0, deliver as usize)?;
                    }
                    Ok(())
                })();
                if let Err(error) = handled {
                    if errno() != ESRCH {
                        return Err(error);
                    }
                    if let Some(task) = children.tasks.get_mut(&tid) {
                        task.awaiting_death = true;
                    }
                }
            }
            if !progress {
                // SIGCHLD is blocked in the tracer, so a stop cannot race the wait.
                // Wake on actual child events, with a bound for timeout/cancellation.
                let deadline = timespec {
                    tv_sec: 0,
                    tv_nsec: 50_000_000,
                };
                let result = unsafe { sigtimedwait(&child_events, ptr::null_mut(), &deadline) };
                if result < 0 && ![EAGAIN, EINTR].contains(&errno()) {
                    return Err(format!(
                        "waiting for child events: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
        }
        Ok(code)
    }
    fn directory(path: &Path) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            .open(path)
            .map_err(|e| e.to_string())?;
        let fd = unsafe { fcntl(file.as_raw_fd(), F_DUPFD_CLOEXEC, 64) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    // One atomic, bounded record. CLOEXEC closes this before any application runs.
    fn setup_failure(fd: i32, operation: i32) -> ! {
        let record = [operation, errno()];
        unsafe {
            write(fd, record.as_ptr().cast(), std::mem::size_of_val(&record));
            _exit(1);
        }
    }
    fn setup_identity(fd: i32, user: &crate::user::ResolvedUser, groups: &mut [gid_t]) {
        unsafe {
            let count = getgroups(groups.len() as i32, groups.as_mut_ptr());
            if count < 0 {
                setup_failure(fd, 5);
            }
            groups[..count as usize].sort_unstable();
            if groups[..count as usize] != user.supplementary_gids
                && setgroups(
                    user.supplementary_gids.len(),
                    user.supplementary_gids.as_ptr(),
                ) != 0
            {
                setup_failure(fd, 6);
            }
            let (mut real, mut effective, mut saved) = (0, 0, 0);
            if getresgid(&mut real, &mut effective, &mut saved) != 0 {
                setup_failure(fd, 7);
            }
            if (real, effective, saved) != (user.gid, user.gid, user.gid)
                && setresgid(user.gid, user.gid, user.gid) != 0
            {
                setup_failure(fd, 8);
            }
            if user.uid != 0
                && (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0
                    || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0)
            {
                setup_failure(fd, 9);
            }
            if getresuid(&mut real, &mut effective, &mut saved) != 0 {
                setup_failure(fd, 10);
            }
            if (real, effective, saved) != (user.uid, user.uid, user.uid)
                && setresuid(user.uid, user.uid, user.uid) != 0
            {
                setup_failure(fd, 11);
            }
            if user.uid != 0 {
                // Clear inheritable capabilities too; UID transitions only clear P/E.
                let mut header = [0x20080522u32, 0];
                let mut caps = [0u32; 6];
                if syscall(SYS_capset, header.as_ptr(), caps.as_ptr()) != 0
                    || syscall(SYS_capget, header.as_mut_ptr(), caps.as_mut_ptr()) != 0
                    || caps != [0; 6]
                {
                    setup_failure(fd, 9);
                }
            }
            if getresuid(&mut real, &mut effective, &mut saved) != 0
                || (real, effective, saved) != (user.uid, user.uid, user.uid)
            {
                setup_failure(fd, 12);
            }
            if getresgid(&mut real, &mut effective, &mut saved) != 0
                || (real, effective, saved) != (user.gid, user.gid, user.gid)
            {
                setup_failure(fd, 12);
            }
            let count = getgroups(groups.len() as i32, groups.as_mut_ptr());
            if count < 0 {
                setup_failure(fd, 12);
            }
            groups[..count as usize].sort_unstable();
            if groups[..count as usize] != user.supplementary_gids {
                setup_failure(fd, 12);
            }
            // Query the filesystem IDs with the unrepresentable (reserved) ID.
            if syscall(SYS_setfsuid, u32::MAX) as u32 != user.uid
                || syscall(SYS_setfsgid, u32::MAX) as u32 != user.gid
            {
                *__errno_location() = EPERM;
                setup_failure(fd, 12);
            }
        }
    }
    pub(super) fn run(options: super::WorkerOptions) -> Result<i32> {
        options.validate()?;
        if unsafe { getuid() != 0 || geteuid() != 0 } {
            return Err("requires real and effective root".into());
        }
        let seconds = options.timeout_seconds;
        let root = fs::canonicalize(&options.rootfs).map_err(|e| e.to_string())?;
        let state = fs::canonicalize(&options.state_dir).map_err(|e| e.to_string())?;
        let cwd = std::env::current_dir()
            .and_then(fs::canonicalize)
            .map_err(|e| e.to_string())?;
        if !root.is_dir()
            || !state.is_dir()
            || root == Path::new("/")
            || cwd.starts_with(&root)
            || root.starts_with(&cwd)
            || root.starts_with(&state)
            || state.starts_with(&root)
        {
            return Err("refusing / or overlapping rootfs/state/cwd (state may equal cwd)".into());
        }
        let pinned = directory(&root)?;
        let user = crate::user::resolve_pinned(&pinned, &options.user)?;
        let meta = pinned.metadata().map_err(|e| e.to_string())?;
        let before = fs::metadata(&root).map_err(|e| e.to_string())?;
        let outer = fs::metadata("/").map_err(|e| e.to_string())?;
        if (meta.dev(), meta.ino()) != (before.dev(), before.ino())
            || (meta.dev(), meta.ino()) == (outer.dev(), outer.ino())
        {
            return Err("root changed or aliases outer /".into());
        }
        let dev = directory(Path::new("/dev"))?;
        let proc = directory(Path::new("/proc"))?;
        let dirs = [dev.as_raw_fd(), proc.as_raw_fd()];
        use std::os::unix::ffi::OsStrExt;
        let command = CString::new(options.command.as_bytes()).map_err(|e| e.to_string())?;
        let argv = [
            c"/bin/sh".as_ptr(),
            c"-c".as_ptr(),
            command.as_ptr(),
            ptr::null(),
        ];
        let working_directory =
            CString::new(options.working_directory.as_bytes()).map_err(|e| e.to_string())?;
        let mut entries: Vec<String> = options
            .environment()
            .into_iter()
            .map(str::to_owned)
            .collect();
        if !entries
            .iter()
            .any(|entry| entry.starts_with("HOME=") && entry.len() > 5)
        {
            entries.retain(|entry| !entry.starts_with("HOME="));
            entries.push(format!("HOME={}", user.home));
        }
        let environment: Vec<CString> = entries
            .into_iter()
            .map(|entry| CString::new(entry).expect("validated environment"))
            .collect();
        let mut env: Vec<_> = environment.iter().map(|entry| entry.as_ptr()).collect();
        env.push(ptr::null());
        let mut group_buffer = vec![0; 65536];
        let mut errors = [0; 2];
        if unsafe { pipe2(errors.as_mut_ptr(), O_CLOEXEC | O_NONBLOCK) } != 0 {
            return Err(format!(
                "USER setup error pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let error_reader = unsafe { File::from_raw_fd(errors[0]) };
        let error_writer = unsafe { File::from_raw_fd(errors[1]) };
        unsafe {
            let mut action: sigaction = zeroed();
            sigemptyset(&mut action.sa_mask);
            action.sa_sigaction = SIG_DFL;
            if sigaction(SIGCHLD, &action, ptr::null_mut()) != 0 {
                return Err("cannot reset SIGCHLD".into());
            }
            action.sa_sigaction = cancel as *const () as usize;
            for signal in [SIGINT, SIGTERM, SIGHUP] {
                if sigaction(signal, &action, ptr::null_mut()) != 0 {
                    return Err("cannot install cancellation handler".into());
                }
            }
            let mut mask: sigset_t = zeroed();
            sigemptyset(&mut mask);
            if sigprocmask(SIG_SETMASK, &mask, ptr::null_mut()) != 0 {
                return Err("cannot clear signal mask".into());
            }
            sigaddset(&mut mask, SIGCHLD);
            if sigprocmask(SIG_BLOCK, &mask, ptr::null_mut()) != 0 {
                return Err("cannot block child events".into());
            }
            // Keep orphaned descendants here for their real-parent reap after
            // ptrace reports death; otherwise they escape to an outer subreaper.
            if prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 {
                return Err("cannot become child subreaper".into());
            }
            let pid = fork();
            if pid < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if pid == 0 {
                close(error_reader.as_raw_fd());
                let error_fd = error_writer.as_raw_fd();
                sigemptyset(&mut mask);
                if sigprocmask(SIG_SETMASK, &mask, ptr::null_mut()) != 0 {
                    setup_failure(error_fd, 1);
                }
                for signal in [SIGINT, SIGTERM, SIGHUP] {
                    libc::signal(signal, SIG_DFL);
                }
                if ptrace(
                    PTRACE_TRACEME,
                    0,
                    ptr::null_mut::<c_void>(),
                    ptr::null_mut::<c_void>(),
                ) != 0
                {
                    setup_failure(error_fd, 2);
                }
                if raise(SIGSTOP) != 0 {
                    setup_failure(error_fd, 2);
                }
                if fchdir(pinned.as_raw_fd()) != 0
                    || chroot(c".".as_ptr()) != 0
                    || chdir(c"/".as_ptr()) != 0
                    || chdir(working_directory.as_ptr()) != 0
                {
                    setup_failure(error_fd, 3);
                }
                close(pinned.as_raw_fd());
                for fd in dirs {
                    if fcntl(fd, F_SETFD, 0) != 0 {
                        setup_failure(error_fd, 4);
                    }
                }
                setup_identity(error_fd, &user, &mut group_buffer);
                // Exercise the existing memory-read gate after the initial UID drop,
                // before application exec; policy denial must not run the command.
                if access(c"/".as_ptr(), F_OK) != 0 {
                    setup_failure(error_fd, 14);
                }
                execve(argv[0], argv.as_ptr(), env.as_ptr());
                setup_failure(error_fd, 13);
            }
            drop(error_writer);
            if std::env::var_os("RPWELD_BUILD_WORKER").is_none() {
                eprintln!(
                    "Note: Weld runs trusted commands only; commands can access host devices and process information."
                );
            }
            let result = supervise(pid, dirs, Duration::from_secs(seconds));
            let mut record = [0i32; 2];
            let count = read(
                error_reader.as_raw_fd(),
                record.as_mut_ptr().cast(),
                std::mem::size_of_val(&record),
            );
            if count == std::mem::size_of_val(&record) as isize {
                let operation = match record[0] {
                    1 => "signal setup",
                    2 => "PTRACE_TRACEME/initial stop (ptrace policy)",
                    3 => "chroot/workdir (CAP_SYS_CHROOT and directory access)",
                    4 => "descriptor setup",
                    5 => "getgroups",
                    6 => "setgroups (CAP_SETGID)",
                    7 => "getresgid",
                    8 => "setresgid (CAP_SETGID)",
                    9 => "clear/verify nonroot capabilities",
                    10 => "getresuid",
                    11 => "setresuid (CAP_SETUID)",
                    12 => "verify IDs/groups",
                    13 => "exec /bin/sh",
                    14 => "initial USER pathname/dumpability gate",
                    _ => "unknown setup operation",
                };
                return Err(format!(
                    "USER {:?} (uid={}, gid={}): {operation} failed: {}",
                    options.user,
                    user.uid,
                    user.gid,
                    std::io::Error::from_raw_os_error(record[1])
                ));
            }
            result
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn cleanup_reaps_orphans_even_without_tracked_tasks() {
            const HELPER: &str = "TRACE_ROOT_REAP_TEST";
            if std::env::var_os(HELPER).is_none() {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "trace_worker::linux::tests::cleanup_reaps_orphans_even_without_tracked_tasks",
                    ])
                    .env(HELPER, "1")
                    .status()
                    .unwrap();
                assert!(status.success());
                return;
            }
            // Isolate subreaper state and wait-any from other Rust test threads.
            unsafe {
                assert_eq!(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), 0);
                let child = fork();
                assert!(child >= 0);
                if child == 0 {
                    let grandchild = fork();
                    if grandchild < 0 {
                        _exit(1);
                    }
                    _exit(0);
                }
                let mut children = Children {
                    tasks: BTreeMap::new(),
                };
                children.cleanup();
                let mut status = 0;
                assert_eq!(waitpid(-1, &mut status, WNOHANG | __WALL), -1);
                assert_eq!(errno(), ECHILD);
            }
        }
        #[test]
        fn process_identity_is_shared_by_threads_and_survives_exec() {
            let mut parent = Task {
                tgid: unsafe { getpid() },
                ..Task::default()
            };
            parent.pin_process().unwrap();
            let identity = parent.pidfd.as_ref().unwrap().clone();
            let mut thread = parent.child(123, CLONE_THREAD as u64);
            assert!(Rc::ptr_eq(thread.pidfd.as_ref().unwrap(), &identity));
            assert!(parent.child(124, CLONE_VM as u64).pidfd.is_none());
            thread.exec(parent.tgid);
            assert!(Rc::ptr_eq(thread.pidfd.as_ref().unwrap(), &identity));
        }
        #[test]
        fn ioctl_cloexec_protection() {
            for fd in [64, 65, 66, 67] {
                for request in [FIOCLEX, FIONCLEX] {
                    let mut task = Task::default();
                    let mut r: user_regs_struct = unsafe { zeroed() };
                    r.orig_rax = SYS_ioctl as u64;
                    r.rdi = fd;
                    r.rsi = request;
                    remap(0, &mut task, &mut r, [65, 66]).unwrap();
                    let protected = [65, 66].contains(&fd) && request == FIOCLEX;
                    assert_eq!(task.spoof, if protected { Some(0) } else { None });
                    assert_eq!(
                        r.orig_rax,
                        if protected {
                            u64::MAX
                        } else {
                            SYS_ioctl as u64
                        }
                    );
                }
            }
        }
        #[test]
        fn clone_threads_and_shared_mm_are_admitted() {
            for (flags, allowed) in [
                (CLONE_VM, true),
                (CLONE_VM | CLONE_FILES, true),
                (CLONE_VM | CLONE_VFORK, true),
                (CLONE_VM | CLONE_VFORK | CLONE_FILES, true),
                (CLONE_VM | CLONE_VFORK | CLONE_THREAD, true),
                (CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, true),
                (CLONE_THREAD, true), // Invalid flag combinations remain kernel errors.
                (CLONE_UNTRACED, false),
                (CLONE_VM | CLONE_VFORK | CLONE_UNTRACED, false),
                (CLONE_FILES, true),
                (0, true),
            ] {
                let mut task = Task::default();
                let mut r: user_regs_struct = unsafe { zeroed() };
                r.orig_rax = SYS_clone as u64;
                r.rdi = (flags | SIGCHLD) as u64;
                assert_eq!(remap(0, &mut task, &mut r, [65, 66]).is_ok(), allowed);
            }
        }
        #[test]
        fn clone3_fallback_does_not_read_tracee_memory() {
            let mut task = Task::default();
            let mut r: user_regs_struct = unsafe { zeroed() };
            r.orig_rax = SYS_clone3 as u64;
            r.rdi = 1; // Deliberately invalid: clone3 is rejected before reading args.
            remap(0, &mut task, &mut r, [65, 66]).unwrap();
            assert_eq!(r.orig_rax, u64::MAX);
            assert_eq!(task.spoof, Some(-(ENOSYS as i64)));
        }
        #[test]
        fn exec_discards_old_syscall_state() {
            let mut task = Task {
                newborn: true,
                injection: Some(unsafe { zeroed() }),
                entry: Some(unsafe { zeroed() }),
                rewritten: true,
                spoof: Some(0),
                ..Task::default()
            };
            task.exec(123);
            assert_eq!(task.refreshed, None);
            assert_eq!(task.tgid, 123);
            assert!(!task.newborn);
            assert!(task.injection.is_none());
            assert!(task.entry.is_none());
            assert!(!task.rewritten);
            assert!(task.spoof.is_none());
        }
        #[test]
        fn nonleader_exec_replaces_leader_and_retires_only_its_group() {
            let leader = Task {
                tgid: 123,
                ..Task::default()
            };
            let mm = leader.mm.clone();
            let files = leader.files.clone();
            let mut execer = leader.child(124, (CLONE_VM | CLONE_THREAD | CLONE_FILES) as u64);
            execer.entry = Some(unsafe { zeroed() });
            execer.spoof = Some(7);
            let mut sibling = leader.child(125, (CLONE_VM | CLONE_THREAD) as u64);
            sibling.held = true;
            sibling.injection = Some(unsafe { zeroed() });
            mm.borrow_mut().injector = Some(125);
            let peer = leader.child(126, (CLONE_VM | CLONE_FILES) as u64);
            // Never run the OS cleanup destructor on synthetic PIDs, even if
            // an assertion panics.
            let mut children = std::mem::ManuallyDrop::new(Children {
                tasks: BTreeMap::from([(123, leader), (124, execer), (125, sibling), (126, peer)]),
            });
            children.exec(123, 124).unwrap();
            assert!(!children.tasks.contains_key(&124));
            let survivor = &children.tasks[&123];
            assert_eq!(survivor.tgid, 123);
            assert!(survivor.entry.is_none());
            assert!(survivor.spoof.is_none());
            assert!(!Rc::ptr_eq(&survivor.mm, &mm));
            assert!(!Rc::ptr_eq(&survivor.files, &files));
            assert!(children.tasks[&125].retired);
            assert!(!children.tasks[&125].held);
            assert!(children.tasks[&125].injection.is_none());
            assert!(!children.tasks[&126].retired);
            assert!(Rc::ptr_eq(&children.tasks[&126].mm, &mm));
            assert!(Rc::ptr_eq(&children.tasks[&126].files, &files));
            assert!(mm.borrow().idle());
            children.tasks.clear();
        }
        #[test]
        fn unknown_exec_identity_preserves_state() {
            let task = Task {
                tgid: 123,
                injection: Some(unsafe { zeroed() }),
                spoof: Some(7),
                ..Task::default()
            };
            let mut children = std::mem::ManuallyDrop::new(Children {
                tasks: BTreeMap::from([(123, task)]),
            });
            assert!(children.exec(123, 124).is_err());
            assert!(children.tasks[&123].injection.is_some());
            assert_eq!(children.tasks[&123].spoof, Some(7));
            children.tasks.clear();
        }
        fn syscall(n: i64) -> user_regs_struct {
            let mut r: user_regs_struct = unsafe { zeroed() };
            r.orig_rax = n as u64;
            r.rdi = 1;
            r.rsi = 1;
            r
        }
        #[test]
        fn gate_blocks_reads_until_all_mutations_exit_but_not_futex() {
            let task = Task::default();
            let path = syscall(SYS_openat);
            task.mm.borrow_mut().begin_mutation(10);
            task.mm.borrow_mut().begin_mutation(11);
            assert!(!entry_ready(&task, &path));
            for n in [SYS_futex, SYS_rt_sigreturn, SYS_exit_group, SYS_execve] {
                assert!(entry_ready(&task, &syscall(n)));
            }
            // Other mutations can finish independently (e.g. libc setxid).
            assert!(entry_ready(&task, &syscall(SYS_setuid)));
            task.mm.borrow_mut().release(10);
            assert!(!entry_ready(&task, &path));
            task.mm.borrow_mut().release(11);
            assert!(entry_ready(&task, &path));
            assert_eq!(task.mm.borrow().epoch, 2);
            assert_ne!(task.refreshed, Some(task.mm.borrow().epoch));
        }
        #[test]
        fn injection_excludes_mutations_and_reads_until_exit() {
            let mut task = Task::default();
            task.mm.borrow_mut().injector = Some(10);
            assert!(!entry_ready(&task, &syscall(SYS_openat)));
            for n in [SYS_setuid, SYS_setfsuid, SYS_capset, SYS_unshare, SYS_setns] {
                assert!(!entry_ready(&task, &syscall(n)));
            }
            let mut prctl = syscall(SYS_prctl);
            prctl.rdi = PR_SET_DUMPABLE as u64;
            assert!(!entry_ready(&task, &prctl));
            prctl.rdi |= 1u64 << 32; // prctl's option is a kernel int.
            assert!(!entry_ready(&task, &prctl));
            assert!(entry_ready(&task, &syscall(SYS_futex)));
            task.mm.borrow_mut().release(10);
            task.refreshed = Some(task.mm.borrow().epoch);
            task.mm.borrow_mut().begin_mutation(11);
            task.mm.borrow_mut().release(11);
            assert_ne!(task.refreshed, Some(task.mm.borrow().epoch));
        }
        #[test]
        fn clone_tracks_mm_files_and_group_independently() {
            let parent = Task {
                tgid: 10,
                ..Task::default()
            };
            for flags in [
                0,
                CLONE_FILES,
                CLONE_VM,
                CLONE_VM | CLONE_VFORK,
                CLONE_VM | CLONE_FILES,
                CLONE_VM | CLONE_THREAD | CLONE_FILES,
            ] {
                let child = parent.child(11, flags as u64);
                assert_eq!(Rc::ptr_eq(&parent.mm, &child.mm), flags & CLONE_VM != 0);
                assert_eq!(
                    Rc::ptr_eq(&parent.files, &child.files),
                    flags & CLONE_FILES != 0
                );
                assert_eq!(child.tgid, if flags & CLONE_THREAD != 0 { 10 } else { 11 });
                assert_eq!(child.refreshed, None);
            }
        }
        #[test]
        fn vfork_child_death_releases_gate_and_invalidates_parent_refresh() {
            let mut parent = Task {
                tgid: 10,
                refreshed: Some(0),
                ..Task::default()
            };
            let child = parent.child(11, (CLONE_VM | CLONE_VFORK) as u64);
            child.mm.borrow_mut().begin_mutation(11);
            assert!(!entry_ready(&parent, &syscall(SYS_open)));
            let mut children = std::mem::ManuallyDrop::new(Children {
                tasks: BTreeMap::from([(11, child)]),
            });
            children.remove(11);
            assert!(entry_ready(&parent, &syscall(SYS_open)));
            assert_ne!(parent.refreshed, Some(parent.mm.borrow().epoch));
            parent.mm.borrow_mut().injector = Some(10);
            let mm = parent.mm.clone();
            parent.injection = Some(unsafe { zeroed() });
            children.tasks.insert(10, parent);
            children.remove(10);
            assert!(mm.borrow().idle());
        }
        #[test]
        fn sigreturn_is_not_rewritten() {
            let mut task = Task::default();
            let mut r: user_regs_struct = unsafe { zeroed() };
            r.orig_rax = SYS_rt_sigreturn as u64;
            r.rdi = 11;
            r.rsi = 22;
            r.rdx = 33;
            r.r10 = 44;
            r.r8 = 55;
            r.r9 = 66;
            let before = syscall_arguments(&r);
            remap(0, &mut task, &mut r, [65, 66]).unwrap();
            assert_eq!(syscall_arguments(&r), before);
            assert_eq!(task.spoof, None);
        }
        #[test]
        fn whitelist_and_descriptor_protection() {
            for path in [b"null".as_slice(), b"pts/0", b"pts/ptmx"] {
                assert!(device(path));
            }
            for path in [b"sda".as_slice(), b"pts/../sda", b"null/", b"pts/"] {
                assert!(!device(path));
            }
            let mut task = Task::default();
            let mut r: user_regs_struct = unsafe { zeroed() };
            r.orig_rax = SYS_close as u64;
            r.rdi = 65;
            remap(0, &mut task, &mut r, [65, 66]).unwrap();
            assert_eq!(task.spoof, Some(0));
            r.orig_rax = SYS_dup2 as u64;
            r.rsi = 66;
            r.rdi = 1;
            assert!(remap(0, &mut task, &mut r, [65, 66]).is_err());
            r.orig_rax = SYS_close_range as u64;
            r.rdi = 3;
            r.rsi = u32::MAX as u64;
            remap(0, &mut task, &mut r, [65, 66]).unwrap();
            assert_eq!(task.spoof, Some(-(ENOSYS as i64)));
        }
    }
}

#[cfg(test)]
mod option_tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<WorkerOptions, String> {
        WorkerOptions::from_args(args.iter().map(OsString::from))
    }

    #[test]
    fn legacy_defaults_and_explicit_environment() {
        let defaults = parse(&["root", "state", "30", "true"]).unwrap();
        assert_eq!(defaults.working_directory, "/");
        assert_eq!(defaults.env.len(), 3);
        assert!(defaults.env.contains(&"HOME=/root".into()));
        let options = parse(&[
            "root",
            "state",
            "30",
            "true",
            "--workdir",
            "/app",
            "--clear-env",
            "--env",
            "BASE=old",
            "--env",
            "BASE=new=tail",
            "--env",
            "EMPTY=",
        ])
        .unwrap();
        assert_eq!(options.working_directory, "/app");
        assert_eq!(options.environment(), vec!["BASE=new=tail", "EMPTY="]);
        let user = parse(&["root", "state", "30", "true", "--user", "app"]).unwrap();
        assert_eq!(user.user, "app");
        assert!(!user.env.iter().any(|e| e.starts_with("HOME=")));
        let explicit = parse(&[
            "root",
            "state",
            "30",
            "true",
            "--env",
            "HOME=/chosen",
            "--user",
            "app",
        ])
        .unwrap();
        assert!(explicit.env.contains(&"HOME=/chosen".into()));
    }

    #[test]
    fn invalid_options_are_rejected() {
        for seconds in ["0", "86401", "-1", "abc"] {
            assert!(parse(&["root", "state", seconds, "true"]).is_err());
        }
        for args in [
            vec!["--env"],
            vec!["--workdir"],
            vec!["--user"],
            vec!["--user", ""],
            vec!["--user", "app:"],
            vec!["--unknown"],
            vec!["--env", "MISSING"],
            vec!["--env", "=value"],
            vec!["--env", "BAD\0=value"],
            vec!["--env", "OK=bad\0value"],
            vec!["--workdir", "relative"],
            vec!["--workdir", ""],
            vec!["--workdir", "/bad\0path"],
        ] {
            let mut input = vec!["root", "state", "1", "true"];
            input.extend(args);
            assert!(parse(&input).is_err());
        }
        assert!(parse(&["root", "state", "1"]).is_err());
    }

    #[test]
    fn image_paths_keep_kernel_resolution_semantics() {
        for path in ["/", "/app/../work", "/../../work", "/absolute-symlink"] {
            assert!(parse(&["root", "state", "86400", "true", "--workdir", path]).is_ok());
        }
    }
}
