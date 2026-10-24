//! Experimental trusted-image runner, Linux x86_64, root only (no USER support).
//! Usage: trace_root ROOTFS STATE_DIR TIMEOUT_SECONDS SHELL_COMMAND
//! Real chroot and real credentials; apt's sandbox is not disabled. The tracer
//! restores PR_SET_DUMPABLE after credential changes/exec, changing introspection
//! permissions. PEEKDATA is used, never process_vm_readv or memory/code patches.
//! Absolute supported /dev paths and /proc descendants expose the OUTER Pod;
//! this is not PID/device isolation or a hostile-workload security boundary.
//! Engine-owned directory fds are retained across application close/CLOEXEC requests.
//! Relative paths stay native. Exact /dev and /proc are explicitly unsupported.
//! Only the pathname syscall families below are translated; other calls stay
//! native. Threads, shared mm without vfork, clone3 (libc can fall back to clone), and group stops are
//! unsupported. Trusted stable paths only: mount aliases/renames are not isolated.
//! SIGINT/SIGTERM/SIGHUP cancel. Cleanup is bounded; uninterruptible kernel tasks
//! can outlive it (EXITKILL also applies when the tracer exits). No library use.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("trace_root requires Linux x86_64");
    std::process::exit(1);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    match linux::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("trace_root: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use libc::*;
    use std::{
        collections::BTreeMap,
        ffi::CString,
        fs::{self, File, OpenOptions},
        mem::zeroed,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
        ptr,
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
                Err(format!(
                    "ptrace {request:#x} pid {pid}: {}",
                    std::io::Error::last_os_error()
                ))
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
        ]
        .contains(&(n as i64))
    }
    #[derive(Default)]
    struct Task {
        newborn: bool,
        dumpable: bool,
        injection: Option<user_regs_struct>,
        entry: Option<user_regs_struct>,
        rewritten: bool,
        spoof: Option<i64>,
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
            eprintln!(
                "trace_root: close_range covers pinned fds; returning ENOSYS for caller fallback"
            );
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
        if n == SYS_clone && r.rdi & (CLONE_THREAD | CLONE_UNTRACED) as u64 != 0 {
            return Err("CLONE_THREAD/CLONE_UNTRACED unsupported".into());
        }
        if n == SYS_clone && r.rdi & CLONE_VM as u64 != 0 && r.rdi & CLONE_VFORK as u64 == 0 {
            return Err("CLONE_VM without CLONE_VFORK unsupported".into());
        }
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
                if task.dumpable {
                    task.injection = Some(r);
                    r.orig_rax = SYS_prctl as u64;
                    r.rdi = PR_SET_DUMPABLE as u64;
                    r.rsi = 1;
                    r.rdx = 0;
                    r.r10 = 0;
                    r.r8 = 0;
                    r.r9 = 0;
                } else {
                    task.entry = Some(r);
                    remap(pid, task, &mut r, dirs)?;
                    task.rewritten =
                        syscall_arguments(&r) != syscall_arguments(task.entry.as_ref().unwrap());
                }
                set_registers(pid, &r)?;
            }
            2 => {
                if let Some(mut saved) = task.injection.take() {
                    if r.rax != 0 || r.rip != saved.rip {
                        return Err("register-only dumpability injection failed".into());
                    }
                    // Replay the displaced syscall instruction, with every original
                    // argument intact. Its next ENTRY is handled normally.
                    saved.rax = saved.orig_rax;
                    saved.rip = saved.rip.checked_sub(2).ok_or("invalid syscall RIP")?;
                    set_registers(pid, &saved)?;
                    task.dumpable = false;
                } else if let Some(saved) = task.entry.take() {
                    if credential(saved.orig_rax) && (r.rax as i64 >= 0) {
                        // fsuid/fsgid return the old ID even on failure: harmlessly
                        // refresh dumpability after either outcome.
                        task.dumpable = true;
                    }
                    if saved.orig_rax == SYS_prctl as u64
                        && saved.rdi == PR_SET_DUMPABLE as u64
                        && r.rax == 0
                    {
                        task.dumpable = true;
                    }
                    // A vfork child can change the shared mm's dumpability and die
                    // before its next syscall gives us a chance to restore it.
                    if (r.rax as i64) > 0
                        && (saved.orig_rax == SYS_vfork as u64
                            || (saved.orig_rax == SYS_clone as u64
                                && saved.rdi & CLONE_VFORK as u64 != 0))
                    {
                        task.dumpable = true;
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
        fn cleanup(&mut self) {
            let until = Instant::now() + Duration::from_secs(3);
            // Only known unreaped tracees: no group signals or unrelated reapers.
            for &pid in self.tasks.keys() {
                unsafe {
                    kill(pid, SIGKILL);
                }
            }
            while !self.tasks.is_empty() && Instant::now() < until {
                let pids: Vec<_> = self.tasks.keys().copied().collect();
                for pid in pids {
                    let mut status = 0;
                    let result = unsafe { waitpid(pid, &mut status, WNOHANG | __WALL) };
                    if result == pid {
                        if WIFEXITED(status) || WIFSIGNALED(status) {
                            self.tasks.remove(&pid);
                        } else {
                            let event = status >> 16;
                            if [PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE]
                                .contains(&event)
                            {
                                let mut new_pid = 0usize;
                                if trace(
                                    PTRACE_GETEVENTMSG,
                                    pid,
                                    0,
                                    &mut new_pid as *mut _ as usize,
                                )
                                .is_ok()
                                {
                                    self.tasks.entry(new_pid as pid_t).or_default();
                                    unsafe {
                                        kill(new_pid as pid_t, SIGKILL);
                                    }
                                }
                            }
                            let _ = trace(PTRACE_CONT, pid, 0, SIGKILL as usize);
                        }
                    } else if result < 0 && errno() == ECHILD {
                        self.tasks.remove(&pid);
                    }
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if !self.tasks.is_empty() {
                eprintln!(
                    "trace_root: cleanup deadline; remaining tracees {:?}",
                    self.tasks.keys()
                );
            }
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
                    dumpable: true,
                    ..Task::default()
                },
            )]),
        };
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
                eprintln!("trace_root: cancelled by signal {signal}");
                return Ok(128 + signal);
            }
            if start.elapsed() >= timeout {
                eprintln!("trace_root: timeout");
                return Ok(124);
            }
            let pids: Vec<_> = children.tasks.keys().copied().collect();
            let mut progress = false;
            for tid in pids {
                let mut status = 0;
                let result = unsafe { waitpid(tid, &mut status, WNOHANG | __WALL) };
                if result == 0 {
                    continue;
                }
                if result < 0 {
                    if errno() == EINTR {
                        continue;
                    }
                    if errno() == ECHILD {
                        children.tasks.remove(&tid);
                    }
                    return Err(format!(
                        "waitpid {tid}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                progress = true;
                if WIFEXITED(status) || WIFSIGNALED(status) {
                    children.tasks.remove(&tid);
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
                if [PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE].contains(&event) {
                    let mut new_pid = 0usize;
                    trace(PTRACE_GETEVENTMSG, tid, 0, &mut new_pid as *mut _ as usize)?;
                    children.tasks.insert(
                        new_pid as pid_t,
                        Task {
                            newborn: true,
                            ..Task::default()
                        },
                    );
                } else if event == PTRACE_EVENT_EXEC {
                    let task = children.tasks.get_mut(&tid).unwrap();
                    task.dumpable = true;
                    task.entry = None;
                    task.injection = None;
                    task.spoof = None;
                    task.rewritten = false;
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
                trace(PTRACE_SYSCALL, tid, 0, deliver as usize)?;
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
    pub fn run() -> Result<i32> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() != 5 {
            return Err("usage: trace_root ROOTFS STATE_DIR TIMEOUT_SECONDS SHELL_COMMAND".into());
        }
        if unsafe { getuid() != 0 || geteuid() != 0 } {
            return Err("requires real and effective root".into());
        }
        let seconds = args[3]
            .to_str()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&s| s > 0 && s <= 86400)
            .ok_or("timeout must be 1..86400 seconds")?;
        let root = fs::canonicalize(&args[1]).map_err(|e| e.to_string())?;
        let state = fs::canonicalize(&args[2]).map_err(|e| e.to_string())?;
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
        let command = CString::new(args[4].as_bytes()).map_err(|e| e.to_string())?;
        let argv = [
            c"/bin/sh".as_ptr(),
            c"-c".as_ptr(),
            command.as_ptr(),
            ptr::null(),
        ];
        let env = [
            c"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".as_ptr(),
            c"HOME=/root".as_ptr(),
            c"LC_ALL=C".as_ptr(),
            ptr::null(),
        ];
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
            let pid = fork();
            if pid < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if pid == 0 {
                sigemptyset(&mut mask);
                if sigprocmask(SIG_SETMASK, &mask, ptr::null_mut()) != 0 {
                    _exit(119);
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
                    _exit(120);
                }
                if raise(SIGSTOP) != 0 {
                    _exit(121);
                }
                if fchdir(pinned.as_raw_fd()) != 0
                    || chroot(c".".as_ptr()) != 0
                    || chdir(c"/".as_ptr()) != 0
                {
                    _exit(122);
                }
                close(pinned.as_raw_fd());
                for fd in dirs {
                    if fcntl(fd, F_SETFD, 0) != 0 {
                        _exit(123);
                    }
                }
                if setgroups(0, ptr::null()) != 0 || setgid(0) != 0 {
                    _exit(125);
                }
                execve(argv[0], argv.as_ptr(), env.as_ptr());
                _exit(126);
            }
            eprintln!(
                "trace_root: trusted experiment; outer /dev and /proc exposed; dumpability restored; relative paths native"
            );
            supervise(pid, dirs, Duration::from_secs(seconds))
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn ioctl_cloexec_protection() {
            for fd in [64, 65, 66, 67] {
                for request in [FIOCLEX, FIONCLEX] {
                    let mut task = Task::default();
                    let mut r: user_regs_struct = unsafe { zeroed() };
                    r.orig_rax = SYS_ioctl as u64;
                    r.rdi = fd;
                    r.rsi = request as u64;
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
        fn shared_mm_requires_vfork() {
            for (flags, allowed) in [
                (CLONE_VM, false),
                (CLONE_VM | CLONE_VFORK, true),
                (CLONE_VM | CLONE_VFORK | CLONE_THREAD, false),
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
