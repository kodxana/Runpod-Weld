//! Linux x86_64 feasibility probe; run as root WITHOUT CAP_SYS_PTRACE:
//! cargo +1.90.0 run --release --example ptrace_credentials
//! JSONL on stdout, exit 0=all scenarios supported, 1=failed/unsupported, 2=usage.
//! Requires Linux >=5.3 (PTRACE_GET_SYSCALL_INFO), /proc, and a self executable
//! accessible to UID 1234. No apt/executor integration or sandbox changes.
//! Restoring dumpability changes process introspection behavior; this is NOT
//! isolation/security. A trusted single-threaded child provides syscall slots.
//!
//! Kernel source investigated before implementation (v6.12):
//! https://github.com/torvalds/linux/blob/v6.12/kernel/ptrace.c
//! ptrace_access_vm checks the established relationship and dumpability, not
//! fresh UID equality. TRACEME's ptrace_link saves current_cred (the child).
//! https://github.com/torvalds/linux/blob/v6.12/kernel/capability.c
//! ptracer_capable checks that saved ptracer_cred for CAP_SYS_PTRACE.
//! https://github.com/torvalds/linux/blob/v6.12/arch/x86/kernel/ptrace.c
//! GETREGS/SETREGS copy register state without ptrace_access_vm's memory gate.
//! Kernel/LSM/container policy may still reject any operation; measure, don't assume.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    println!("{{\"status\":\"unsupported\",\"reason\":\"requires Linux x86_64\"}}");
    std::process::exit(1);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    linux::run();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use libc::*;
    use serde_json::{Value, json};
    use std::{
        ffi::CString,
        mem::zeroed,
        ptr,
        time::{Duration, Instant},
    };

    const MAGIC: u64 = 0x505452414345;
    // Whole words, including the NUL and padding: PEEKDATA never overreads it.
    const PATH: &[u8; 16] = b"/dev/null\0\0\0\0\0\0\0";
    const GET_SYSCALL_INFO: c_uint = 0x420e;

    fn errno() -> i32 {
        unsafe { *__errno_location() }
    }

    // No allocations, formatting, unwinding or destructors in the post-fork child.
    unsafe fn verify(uid: uid_t) -> ! {
        unsafe {
            let pid = syscall(SYS_getpid);
            for phase in 0..2u64 {
                let (mut r, mut e, mut s) = (0, 0, 0);
                let (mut gr, mut ge, mut gs) = (0, 0, 0);
                if getresuid(&mut r, &mut e, &mut s) != 0
                    || r != uid
                    || e != uid
                    || s != uid
                    || (uid == 1234
                        && (getresgid(&mut gr, &mut ge, &mut gs) != 0
                            || gr != 1234
                            || ge != 1234
                            || gs != 1234
                            || getgroups(0, ptr::null_mut()) != 0))
                {
                    _exit(24);
                }
                let real_uid = syscall(SYS_getuid);
                let dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
                if real_uid != uid as c_long || dumpable < 0 {
                    _exit(25);
                }
                // getpid ignores arguments: register-only protocol, valid after ASLR/exec.
                let result = syscall(
                    SYS_getpid,
                    MAGIC,
                    phase,
                    PATH.as_ptr(),
                    real_uid as u64,
                    dumpable as u64,
                    syscall(SYS_getgid) as u64,
                );
                if result != pid {
                    _exit(26);
                }
                if phase == 1 && dumpable != 1 {
                    _exit(27);
                }
            }
            _exit(0);
        }
    }

    unsafe fn child(mode: usize, exe: &CString, argv: &[*const c_char; 3]) -> ! {
        unsafe {
            let mut mask: sigset_t = zeroed();
            sigemptyset(&mut mask);
            sigprocmask(SIG_SETMASK, &mask, ptr::null_mut());
            signal(SIGALRM, SIG_DFL);
            alarm(15);
            if ptrace(
                PTRACE_TRACEME,
                0,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            ) != 0
            {
                _exit(20);
            }
            if raise(SIGSTOP) != 0 {
                _exit(21);
            }
            if mode != 0
                && (setgroups(0, ptr::null()) != 0 || setgid(1234) != 0 || setuid(1234) != 0)
            {
                _exit(22);
            }
            if mode == 2 {
                let env = [ptr::null::<c_char>()];
                execve(exe.as_ptr(), argv.as_ptr(), env.as_ptr());
                _exit(23);
            }
            verify(if mode == 0 { 0 } else { 1234 });
        }
    }

    fn trace(request: c_uint, pid: pid_t, addr: usize, data: usize) -> Result<c_long, String> {
        unsafe {
            *__errno_location() = 0;
            let rc = ptrace(request, pid, addr as *mut c_void, data as *mut c_void);
            let error = errno();
            if rc == -1 && error != 0 {
                Err(format!("ptrace request={request:#x} errno={error}"))
            } else {
                Ok(rc)
            }
        }
    }

    struct Child {
        pid: pid_t,
        owned: bool,
    }
    impl Child {
        fn wait(&mut self, until: Instant) -> Result<i32, String> {
            loop {
                if Instant::now() >= until {
                    return Err("child deadline exceeded".into());
                }
                let mut status = 0;
                let rc = unsafe { waitpid(self.pid, &mut status, WNOHANG) };
                if rc == self.pid {
                    if WIFEXITED(status) || WIFSIGNALED(status) {
                        self.owned = false;
                    }
                    return Ok(status);
                }
                if rc < 0 {
                    let error = errno();
                    if error == ECHILD {
                        self.owned = false;
                    }
                    if error != EINTR {
                        return Err(format!("waitpid errno={error}"));
                    }
                }
                if Instant::now() >= until {
                    return Err("child deadline exceeded".into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn cleanup(&mut self) -> Value {
            if !self.owned {
                return json!({"reaped": true});
            }
            // SIGCHLD is default, no threads/reapers exist, and terminal wait clears
            // owned immediately. An unreaped child pins its PID even after death.
            let rc = unsafe { kill(self.pid, SIGKILL) };
            let kill_errno = if rc < 0 { Some(errno()) } else { None };
            let until = Instant::now() + Duration::from_secs(2);
            let mut failure = None;
            while self.owned {
                match self.wait(until) {
                    Ok(_) => {}
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                }
            }
            json!({"reaped": !self.owned, "kill_errno": kill_errno, "error": failure})
        }
    }
    impl Drop for Child {
        fn drop(&mut self) {
            if self.owned {
                let _ = self.cleanup();
            }
        }
    }

    fn memory(pid: pid_t, addr: u64) -> (Value, bool) {
        let mut bytes = [0u8; 16];
        let mut peek_error = None;
        for offset in [0, 8] {
            match trace(PTRACE_PEEKDATA, pid, addr as usize + offset, 0) {
                Ok(word) => bytes[offset..offset + 8].copy_from_slice(&word.to_ne_bytes()),
                Err(e) => {
                    peek_error = Some(e);
                    break;
                }
            }
        }
        let matched = peek_error.is_none() && &bytes == PATH;
        let mut vm = [0u8; 16];
        let local = iovec {
            iov_base: vm.as_mut_ptr().cast(),
            iov_len: vm.len(),
        };
        let remote = iovec {
            iov_base: addr as *mut c_void,
            iov_len: vm.len(),
        };
        let n = unsafe { process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        let vm_errno = if n < 0 { Some(errno()) } else { None };
        (
            json!({"peekdata_match": matched, "peekdata_error": peek_error,
            "process_vm_readv_bytes": n, "process_vm_readv_errno": vm_errno,
            "process_vm_readv_match": n == 16 && &vm == PATH}),
            matched,
        )
    }

    fn scenario(mode: usize, exe: &CString) -> Value {
        let argv = [exe.as_ptr(), c"--ptrace-child".as_ptr(), ptr::null()];
        let pid = unsafe { fork() };
        if pid == 0 {
            unsafe {
                child(mode, exe, &argv);
            }
        }
        let mut report = json!({"scenario": (["root", "uid1234_noexec", "uid1234_exec"][mode]),
            "status": "unsupported", "before": null, "after": null,
            "injection": null, "exec_events": 0});
        if pid < 0 {
            report["error"] = json!(format!("fork errno={}", errno()));
            return report;
        }
        let mut child = Child { pid, owned: true };
        let until = Instant::now() + Duration::from_secs(10);
        let result = (|| -> Result<(), String> {
            let status = child.wait(until)?;
            if !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP {
                return Err(format!(
                    "expected initial TRACEME stop, wait_status={status}"
                ));
            }
            trace(
                PTRACE_SETOPTIONS,
                pid,
                0,
                (PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC) as usize,
            )?;
            let mut pending: Option<user_regs_struct> = None;
            let mut phase = 0;
            let mut execs = 0;
            let mut before_ok = false;
            let mut after_ok = false;
            loop {
                trace(PTRACE_SYSCALL, pid, 0, 0)?;
                let status = child.wait(until)?;
                if WIFEXITED(status) || WIFSIGNALED(status) {
                    report["wait_status"] = json!(status);
                    if WIFEXITED(status) {
                        report["child_exit_code"] = json!(WEXITSTATUS(status));
                    }
                    if status != 0
                        || phase != 2
                        || pending.is_some()
                        || !after_ok
                        || (mode == 0 && !before_ok)
                        || execs != usize::from(mode == 2)
                    {
                        return Err(
                            "child/protocol/pathname self-check failed (see exit-code legend)"
                                .into(),
                        );
                    }
                    return Ok(());
                }
                if !WIFSTOPPED(status) {
                    return Err(format!("unexpected wait_status={status}"));
                }
                if status >> 16 == PTRACE_EVENT_EXEC {
                    execs += 1;
                    report["exec_events"] = json!(execs);
                    continue;
                }
                if WSTOPSIG(status) != (SIGTRAP | 0x80) {
                    return Err(format!("unexpected stop signal={}", WSTOPSIG(status)));
                }
                // Kernel op identifies entry/exit; exec and signals cannot desync a toggle.
                let mut info = [0u64; 11];
                let n = trace(GET_SYSCALL_INFO, pid, 88, info.as_mut_ptr() as usize)?;
                if n < 24 {
                    return Err("short PTRACE_GET_SYSCALL_INFO".into());
                }
                if info[0] >> 32 != 0xc000003e {
                    return Err("unexpected syscall architecture (requires native x86_64)".into());
                }
                let op = info[0] & 0xff;
                let mut regs: user_regs_struct = unsafe { zeroed() };
                trace(
                    PTRACE_GETREGS,
                    pid,
                    0,
                    (&mut regs as *mut user_regs_struct) as usize,
                )?;
                if op == 2 {
                    if let Some(saved) = pending.take() {
                        let ret = regs.rax as i64;
                        report["injection"] = json!({"prctl_return": ret,
                            "child_memory_reads_for_injection": 0, "code_patched": false});
                        if ret != 0 || regs.rip != saved.rip {
                            return Err(
                                "injected prctl failed or instruction pointer changed".into()
                            );
                        }
                        // Preserve exit flags/rcx/r11; restore only changed syscall registers.
                        regs.orig_rax = saved.orig_rax;
                        regs.rdi = saved.rdi;
                        regs.rsi = saved.rsi;
                        regs.rdx = saved.rdx;
                        regs.r10 = saved.r10;
                        regs.r8 = saved.r8;
                        regs.r9 = saved.r9;
                        regs.rax = pid as u64; // genuine getpid semantics in this PID namespace
                        trace(
                            PTRACE_SETREGS,
                            pid,
                            0,
                            (&regs as *const user_regs_struct) as usize,
                        )?;
                        report["injection"]["getpid_return_restored"] = json!(true);
                    }
                    continue;
                }
                if op != 1 {
                    return Err(format!("unexpected syscall stop op={op}"));
                }
                if regs.orig_rax != SYS_getpid as u64 || regs.rdi != MAGIC {
                    continue;
                }
                if regs.rsi != phase
                    || phase > 1
                    || regs.r10 != (if mode == 0 { 0 } else { 1234 })
                    || (mode != 0 && regs.r9 != 1234)
                {
                    return Err("invalid slot sequence or real credentials".into());
                }
                let (mem, matched) = memory(pid, regs.rdx);
                let observation = json!({"getregs": true, "real_getuid": regs.r10,
                    "gid": regs.r9, "dumpable": regs.r8, "memory": mem});
                if phase == 0 {
                    before_ok = matched;
                    report["before"] = observation;
                    let mut injected = regs;
                    injected.orig_rax = SYS_prctl as u64;
                    injected.rdi = PR_SET_DUMPABLE as u64;
                    injected.rsi = 1;
                    injected.rdx = 0;
                    injected.r10 = 0;
                    injected.r8 = 0;
                    injected.r9 = 0;
                    trace(
                        PTRACE_SETREGS,
                        pid,
                        0,
                        (&injected as *const user_regs_struct) as usize,
                    )?;
                    pending = Some(regs);
                } else {
                    after_ok = matched && regs.r8 == 1;
                    report["after"] = observation;
                    report["memory_access_restored"] = json!(!before_ok && after_ok);
                    report["memory_access_already_available"] = json!(before_ok);
                }
                phase += 1;
            }
        })();
        report["cleanup"] = child.cleanup();
        match result {
            Ok(()) => report["status"] = json!("supported"),
            Err(e) => report["error"] = json!(e),
        }
        report
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if args.len() == 2 && args[1] == "--ptrace-child" {
            unsafe {
                verify(1234);
            }
        }
        if args.len() != 1 {
            println!(
                "{}",
                json!({"status": "usage", "command":
                "cargo +1.90.0 run --release --example ptrace_credentials"})
            );
            std::process::exit(2);
        }
        let setup = (|| -> Result<CString, String> {
            if unsafe { getuid() != 0 || geteuid() != 0 } {
                return Err("requires real/effective root".into());
            }
            let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
            for key in ["CapEff:", "CapPrm:"] {
                let bits = status
                    .lines()
                    .find_map(|line| line.strip_prefix(key))
                    .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
                    .ok_or("cannot read capabilities")?;
                if bits & (1 << 19) != 0 {
                    return Err(format!("{key} contains CAP_SYS_PTRACE; run without it"));
                }
            }
            if std::fs::read_dir("/proc/self/task")
                .map_err(|e| e.to_string())?
                .count()
                != 1
            {
                return Err("requires single-threaded process".into());
            }
            // Disable inherited auto-reaping, so only our waits can release the PID.
            unsafe {
                let mut action: sigaction = zeroed();
                action.sa_sigaction = SIG_DFL;
                sigemptyset(&mut action.sa_mask);
                if sigaction(SIGCHLD, &action, ptr::null_mut()) != 0 {
                    return Err(format!("sigaction errno={}", errno()));
                }
            }
            use std::os::unix::ffi::OsStrExt;
            CString::new(
                std::env::current_exe()
                    .map_err(|e| e.to_string())?
                    .as_os_str()
                    .as_bytes(),
            )
            .map_err(|e| e.to_string())
        })();
        let exe = match setup {
            Ok(exe) => exe,
            Err(e) => {
                println!("{}", json!({"status": "unsupported", "reason": e}));
                std::process::exit(1);
            }
        };
        let mut ok = true;
        for mode in 0..3 {
            let report = scenario(mode, &exe);
            ok &= report["status"] == "supported";
            println!("{report}");
        }
        println!(
            "{}",
            json!({"all_required_supported": ok, "cap_sys_ptrace": false,
            "scope": "trusted single-threaded child; no namespaces, apt, seccomp notification, or executor integration",
            "warning": "Restoring dumpability changes process introspection behavior; this is not isolation/security",
            "child_exit_codes": {"20": "TRACEME failed", "21": "initial stop failed",
                "22": "real setgroups/setgid/setuid failed", "23": "execve failed",
                "24": "real/effective/saved credentials or groups mismatch", "25": "getuid/dumpable failed",
                "26": "getpid return semantics not restored", "27": "dumpability not restored"}})
        );
        std::process::exit(if ok { 0 } else { 1 });
    }
}
