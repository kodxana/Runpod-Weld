//! Experimental Linux x86_64 feasibility probe, NOT a sandbox or apt broker.
//! Run as root: cargo +1.90.0 run --release --example seccomp_probe
//! Optional diagnostic: append -- --proc-mem-fscreds (default: process_vm_readv).
//! proc status columns: https://www.kernel.org/doc/html/latest/filesystems/proc.html
//! Access checks: https://github.com/torvalds/linux/blob/master/kernel/ptrace.c
//! mem open: https://github.com/torvalds/linux/blob/master/fs/proc/base.c
//! Single-threaded executable only: the post-fork path uses stack data and libc,
//! no Rust allocation, formatting, unwinding, or destructors before exec/_exit.
//! UAPI: https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h
//! Semantics: https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
//! shortcut: fixed x86_64 ABI sizes are checked; extend before supporting other ABIs.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("{{\"status\":\"unsupported\",\"reason\":\"requires Linux x86_64\"}}");
    std::process::exit(1);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    linux::run();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use libc::*;
    use std::{
        ffi::CString,
        io::Read,
        mem::{size_of, size_of_val, zeroed},
        ptr,
        time::{Duration, Instant},
    };
    const MAGIC: i32 = -4242;
    const PATH: &[u8] = b"/dev/null\0";
    const FLAGS: i32 = O_RDWR | O_CLOEXEC;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 8;
    const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;
    const RECV: c_ulong = 0xc0502100; // _IOWR('!', 0, seccomp_notif)
    const SEND: c_ulong = 0xc0182101; // _IOWR('!', 1, seccomp_notif_resp)
    const ADDFD: c_ulong = 0x40182103; // _IOW ('!', 3, seccomp_notif_addfd)
    #[repr(C)]
    #[derive(Default)]
    struct Data {
        nr: i32,
        arch: u32,
        ip: u64,
        args: [u64; 6],
    }
    #[repr(C)]
    #[derive(Default)]
    struct Notif {
        id: u64,
        pid: u32,
        flags: u32,
        data: Data,
    }
    #[repr(C)]
    struct Response {
        id: u64,
        val: i64,
        error: i32,
        flags: u32,
    }
    #[repr(C)]
    struct AddFd {
        id: u64,
        flags: u32,
        srcfd: u32,
        newfd: u32,
        newfd_flags: u32,
    }
    // Packets: stage (0=success, 10..=failure), errno, dumpable, uid.
    fn errno() -> i32 {
        unsafe { *__errno_location() }
    }
    unsafe fn packet(sock: i32, stage: i32, error: i32) {
        unsafe {
            let p = [stage, error, prctl(PR_GET_DUMPABLE), getuid() as i32];
            send(sock, p.as_ptr().cast(), size_of_val(&p), MSG_NOSIGNAL);
        }
    }
    unsafe fn fail(sock: i32, stage: i32) -> ! {
        unsafe {
            packet(sock, stage, errno());
            _exit(stage);
        }
    }
    unsafe fn verify(sock: i32) -> ! {
        unsafe {
            let fd = syscall(SYS_openat, MAGIC as c_long, PATH.as_ptr(), FLAGS, 0) as i32;
            if fd < 0 {
                fail(sock, 20);
            }
            let mut st: stat = zeroed();
            let mut byte = 42u8;
            let ok = fstat(fd, &mut st) == 0
                && st.st_mode & S_IFMT == S_IFCHR
                && major(st.st_rdev) == 1
                && minor(st.st_rdev) == 3
                && fcntl(fd, F_GETFD) == FD_CLOEXEC
                && read(fd, (&mut byte as *mut u8).cast(), 1) == 0
                && write(fd, (&byte as *const u8).cast(), 1) == 1;
            close(fd);
            packet(sock, if ok { 0 } else { 21 }, if ok { 0 } else { errno() });
            _exit(if ok { 0 } else { 21 });
        }
    }
    fn ins(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
        sock_filter { code, jt, jf, k }
    }
    unsafe fn child(sock: i32, drop_uid: bool, exec: bool, exe: &CString, fdarg: &CString) -> ! {
        unsafe {
            signal(SIGALRM, SIG_DFL);
            alarm(12); // Survives exec; parent also bounds every protocol wait.
            let mut filter = [
                ins(0x20, 0, 0, 4), // seccomp_data.arch
                ins(0x15, 0, 5, 0xc000003e),
                ins(0x20, 0, 0, 0), // nr: exact native openat, excludes x32
                ins(0x15, 0, 3, SYS_openat as u32),
                ins(0x20, 0, 0, 16), // low 32 bits of dirfd (an int)
                ins(0x15, 0, 1, MAGIC as u32),
                ins(0x06, 0, 0, 0x7fc00000), // USER_NOTIF
                ins(0x06, 0, 0, 0x7fff0000), // ALLOW
            ];
            let prog = sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                fail(sock, 10);
            }
            let listener = syscall(SYS_seccomp, 1, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog) as i32;
            if listener < 0 {
                fail(sock, 11);
            }
            let mut control = [0usize; 3]; // aligned CMSG_SPACE(sizeof(int)) = 24
            let mut byte = 0u8;
            let mut iov = iovec {
                iov_base: (&mut byte as *mut u8).cast(),
                iov_len: 1,
            };
            let mut msg: msghdr = zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = 24;
            let c = CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = SOL_SOCKET;
            (*c).cmsg_type = SCM_RIGHTS;
            (*c).cmsg_len = CMSG_LEN(4) as usize;
            ptr::write(CMSG_DATA(c).cast::<i32>(), listener);
            if sendmsg(sock, &msg, MSG_NOSIGNAL) != 1 {
                fail(sock, 12);
            }
            close(listener);
            if drop_uid
                && (setgroups(0, ptr::null()) != 0 || setgid(1234) != 0 || setuid(1234) != 0)
            {
                fail(sock, 13);
            }
            if exec {
                let argv = [
                    exe.as_ptr(),
                    c"--probe-child".as_ptr(),
                    fdarg.as_ptr(),
                    ptr::null(),
                ];
                let env = [ptr::null::<c_char>()];
                execve(exe.as_ptr(), argv.as_ptr(), env.as_ptr());
                fail(sock, 14);
            }
            verify(sock);
        }
    }
    extern "C" fn timeout(_: i32) {}
    fn poll_in(fd: i32) -> Result<(), String> {
        let mut p = pollfd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        if unsafe { poll(&mut p, 1, 3000) } > 0 && p.revents & POLLIN != 0 {
            Ok(())
        } else {
            Err(format!(
                "poll timeout/closed/error: revents={} errno={}",
                p.revents,
                errno()
            ))
        }
    }
    unsafe fn receive_listener(sock: i32) -> Result<i32, String> {
        unsafe {
            poll_in(sock)?;
            let mut p = [0i32; 4];
            let mut control = [0usize; 3];
            let mut iov = iovec {
                iov_base: p.as_mut_ptr().cast(),
                iov_len: 16,
            };
            let mut msg: msghdr = zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = 24;
            let n = recvmsg(sock, &mut msg, MSG_CMSG_CLOEXEC);
            let c = CMSG_FIRSTHDR(&msg);
            if n == 1
                && !c.is_null()
                && (*c).cmsg_level == SOL_SOCKET
                && (*c).cmsg_type == SCM_RIGHTS
                && (*c).cmsg_len == CMSG_LEN(4) as usize
            {
                return Ok(ptr::read(CMSG_DATA(c).cast::<i32>()));
            }
            Err(format!(
                "listener transfer failed: packet={p:?} recv={n} errno={}",
                errno()
            ))
        }
    }
    fn target_ids(status: &str, field: &str) -> Result<u32, String> {
        let mut lines = status.lines().filter_map(|line| line.strip_prefix(field));
        let line = lines.next().ok_or_else(|| format!("missing {field}"))?;
        if lines.next().is_some() {
            return Err(format!("duplicate {field}"));
        }
        let mut words = line.split_ascii_whitespace();
        let mut ids = [0u32; 4];
        for id in &mut ids {
            let word = words.next().ok_or_else(|| format!("short {field}"))?;
            if !word.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("invalid {field}"));
            }
            *id = word.parse().map_err(|_| format!("invalid {field}"))?;
            if *id == u32::MAX {
                return Err(format!("invalid sentinel in {field}"));
            }
        }
        if words.next().is_some() || ids[0] != ids[1] || ids[0] != ids[2] {
            return Err(format!(
                "cannot match real/effective/saved {field}: {ids:?}"
            ));
        }
        // FSCREDS selects the caller's IDs, not the target's fourth (filesystem) column.
        Ok(ids[0])
    }
    fn proc_mem_path(pid: i32, address: u64, path: &mut [u8]) -> Result<(), String> {
        let offset = off_t::try_from(address).map_err(|_| "pathname address exceeds off_t")?;
        let mut status = String::new();
        std::fs::File::open(format!("/proc/{pid}/status"))
            .and_then(|f| f.take(16385).read_to_string(&mut status))
            .map_err(|e| format!("proc-mem-fscreds cannot read target status: {e}"))?;
        if status.len() > 16384 || !status.ends_with('\n') {
            return Err("proc-mem-fscreds target status exceeds bound or is incomplete".into());
        }
        let uid = target_ids(&status, "Uid:")?;
        let gid = target_ids(&status, "Gid:")?;
        let mem = CString::new(format!("/proc/{pid}/mem")).unwrap();
        unsafe {
            // Raw syscalls affect only this thread. No fallible Rust work or early returns
            // between switching and verification of restoration, even if either set fails.
            let old_gid = syscall(SYS_setfsgid, u32::MAX) as u32;
            let old_uid = syscall(SYS_setfsuid, u32::MAX) as u32;
            if old_gid == u32::MAX || old_uid == u32::MAX {
                return Err(
                    "proc-mem-fscreds unable to query previous filesystem credentials".into(),
                );
            }
            syscall(SYS_setfsgid, gid);
            syscall(SYS_setfsuid, uid);
            let actual_gid = syscall(SYS_setfsgid, u32::MAX) as u32;
            let actual_uid = syscall(SYS_setfsuid, u32::MAX) as u32;
            let matched = actual_gid == gid && actual_uid == uid;
            let fd = if matched {
                open(mem.as_ptr(), O_RDONLY | O_CLOEXEC)
            } else {
                -1
            };
            let open_error = errno();
            syscall(SYS_setfsuid, old_uid);
            syscall(SYS_setfsgid, old_gid);
            let restored_uid = syscall(SYS_setfsuid, u32::MAX) as u32;
            let restored_gid = syscall(SYS_setfsgid, u32::MAX) as u32;
            if restored_uid != old_uid || restored_gid != old_gid {
                if fd >= 0 {
                    close(fd);
                }
                // Never continue to another scenario/device open with uncertain credentials.
                let msg = b"{\"strategy\":\"proc-mem-fscreds\",\"status\":\"fatal\",\"reason\":\"filesystem credential restoration verification failed\"}\n";
                write(STDERR_FILENO, msg.as_ptr().cast(), msg.len());
                _exit(1);
            }
            if !matched {
                return Err(format!(
                    "proc-mem-fscreds unable to set fsuid/fsgid={uid}/{gid}; observed={actual_uid}/{actual_gid}; previous credentials restored"
                ));
            }
            if fd < 0 {
                return Err(format!(
                    "proc-mem-fscreds unable to open /proc/{pid}/mem errno={open_error} with fsuid/fsgid={uid}/{gid}; previous credentials restored; matching IDs do not bypass dumpability/LSM checks"
                ));
            }
            let count = pread(fd, path.as_mut_ptr().cast(), path.len(), offset);
            let read_error = if count < 0 { errno() } else { 0 };
            close(fd);
            if count != path.len() as isize {
                return Err(format!(
                    "proc-mem-fscreds unable to read complete pathname: pread bytes={count} errno={read_error}; previous credentials restored"
                ));
            }
        }
        Ok(())
    }
    #[cfg(test)]
    #[test]
    fn status_ids_require_four_valid_columns_and_matching_target_ids() {
        assert_eq!(
            target_ids("Uid:\t1234 1234 1234 99\n", "Uid:").unwrap(),
            1234
        );
        assert_eq!(target_ids("Gid:\t0 0 0 0\n", "Gid:").unwrap(), 0);
        for bad in [
            "",
            "Uid: 1 1 1\n",
            "Uid: 1 1 1 1 1\n",
            "Uid: 1 2 1 1\n",
            "Uid: 1 1 2 1\n",
            "Uid: -1 1 1 1\n",
            "Uid: +1 1 1 1\n",
            "Uid: 4294967296 1 1 1\n",
            "Uid: 1 1 1 4294967295\n",
            "Uid: 1 1 1 1\nUid: 1 1 1 1\n",
        ] {
            assert!(target_ids(bad, "Uid:").is_err(), "{bad:?}");
        }
    }
    unsafe fn broker(fd: i32, pid: i32, proc_mem_fscreds: bool) -> Result<i32, String> {
        unsafe {
            poll_in(fd)?;
            let mut n = Notif::default();
            alarm(3); // No SA_RESTART: bounds even a notification canceled after poll.
            let rc = ioctl(fd, RECV, &mut n);
            let error = errno();
            alarm(0);
            if rc != 0 {
                return Err(format!("NOTIF_RECV errno={error}"));
            }
            let result = (|| {
                if n.pid != pid as u32
                    || n.flags != 0
                    || n.data.arch != 0xc000003e
                    || n.data.nr != SYS_openat as i32
                    || n.data.args[0] as i32 != MAGIC
                    || n.data.args[2] != FLAGS as u64
                {
                    return Err("unexpected notification".into());
                }
                let mut path = [0u8; 10];
                if proc_mem_fscreds {
                    proc_mem_path(pid, n.data.args[1], &mut path)?;
                } else {
                    let local = iovec {
                        iov_base: path.as_mut_ptr().cast(),
                        iov_len: path.len(),
                    };
                    let remote = iovec {
                        iov_base: n.data.args[1] as *mut c_void,
                        iov_len: path.len(),
                    };
                    let read = process_vm_readv(pid, &local, 1, &remote, 1, 0);
                    if read != path.len() as isize {
                        return Err(format!(
                            "process_vm_readv bytes={read} errno={} (EACCES/EPERM means unsupported credentials/dumpability)",
                            errno()
                        ));
                    }
                }
                if path.as_slice() != PATH {
                    return Err("pathname is not exact /dev/null".into());
                }
                // Fresh open file description for this request; never create device nodes.
                let src = open(c"/dev/null".as_ptr(), FLAGS);
                if src < 0 {
                    return Err(format!("parent open errno={}", errno()));
                }
                let add = AddFd {
                    id: n.id,
                    flags: SECCOMP_ADDFD_FLAG_SEND,
                    srcfd: src as u32,
                    newfd: 0,
                    newfd_flags: (n.data.args[2] as i32 & O_CLOEXEC) as u32,
                };
                alarm(3);
                let injected = ioctl(fd, ADDFD, &add);
                let error = errno();
                alarm(0);
                close(src);
                if injected < 0 {
                    Err(format!("ADDFD atomic SEND errno={error}"))
                } else {
                    Ok(injected)
                }
            })();
            if result.is_err() {
                let deny = Response {
                    id: n.id,
                    val: 0,
                    error: -EACCES,
                    flags: 0,
                };
                alarm(3);
                let rc = ioctl(fd, SEND, &deny);
                let error = errno();
                alarm(0);
                if rc < 0 {
                    return Err(format!(
                        "{}; explicit denial failed errno={error}",
                        result.unwrap_err()
                    ));
                }
            }
            result
        }
    }
    unsafe fn reap(pid: i32) -> Option<i32> {
        unsafe {
            let until = Instant::now() + Duration::from_secs(3);
            let mut status = 0;
            loop {
                let r = waitpid(pid, &mut status, WNOHANG);
                if r == pid {
                    return Some(status);
                }
                if r < 0 && errno() != EINTR {
                    return None;
                }
                if Instant::now() >= until {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            kill(pid, SIGKILL);
            // SIGKILL wakes a child blocked on USER_NOTIF. Bound the final reap too.
            alarm(3);
            let r = waitpid(pid, &mut status, 0);
            alarm(0);
            if r == pid { Some(status) } else { None }
        }
    }
    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--probe-child") {
            let fd = args
                .get(2)
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(-1);
            if fd < 0 {
                std::process::exit(2);
            }
            unsafe {
                verify(fd);
            }
        }
        let proc_mem_fscreds = match args.get(1).map(String::as_str) {
            None => false,
            Some("--proc-mem-fscreds") if args.len() == 2 => true,
            _ => {
                eprintln!("usage: seccomp_probe [--proc-mem-fscreds]");
                std::process::exit(2);
            }
        };
        let strategy = if proc_mem_fscreds {
            "proc-mem-fscreds"
        } else {
            "process_vm_readv"
        };
        unsafe {
            let mut action: sigaction = zeroed();
            action.sa_sigaction = timeout as *const () as usize;
            sigemptyset(&mut action.sa_mask);
            if sigaction(SIGALRM, &action, ptr::null_mut()) != 0 {
                std::process::exit(1);
            }
            let mut sizes = [0u16; 3];
            let abi_ok = size_of::<Notif>() == 80
                && size_of::<Response>() == 24
                && size_of::<AddFd>() == 24
                && syscall(SYS_seccomp, 3, 0, sizes.as_mut_ptr()) == 0
                && sizes == [80, 24, 64];
            let exe = std::env::current_exe().ok().and_then(|p| {
                use std::os::unix::ffi::OsStrExt;
                CString::new(p.as_os_str().as_bytes()).ok()
            });
            let mut all_ok = true;
            for (name, drop_uid, exec) in [
                ("root", false, false),
                ("uid1234_no_exec", true, false),
                ("uid1234_exec", true, true),
                ("root_exec", false, true),
            ] {
                let mut listener = -1;
                let mut sockets = [-1; 2];
                let mut pid = -1;
                let mut child_packet = [-1i32; 4];
                let result = (|| -> Result<i32, String> {
                    if !abi_ok {
                        return Err(format!("unsupported seccomp ABI: {sizes:?}"));
                    }
                    if getuid() != 0 || geteuid() != 0 {
                        return Err("requires real/effective root".into());
                    }
                    let exe = exe.as_ref().ok_or("cannot resolve executable")?;
                    if socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets.as_mut_ptr()) != 0 {
                        return Err(format!("socketpair errno={}", errno()));
                    }
                    let fdarg = CString::new(sockets[1].to_string()).unwrap();
                    pid = fork();
                    if pid == 0 {
                        close(sockets[0]);
                        child(sockets[1], drop_uid, exec, exe, &fdarg);
                    }
                    close(sockets[1]);
                    sockets[1] = -1;
                    if pid < 0 {
                        return Err(format!("fork errno={}", errno()));
                    }
                    listener = receive_listener(sockets[0])?;
                    let outcome = broker(listener, pid, proc_mem_fscreds);
                    // Even a denial must return to the child and produce a result.
                    poll_in(sockets[0])?;
                    if recv(sockets[0], child_packet.as_mut_ptr().cast(), 16, 0) != 16 {
                        return Err(format!("missing child result; broker={outcome:?}"));
                    }
                    outcome
                })();
                if listener >= 0 {
                    close(listener);
                }
                for fd in sockets {
                    if fd >= 0 {
                        close(fd);
                    }
                }
                let status = if pid > 0 { reap(pid) } else { None };
                let ok = result.is_ok() && child_packet[0] == 0 && status == Some(0);
                all_ok &= ok;
                println!(
                    "{}",
                    serde_json::json!({"scenario": name,
                    "strategy": strategy,
                    "status": if ok { "supported" } else { "unsupported" },
                    "injected_fd": result.as_ref().ok(), "reason": result.err(),
                    "child_stage": child_packet[0], "child_errno": child_packet[1],
                    "dumpable": child_packet[2], "uid": child_packet[3], "wait_status": status})
                );
            }
            println!(
                "{}",
                serde_json::json!({"experimental": true, "all_required_supported": all_ok,
                "strategy": strategy,
                "scope": "single openat /dev/null per scenario; no mknod, library integration, or apt claim"})
            );
            std::process::exit(if all_ok { 0 } else { 1 });
        }
    }
}
