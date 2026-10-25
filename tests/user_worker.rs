#![cfg(target_os = "linux")]

use rpweld::user::{resolve_user, validate_user_spec};
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Output},
};

fn accounts(root: &Path) {
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(root.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\napp:x:1234:2345::/home/app:/bin/sh\nnobody:x:65534:65534::/:/bin/sh\n").unwrap();
    fs::write(
        root.join("etc/group"),
        "root:x:0:\napp:x:2345:\nextra:x:3456:app\nother:x:4567:root,app\n",
    )
    .unwrap();
}

#[test]
fn resolver_names_numbers_groups_and_defaults() {
    let root = tempfile::tempdir().unwrap();
    accounts(root.path());
    for spec in ["app", "1234", "001234"] {
        let user = resolve_user(root.path(), spec).unwrap();
        assert_eq!((user.uid, user.gid), (1234, 2345));
        assert_eq!(user.supplementary_gids, [3456, 4567]);
        assert_eq!(user.home, "/home/app");
    }
    for spec in ["app:extra", "1234:3456", "1234:extra", "app:3456"] {
        let user = resolve_user(root.path(), spec).unwrap();
        assert_eq!((user.uid, user.gid), (1234, 3456));
        assert!(user.supplementary_gids.is_empty());
    }
    let unknown = resolve_user(root.path(), "9876").unwrap();
    assert_eq!(
        (unknown.uid, unknown.gid, unknown.home.as_str()),
        (9876, 0, "/")
    );
    assert!(resolve_user(root.path(), "missing").is_err());
    assert!(resolve_user(root.path(), "app:missing").is_err());
    assert!(
        resolve_user(root.path(), "")
            .unwrap()
            .supplementary_gids
            .is_empty()
    );
    assert_eq!(
        resolve_user(root.path(), "root")
            .unwrap()
            .supplementary_gids,
        [4567]
    );
    for bad in [
        "-1",
        "+1",
        "2147483648",
        "4294967295",
        ":1",
        "app:",
        "a:b:c",
        "a b",
        "a\0",
        "a/b",
    ] {
        assert!(validate_user_spec(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn resolver_confines_symlinks_and_bounds_account_data() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    accounts(root.path());
    fs::rename(root.path().join("etc/passwd"), root.path().join("accounts")).unwrap();
    symlink("/accounts", root.path().join("etc/passwd")).unwrap();
    assert_eq!(resolve_user(root.path(), "app").unwrap().uid, 1234);
    fs::remove_file(root.path().join("etc/passwd")).unwrap();
    symlink("../../../../etc/passwd", root.path().join("etc/passwd")).unwrap();
    assert!(resolve_user(root.path(), "root").is_err()); // loops inside image, never host /etc/passwd
    fs::remove_file(root.path().join("etc/passwd")).unwrap();
    let passwd = root.path().join("etc/passwd");
    fs::write(&passwd, b"app:x:1234:1::/bad\xff:/bin/sh\n").unwrap();
    assert!(
        resolve_user(root.path(), "app")
            .unwrap_err()
            .contains("UTF-8")
    );
    fs::write(&passwd, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    assert!(
        resolve_user(root.path(), "1234")
            .unwrap_err()
            .contains("1 MiB")
    );
    fs::write(
        &passwd,
        "app:x:1234:1::/home:/bin/sh\napp:x:1234:1::/home:/bin/sh\n",
    )
    .unwrap();
    assert!(
        resolve_user(root.path(), "app")
            .unwrap_err()
            .contains("ambiguous")
    );
    fs::write(
        &passwd,
        format!("app:x:1234:1::/{}:/bin/sh\n", "h".repeat(4096)),
    )
    .unwrap();
    assert!(
        resolve_user(root.path(), "app")
            .unwrap_err()
            .contains("HOME")
    );
    fs::remove_file(&passwd).unwrap();
    fs::create_dir(&passwd).unwrap();
    assert!(
        resolve_user(root.path(), "app")
            .unwrap_err()
            .contains("regular file")
    );
    fs::remove_dir(&passwd).unwrap();
    let name = std::ffi::CString::new(passwd.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(
        resolve_user(root.path(), "app")
            .unwrap_err()
            .contains("regular file")
    );
}

#[test]
fn account_lookup_preserves_regular_file_and_directory_timestamps() {
    let root = tempfile::tempdir().unwrap();
    accounts(root.path());
    let paths = [
        root.path().to_owned(),
        root.path().join("etc"),
        root.path().join("etc/passwd"),
        root.path().join("etc/group"),
    ];
    let times = [
        libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        },
    ];
    let stamp = |path: &Path| {
        let m = fs::metadata(path).unwrap();
        (
            m.atime(),
            m.atime_nsec(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    for path in &paths {
        let p = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), times.as_ptr(), 0) },
            0
        );
    }
    let before: Vec<_> = paths.iter().map(|p| stamp(p)).collect();
    assert_eq!(resolve_user(root.path(), "app").unwrap().uid, 1234);
    assert_eq!(before, paths.iter().map(|p| stamp(p)).collect::<Vec<_>>());
}

const PROBE: &str = r#"
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  const char *mode = argc > 2 ? argv[2] : "exec-child";
  uid_t r,e,s; gid_t gr,ge,gs; gid_t groups[65536];
  if (getresuid(&r,&e,&s) || getresgid(&gr,&ge,&gs)) return 20;
  int n = getgroups(65536, groups); if(n < 0) return 21;
  printf("ids=%u,%u,%u:%u,%u,%u HOME=%s groups=",r,e,s,gr,ge,gs,getenv("HOME"));
  for(int i=0;i<n;i++) printf("%u,",groups[i]); puts(""); fflush(stdout);
  struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
  struct __user_cap_data_struct caps[2]={0};
  if (syscall(SYS_capget,&h,caps)) return 22;
  if(r && (caps[0].effective || caps[1].effective || caps[0].permitted || caps[1].permitted || caps[0].inheritable || caps[1].inheritable)) return 23;
  if(r && (setuid(0) != -1 || errno != EPERM)) return 24;
  int nullfd=open("/dev/null",O_WRONLY); if(nullfd<0) {perror("open dev null"); return 25;} close(nullfd);
  int procfd=open("/proc/self/status",O_RDONLY); if(procfd<0) {perror("open proc status"); return 26;} close(procfd);
  if(!strcmp(mode,"exec-child")) return 0;
  int f=open("/out/owned",O_CREAT|O_WRONLY,0644); if(f<0) {perror("owned");return 27;} close(f);
  int protected=open("/protected",O_WRONLY);
  if(r && protected>=0) return 28;
  if(!r && protected<0) return 29;
  if(protected>=0)close(protected);
  int groupfd=open("/group-file",O_RDONLY);
  printf("group-access=%d\n",groupfd>=0); fflush(stdout); if(groupfd>=0)close(groupfd);
  pid_t child=fork(); if(child<0)return 30;
  if(!child){execl("/bin/sh","sh",NULL);_exit(31);}
  int status; if(waitpid(child,&status,0)<0 || status!=0)return 32;
  puts("APP_SENTINEL"); return 0;
}
"#;

struct Fixture {
    _temp: tempfile::TempDir,
    root: std::path::PathBuf,
    state: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0, "runtime test requires root");
        let temp = tempfile::Builder::new()
            .prefix("weld-user-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("out")).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(root.join("out"), fs::Permissions::from_mode(0o777)).unwrap();
        accounts(&root);
        fs::write(root.join("protected"), "root only").unwrap();
        fs::set_permissions(root.join("protected"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(root.join("group-file"), "group only").unwrap();
        let groupfile =
            std::ffi::CString::new(root.join("group-file").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(groupfile.as_ptr(), 0, 3456) }, 0);
        fs::set_permissions(root.join("group-file"), fs::Permissions::from_mode(0o640)).unwrap();
        let source = temp.path().join("probe.c");
        fs::write(&source, PROBE).unwrap();
        let output = Command::new("cc")
            .args(["-static", "-O2", "-o"])
            .arg(root.join("bin/sh"))
            .arg(source)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            _temp: temp,
            root,
            state,
        }
    }
    fn command(&self, user: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        cmd.arg("__trace-worker")
            .arg(&self.root)
            .arg(&self.state)
            .args(["10", "probe", "--clear-env"]);
        if !user.is_empty() {
            cmd.args(["--user", user]);
        }
        cmd
    }
}

fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "status {:?}\nstdout {}\nstderr {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

// Remove privileges in the fresh worker executable, never in the test/builder.
fn drop_caps(cmd: &mut Command, bits: u64) {
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut h = [0x20080522u32, 0];
            let mut caps = [0u32; 6];
            if libc::syscall(libc::SYS_capget, h.as_mut_ptr(), caps.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (i, cap) in caps.iter_mut().enumerate() {
                *cap &= !((bits >> (if i < 3 { 0 } else { 32 })) as u32);
            }
            if libc::syscall(libc::SYS_capset, h.as_ptr(), caps.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[test]
#[ignore = "requires Linux root, cc -static, chroot and child ptrace"]
fn real_nonroot_initial_path_exec_and_fresh_root() {
    let f = Fixture::new();
    let mut cmd = f.command("app");
    drop_caps(&mut cmd, (1 << 19) | (1 << 21));
    let out = success(&cmd.output().unwrap());
    assert!(
        out.contains("ids=1234,1234,1234:2345,2345,2345 HOME=/home/app groups=3456,4567,"),
        "{out}"
    );
    assert!(out.contains("group-access=1"));
    assert!(out.contains("APP_SENTINEL"));
    let metadata = fs::metadata(f.root.join("out/owned")).unwrap();
    assert_eq!((metadata.uid(), metadata.gid()), (1234, 2345));
    fs::remove_file(f.root.join("out/owned")).unwrap();
    let out = success(&f.command("app:2345").output().unwrap());
    assert!(out.contains("group-access=0"), "{out}");
    fs::remove_file(f.root.join("out/owned")).unwrap();
    let out = success(&f.command("").output().unwrap());
    assert!(
        out.contains("ids=0,0,0:0,0,0 HOME=/root groups=\n"),
        "{out}"
    );
    assert_eq!(fs::metadata(f.root.join("out/owned")).unwrap().uid(), 0);
}

#[test]
#[ignore = "requires Linux root, cc -static, chroot and child ptrace"]
fn home_fallback_explicit_values_and_account_changes() {
    let f = Fixture::new();
    for (user, home, expected) in [
        ("app", None, "/home/app"),
        ("9876", None, "/"),
        ("app", Some(""), "/home/app"),
        ("app", Some("/explicit"), "/explicit"),
    ] {
        let mut cmd = f.command(user);
        if let Some(home) = home {
            cmd.args(["--env", &format!("HOME={home}")]);
        }
        let out = success(&cmd.output().unwrap());
        assert!(out.contains(&format!("HOME={expected} ")), "{out}");
        fs::remove_file(f.root.join("out/owned")).unwrap();
    }
    fs::write(
        f.root.join("etc/passwd"),
        "app:x:6789:7890::/changed:/bin/sh\n",
    )
    .unwrap();
    let out = success(&f.command("app").output().unwrap());
    assert!(
        out.contains("ids=6789,6789,6789:7890,7890,7890 HOME=/changed"),
        "{out}"
    );
    assert_eq!(fs::metadata(f.root.join("out/owned")).unwrap().uid(), 6789);
}

#[test]
#[ignore = "requires Linux root, cc -static, chroot and child ptrace"]
fn denied_credentials_never_execute_and_leave_no_children() {
    let f = Fixture::new();
    for (bits, user, expected) in [
        (1 << 7, "app", "setresuid"),
        (1 << 6, "app", "setgroups"),
        (1 << 6, "0:4567", "setresgid"),
    ] {
        let mut cmd = f.command(user);
        // Exact empty inherited groups allow the third case to reach setresgid.
        if user == "0:4567" {
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setgroups(0, std::ptr::null()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        drop_caps(&mut cmd, bits);
        let out = cmd.output().unwrap();
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(
            out.stdout.is_empty(),
            "application ran: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(!f.root.join("out/owned").exists());
    }
    let mut cmd = f.command("65534");
    unsafe {
        cmd.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(65534, 65534, 65534) != 0
                || libc::setresuid(65534, 65534, 65534) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires real and effective root"));
    assert!(out.stdout.is_empty());
    assert!(!f.root.join("out/owned").exists());
    // A process-scoped worker has no surviving tracees after any failed setup.
    let worker_children =
        fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id())).unwrap();
    assert!(
        worker_children.trim().is_empty(),
        "leaked children: {worker_children}"
    );
}

#[test]
#[ignore = "requires Linux root, cc -static, chroot and child ptrace"]
fn exact_root_identity_works_without_setuid_setgid_capabilities() {
    let f = Fixture::new();
    let mut cmd = f.command("");
    unsafe {
        cmd.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    drop_caps(&mut cmd, (1 << 6) | (1 << 7));
    assert!(success(&cmd.output().unwrap()).contains("APP_SENTINEL"));
}

#[test]
#[ignore = "requires Linux root, cc -static, chroot, ptrace and seccomp filters"]
fn denied_initial_dumpability_gate_never_executes_application() {
    let f = Fixture::new();
    let mut cmd = f.command("app");
    unsafe {
        cmd.pre_exec(|| {
            let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
            // Deny only prctl(PR_SET_DUMPABLE); all setup and tracing calls remain allowed.
            let mut filter = [
                instruction(0x20, 0, 0, 0),
                instruction(0x15, 0, 3, libc::SYS_prctl as u32),
                instruction(0x20, 0, 0, 16),
                instruction(0x15, 0, 1, libc::PR_SET_DUMPABLE as u32),
                instruction(0x06, 0, 0, 0x00050000 | libc::EPERM as u32),
                instruction(0x06, 0, 0, 0x7fff0000),
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_SECCOMP, 2, &program, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("PR_SET_DUMPABLE policy"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!f.root.join("out/owned").exists());
}
