//! Read-only observations, not a test or promise of kernel enforcement.
use serde_json::{Value, json};

pub fn inspect() -> Value {
    #[cfg(target_os = "linux")]
    {
        linux::inspect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        json!({"supported": false, "platform": std::env::consts::OS,
        "reason": "capability inspection requires Linux"})
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{ffi::CString, fs, os::unix::fs::FileTypeExt};

    fn read(path: &str) -> Value {
        match fs::read_to_string(path) {
            Ok(text) => json!({"value": text.trim_end()}),
            Err(error) => json!({"value": null, "error": error.to_string()}),
        }
    }

    fn writable(path: &str) -> Value {
        let path_c = CString::new(path).unwrap();
        // faccessat observes effective-ID access; no file is opened for writing.
        let result = unsafe {
            libc::faccessat(
                libc::AT_FDCWD,
                path_c.as_ptr(),
                libc::W_OK,
                libc::AT_EACCESS,
            )
        };
        if result == 0 {
            json!({"path": path, "access_w_ok": true})
        } else {
            json!({"path": path, "access_w_ok": false,
            "error": std::io::Error::last_os_error().to_string()})
        }
    }

    pub(super) fn inspect() -> Value {
        let status = fs::read_to_string("/proc/self/status");
        let mut fields = serde_json::Map::new();
        if let Ok(text) = &status {
            for line in text.lines() {
                if let Some((name, value)) = line.split_once(':')
                    && matches!(
                        name,
                        "Uid"
                            | "Gid"
                            | "Groups"
                            | "CapEff"
                            | "CapBnd"
                            | "Seccomp"
                            | "Seccomp_filters"
                            | "NoNewPrivs"
                    )
                {
                    fields.insert(name.to_owned(), json!(value.trim()));
                }
            }
        }
        let devices: Vec<Value> = [
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
            "/dev/fuse",
            "/dev/kvm",
            "/var/run/docker.sock",
        ]
        .iter()
        .map(|path| match fs::metadata(path) {
            Ok(meta) => json!({"path": path, "present": true,
                    "character_device": meta.file_type().is_char_device(),
                    "socket": meta.file_type().is_socket()}),
            Err(error) => json!({"path": path, "present": null, "error": error.to_string()}),
        })
        .collect();
        json!({
            "supported": true, "platform": "linux", "read_only": true,
            "uid": unsafe { libc::getuid() }, "effective_uid": unsafe { libc::geteuid() },
            "status": fields, "status_error": status.err().map(|e| e.to_string()),
            "apparmor_current": read("/proc/self/attr/current"),
            "mountinfo": read("/proc/self/mountinfo"),
            "devices": devices, "cgroup_membership": read("/proc/self/cgroup"),
            "cgroup_access_observations": [writable("/sys/fs/cgroup"),
                writable("/sys/fs/cgroup/cgroup.procs"), writable("/sys/fs/cgroup/cgroup.subtree_control")],
            "limitations": ["No mounts, namespaces, device creation or cgroup writes attempted.",
                "Access checks on conventional cgroup paths do not establish delegation or enforcement; membership may resolve elsewhere.",
                "Capability bits and security labels do not prove that a syscall will succeed."]
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspection_is_structured() {
        let result = super::inspect();
        assert_eq!(result["supported"], cfg!(target_os = "linux"));
        assert!(result["platform"].is_string());
    }
}
