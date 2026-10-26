//! Private release layout. Never discover transport executables through PATH/CWD.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

type Result<T> = std::result::Result<T, String>;

pub(super) struct Backend {
    bundle: Option<PathBuf>,
}

impl Backend {
    pub(super) fn discover() -> Result<Self> {
        Self::at(&std::env::current_exe().map_err(|e| e.to_string())?)
    }

    fn at(executable: &Path) -> Result<Self> {
        let root = executable
            .parent()
            .and_then(Path::parent)
            .ok_or("cannot locate registry backend")?
            .join("lib/rpweld");
        match fs::symlink_metadata(&root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self { bundle: None }),
            Err(e) => Err(e.to_string()),
            Ok(m) => {
                if !m.is_dir() || m.file_type().is_symlink() {
                    return Err("bundled registry backend must be a real directory".into());
                }
                // ld.so separates search paths with ':'; reject an ambiguous installation.
                if root.as_os_str().as_encoded_bytes().contains(&b':') {
                    return Err("bundle installation path must not contain ':'".into());
                }
                for name in [
                    "skopeo",
                    "ld-linux-x86-64.so.2",
                    "libc.so.6",
                    "policy.json",
                    "ca-certificates.crt",
                ] {
                    let m = fs::symlink_metadata(root.join(name))
                        .map_err(|_| "incomplete bundled registry backend")?;
                    if !m.is_file() || m.file_type().is_symlink() {
                        return Err("invalid bundled registry backend file".into());
                    }
                }
                Ok(Self { bundle: Some(root) })
            }
        }
    }

    pub(super) fn policy(&self) -> Result<PathBuf> {
        self.policy_at(Path::new("/etc/containers/policy.json"))
    }

    fn policy_at(&self, system: &Path) -> Result<PathBuf> {
        match fs::symlink_metadata(system) {
            Ok(_) => Ok(system.into()), // Opening/validation must fail closed, even for dangling links.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(self
                .bundle
                .as_ref()
                .map_or_else(|| system.to_path_buf(), |root| root.join("policy.json"))),
            Err(_) => Err("cannot inspect registry signature policy".into()),
        }
    }

    pub(super) fn command(
        &self,
        lease: Option<&crate::store_lease::StoreLease>,
    ) -> Result<Command> {
        let program = self.bundle.as_ref().map_or_else(
            || PathBuf::from("/usr/bin/skopeo"),
            |root| root.join("ld-linux-x86-64.so.2"),
        );
        if !program.is_file() {
            return Err(
                "registry backend missing: install the complete Weld package or Skopeo".into(),
            );
        }
        let mut cmd = if lease.is_some() {
            crate::lease_process::command(&program, lease).map_err(|e| e.to_string())?
        } else {
            Command::new(&program)
        };
        if let Some(root) = &self.bundle {
            cmd.args(["--inhibit-cache", "--library-path"])
                .arg(root)
                .arg(root.join("skopeo"));
        }
        Ok(cmd)
    }

    pub(super) fn configure(&self, cmd: &mut Command) -> Result<()> {
        cmd.arg("--policy").arg(self.policy()?);
        if let Some(root) = &self.bundle
            && std::env::var_os("SSL_CERT_FILE").is_none()
            && std::env::var_os("SSL_CERT_DIR").is_none()
            && !Path::new("/etc/ssl/certs/ca-certificates.crt").exists()
        {
            cmd.env("SSL_CERT_FILE", root.join("ca-certificates.crt"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundle_is_executable_relative_complete_and_never_masks_system_policy() {
        let temp = tempfile::tempdir().unwrap();
        let exe = temp.path().join("bin/rpweld");
        assert!(Backend::at(&exe).unwrap().bundle.is_none());
        let root = temp.path().join("lib/rpweld");
        fs::create_dir_all(&root).unwrap();
        assert!(Backend::at(&exe).is_err());
        for name in [
            "skopeo",
            "ld-linux-x86-64.so.2",
            "libc.so.6",
            "policy.json",
            "ca-certificates.crt",
        ] {
            fs::write(root.join(name), b"fixture").unwrap();
        }
        let backend = Backend::at(&exe).unwrap();
        let policy = temp.path().join("system-policy");
        assert_eq!(
            backend.policy_at(&policy).unwrap(),
            root.join("policy.json")
        );
        std::os::unix::fs::symlink("absent", &policy).unwrap();
        assert_eq!(backend.policy_at(&policy).unwrap(), policy);
        let cmd = backend.command(None).unwrap();
        assert_eq!(cmd.get_program(), root.join("ld-linux-x86-64.so.2"));
        assert_eq!(cmd.get_args().last().unwrap(), root.join("skopeo"));
        fs::remove_file(root.join("skopeo")).unwrap();
        std::os::unix::fs::symlink("missing", root.join("skopeo")).unwrap();
        assert!(Backend::at(&exe).is_err());
    }
}
