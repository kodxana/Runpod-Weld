//! Registry transport via the packaged Skopeo backend. TLS is mandatory.
//! State is private to the invoking Unix user; trusted, stable ancestry required.
//! No registry password is accepted in argv or forwarded to the build worker.
use std::path::PathBuf;

#[derive(Default)]
pub struct Options {
    pub authfile: Option<PathBuf>,
    pub cert_dir: Option<PathBuf>,
}

pub fn registry(raw: &str) -> Result<String, String> {
    let raw = match raw {
        "index.docker.io" | "registry-1.docker.io" => "docker.io",
        v => v,
    };
    let (host, port) = raw
        .split_once(':')
        .map_or((raw, None), |(h, p)| (h, Some(p)));
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|s| {
            s.is_empty()
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || s.starts_with('-')
                || s.ends_with('-')
        })
        || port.is_some_and(|p| {
            p.parse::<u16>().ok().filter(|n| *n != 0).is_none()
                || !p.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err("expected a registry hostname with optional port, without scheme, path or credentials (IPv6 literals unsupported)".into());
    }
    Ok(raw.into())
}

/// Normalize short names explicitly: never consult registry search/mirror rules.
pub fn reference(raw: &str, allow_digest: bool) -> Result<String, String> {
    if raw.is_empty()
        || raw.len() > 512
        || !raw.is_ascii()
        || raw.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err("invalid image reference".into());
    }
    let (name, digest) = raw
        .split_once('@')
        .map_or((raw, None), |(n, d)| (n, Some(d)));
    if let Some(d) = digest
        && (!allow_digest
            || d.len() != 71
            || !d.starts_with("sha256:")
            || !d[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err(
            "only sha256 digest references are supported for pulls; output requires a tag".into(),
        );
    }
    let (host, path) = match name.split_once('/') {
        Some((h, p)) if h.contains('.') || h.contains(':') || h == "localhost" => (registry(h)?, p),
        _ => ("docker.io".to_owned(), name),
    };
    let (repo, tag) = path
        .rsplit_once(':')
        .map_or((path, None), |(r, t)| (r, Some(t)));
    if repo.split('/').any(|s| {
        s.is_empty()
            || !s.as_bytes()[0].is_ascii_alphanumeric()
            || !s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
            || !s
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    }) {
        return Err("invalid repository name; use lowercase repository components".into());
    }
    if let Some(t) = tag
        && (t.is_empty()
            || t.len() > 128
            || t.starts_with(['.', '-'])
            || !t
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
    {
        return Err("invalid image tag".into());
    }
    let repo = if host == "docker.io" && !repo.contains('/') {
        format!("library/{repo}")
    } else {
        repo.into()
    };
    Ok(match digest {
        Some(d) => format!("{host}/{repo}@{d}"),
        None => format!("{host}/{repo}:{}", tag.unwrap_or("latest")),
    })
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::{
            fd::{AsFd, AsRawFd},
            unix::{
                fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
                process::CommandExt,
            },
        },
        path::{Component, Path},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    type Result<T> = std::result::Result<T, String>;
    const AUTH_CAP: u64 = 1024 * 1024;

    fn err(e: impl std::fmt::Display) -> String {
        e.to_string()
    }
    pub fn private_dir(path: &Path) -> Result<PathBuf> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err("state directory must be an absolute path without dot components".into());
        }
        let mut p = PathBuf::new();
        for part in path.components() {
            p.push(part);
            match fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => (),
                Ok(_) => {
                    return Err("state paths must contain real directories, not symlinks".into());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    match fs::DirBuilder::new().mode(0o700).create(&p) {
                        Ok(()) => (),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            let m = fs::symlink_metadata(&p).map_err(err)?;
                            if !m.is_dir() || m.file_type().is_symlink() {
                                return Err(
                                    "state paths must contain real directories, not symlinks"
                                        .into(),
                                );
                            }
                        }
                        Err(e) => return Err(err(e)),
                    }
                }
                Err(e) => return Err(err(e)),
            }
        }
        let m = fs::metadata(path).map_err(err)?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(format!(
                "{} must be owned by this user with mode 0700",
                path.display()
            ));
        }
        Ok(path.into())
    }
    fn home() -> Result<PathBuf> {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or("HOME must be an absolute directory".into())
    }
    pub fn store_dir() -> Result<PathBuf> {
        let path = std::env::var_os("RPWELD_HOME")
            .map(PathBuf::from)
            .unwrap_or(home()?.join(".local/share/rpweld"));
        private_dir(&path)
    }
    pub fn auth_path(options: &Options) -> Result<PathBuf> {
        match &options.authfile {
            Some(p) => {
                let p = std::path::absolute(p).map_err(err)?;
                let parent = p.parent().ok_or("invalid authfile path")?;
                // Do not create or chmod caller-owned CI directories.
                let parent = fs::canonicalize(parent).map_err(err)?;
                Ok(parent.join(p.file_name().ok_or("invalid authfile name")?))
            }
            None => Ok(private_dir(&home()?.join(".config/rpweld"))?.join("auth.json")),
        }
    }
    fn read_private(path: &Path, cap: u64) -> Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        let m = file.metadata().map_err(err)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
        {
            return Err("credential/state file must be a regular, singly-linked file owned by this user with mode 0600".into());
        }
        let mut bytes = Vec::new();
        file.take(cap + 1).read_to_end(&mut bytes).map_err(err)?;
        if bytes.len() as u64 > cap {
            return Err("credential/state file exceeds size limit".into());
        }
        Ok(Some(bytes))
    }
    fn lock(path: &Path) -> Result<File> {
        state_lock(path, None)
    }
    fn state_lock(path: &Path, cancel: Option<&dyn Fn() -> bool>) -> Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(err)?;
        let m = f.metadata().map_err(err)?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.nlink() != 1
            || m.mode() & 0o077 != 0
        {
            return Err("unsafe state lock".into());
        }
        let start = Instant::now();
        loop {
            if cancel.is_some_and(|c| c()) {
                return Err("base cache lock cancelled".into());
            }
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if cancel.is_none() {
                return Err(
                    "another Weld operation holds this state lock; retry after it finishes".into(),
                );
            }
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(err(error));
            }
            if start.elapsed() >= Duration::from_secs(930) {
                return Err("base cache lock timed out".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(f)
    }
    fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut f =
            tempfile::NamedTempFile::new_in(path.parent().ok_or("missing parent")?).map_err(err)?;
        f.write_all(bytes).map_err(err)?;
        f.as_file().sync_all().map_err(err)?;
        f.persist(path).map_err(err)?;
        File::open(path.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(err)
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BaseRecord {
        version: u32,
        reference: String,
        platform: String,
        source_digest: Option<String>,
        generation: String,
        selected: crate::oci::Descriptor,
    }

    /// Resolve a verified base without touching credentials on cache hits.
    /// Fetch writes only to disposable staging; published generations are immutable.
    pub fn cached_base(
        store: &Path,
        raw: &str,
        refresh_tags: bool,
        limits: crate::image::Limits,
        cancel: impl Fn() -> bool,
        fetch: impl FnOnce(&str, &Path) -> Result<()>,
    ) -> Result<PathBuf> {
        let reference = super::reference(raw, true)?;
        let source_digest = reference.split_once('@').map(|(_, d)| d.to_owned());
        let root = private_dir(&store.join("base-cache-v1"))?;
        let refs = private_dir(&root.join("refs"))?;
        let generations = private_dir(&root.join("generations"))?;
        let key = format!("{:x}", Sha256::digest(format!("{reference}\nlinux/amd64")));
        let record_path = refs.join(format!("{key}.json"));
        let _lock = state_lock(&refs.join(format!("{key}.lock")), Some(&cancel))?;
        if let Some(bytes) = read_private(&record_path, AUTH_CAP)? {
            let record: BaseRecord =
                serde_json::from_slice(&bytes).map_err(|_| "invalid base cache record")?;
            if record.version != 1
                || record.reference != reference
                || record.platform != "linux/amd64"
                || record.source_digest != source_digest
                || !record.generation.starts_with("gen-")
                || record.generation.len() > 128
                || !record
                    .generation
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err("invalid base cache identity or generation".into());
            }
            let layout = generations.join(&record.generation);
            let metadata =
                crate::image::load_layout(&layout, None, limits, &cancel).map_err(err)?;
            if metadata.selected != record.selected {
                return Err("base cache selected descriptor mismatch".into());
            }
            if !refresh_tags || source_digest.is_some() {
                return Ok(layout);
            }
        }
        if cancel() {
            return Err("base cache cancelled".into());
        }
        let staging = tempfile::Builder::new()
            .prefix("staging-")
            .tempdir_in(&root)
            .map_err(err)?;
        let download = staging.path().join("download");
        fetch(&reference, &download)?;
        let metadata = crate::image::load_layout(&download, None, limits, &cancel).map_err(err)?;
        let source = crate::oci::BlobStore::open(&download).map_err(err)?;
        let shared_root = private_dir(&root.join("content"))?;
        let shared = crate::oci::BlobStore::open(&shared_root).map_err(err)?;
        let generation = tempfile::Builder::new()
            .prefix("gen-")
            .tempdir_in(&generations)
            .map_err(err)?;
        let target = crate::oci::BlobStore::open(generation.path()).map_err(err)?;
        for (descriptor, cap) in [
            (&metadata.selected, limits.max_metadata_bytes),
            (&metadata.config_descriptor, limits.max_metadata_bytes),
        ]
        .into_iter()
        .chain(metadata.layers.iter().map(|d| (d, limits.max_layer_bytes)))
        {
            let file = source
                .open_verified(descriptor, cap, &cancel)
                .map_err(err)?;
            shared.ingest(file, descriptor, cap, &cancel).map_err(err)?;
            shared
                .link_verified(&target, descriptor, cap, &cancel)
                .map_err(err)?;
        }
        atomic_write(
            &generation.path().join("oci-layout"),
            b"{\"imageLayoutVersion\":\"1.0.0\"}",
        )?;
        atomic_write(&generation.path().join("index.json"), &serde_json::to_vec(
            &serde_json::json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json", "manifests":[metadata.selected]})
        ).map_err(err)?)?;
        let verified =
            crate::image::load_layout(generation.path(), None, limits, &cancel).map_err(err)?;
        if verified.selected != metadata.selected {
            return Err("base cache publication descriptor mismatch".into());
        }
        for path in [&shared_root, generation.path()] {
            for suffix in ["blobs/sha256", "blobs", ""] {
                File::open(path.join(suffix))
                    .and_then(|f| f.sync_all())
                    .map_err(err)?;
            }
        }
        File::open(&root).and_then(|f| f.sync_all()).map_err(err)?;
        File::open(store).and_then(|f| f.sync_all()).map_err(err)?;
        if cancel() {
            return Err("base cache cancelled".into());
        }
        // Keep before publishing: a failed record write may leave an unreferenced generation,
        // but can never remove a generation named by a durable reference.
        let layout = generation.keep();
        File::open(&generations)
            .and_then(|f| f.sync_all())
            .map_err(err)?;
        let record = BaseRecord {
            version: 1,
            reference,
            platform: "linux/amd64".into(),
            source_digest,
            generation: layout.file_name().unwrap().to_str().unwrap().into(),
            selected: metadata.selected,
        };
        let bytes = serde_json::to_vec(&record).map_err(err)?;
        if bytes.len() as u64 > AUTH_CAP {
            return Err("base cache record exceeds size limit".into());
        }
        atomic_write(&record_path, &bytes)?;
        Ok(layout)
    }

    pub fn check_cache_secret_paths(options: &Options, store: &Path) -> Result<()> {
        let auth = auth_path(options)?;
        let cert = options
            .cert_dir
            .as_ref()
            .map(fs::canonicalize)
            .transpose()
            .map_err(err)?;
        for area in [store.join("cache-v1"), store.join("base-cache-v1")] {
            if auth.starts_with(&area) || cert.as_ref().is_some_and(|p| p.starts_with(&area)) {
                return Err(
                    "registry credentials and certificates must be outside cache areas".into(),
                );
            }
        }
        Ok(())
    }

    pub struct Transport {
        temp: tempfile::TempDir,
        auth: PathBuf,
        cert: Option<PathBuf>,
    }
    impl Transport {
        pub fn new(options: &Options) -> Result<Self> {
            check_cache_secret_paths(options, &store_dir()?)?;
            let source = auth_path(options)?;
            let bytes = read_private(&source, AUTH_CAP)?.unwrap_or(b"{\"auths\":{}}".to_vec());
            // Parse only to validate shape. Never include parser input in errors.
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| "invalid authfile JSON")?;
            if !value.is_object() {
                return Err("authfile must be a JSON object".into());
            }
            if value.get("credsStore").is_some() {
                return Err(
                    "use per-registry credHelpers in the authfile; credsStore is unsupported"
                        .into(),
                );
            }
            if let Some(helpers) = value.get("credHelpers") {
                let helpers = helpers.as_object().ok_or("credHelpers must be an object")?;
                for (host, helper) in helpers {
                    super::registry(host)?;
                    let h = helper
                        .as_str()
                        .ok_or("credential helper name must be a string")?;
                    if h.is_empty()
                        || !h
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                    {
                        return Err("credential helper must be a program suffix, not a path".into());
                    }
                }
            }
            let temp = tempfile::Builder::new()
                .prefix(".rpweld-registry-")
                .tempdir_in(source.parent().ok_or("missing auth parent")?)
                .map_err(err)?;
            let auth = temp.path().join("auth.json");
            atomic_write(&auth, &bytes)?;
            // Hide Docker/containers fallback credentials and user mirror configuration.
            fs::create_dir(temp.path().join(".config")).map_err(err)?;
            fs::create_dir(temp.path().join(".config/containers")).map_err(err)?;
            fs::write(temp.path().join(".config/containers/registries.conf"),
                b"unqualified-search-registries = []\ncredential-helpers = [\"containers-auth.json\"]\n").map_err(err)?;
            Ok(Self {
                temp,
                auth,
                cert: options
                    .cert_dir
                    .as_ref()
                    .map(fs::canonicalize)
                    .transpose()
                    .map_err(err)?,
            })
        }
        fn command(&self) -> Result<Command> {
            // Never resolve an executable from a build context or a caller's PATH.
            let mut cmd = Command::new("/usr/bin/skopeo");
            if !Path::new("/usr/bin/skopeo").is_file() {
                return Err("registry backend missing: install the Weld Debian package (includes the Skopeo dependency)".into());
            }
            cmd.env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .env("HOME", self.temp.path())
                .env("XDG_CONFIG_HOME", self.temp.path().join(".config"))
                .env("XDG_RUNTIME_DIR", self.temp.path())
                .env("DOCKER_CONFIG", self.temp.path().join(".docker"));
            // Proxy and CA configuration is explicit operator configuration, never build ENV.
            for key in [
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "NO_PROXY",
                "http_proxy",
                "https_proxy",
                "no_proxy",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
                "DBUS_SESSION_BUS_ADDRESS",
                "GNUPGHOME",
            ] {
                if let Some(value) = std::env::var_os(key) {
                    cmd.env(key, value);
                }
            }
            cmd.args([
                "--command-timeout",
                "900s",
                "--override-os",
                "linux",
                "--override-arch",
                "amd64",
            ]);
            Ok(cmd)
        }
        fn run(
            &self,
            mut cmd: Command,
            password: Option<&[u8]>,
            input: bool,
            progress: bool,
            cancelled: &impl Fn() -> bool,
        ) -> Result<()> {
            cmd.process_group(0);
            cmd.stdin(if password.is_some() {
                Stdio::piped()
            } else if input {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stdout(if progress {
                // Skopeo copy's report stream contains transfer progress; diagnostics
                // remain on the separate, capped stderr pipe. Preserve TTY detection
                // for native layer bars, and use plain lines when redirected.
                Stdio::from(
                    std::io::stderr()
                        .as_fd()
                        .try_clone_to_owned()
                        .map_err(err)?,
                )
            } else {
                Stdio::null()
            });
            // Drain capped diagnostics without forwarding untrusted registry text/secrets.
            cmd.stderr(Stdio::piped());
            let mut child = cmd
                .spawn()
                .map_err(|_| "could not start packaged Skopeo backend")?;
            let stderr = child.stderr.take().unwrap();
            let reader = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let mut r = stderr;
                let mut buf = [0; 4096];
                while let Ok(n) = r.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if bytes.len() < 65536 {
                        bytes.extend_from_slice(&buf[..n.min(65536 - bytes.len())]);
                    }
                }
                bytes
            });
            if let Some(password) = password {
                let mut stdin = child.stdin.take().unwrap();
                if stdin
                    .write_all(password)
                    .and_then(|_| stdin.write_all(b"\n"))
                    .is_err()
                {
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err("could not deliver password to registry backend".into());
                }
            }
            let start = Instant::now();
            let status = loop {
                if cancelled() || start.elapsed() > Duration::from_secs(910) {
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(
                        "registry operation cancelled or timed out; local image retained".into(),
                    );
                }
                match child.try_wait() {
                    Ok(Some(s)) => break s,
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = reader.join();
                        return Err("registry process wait failed".into());
                    }
                }
            };
            // A helper must not leave descendants holding the diagnostic pipe.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let diagnostic =
                String::from_utf8_lossy(&reader.join().unwrap_or_default()).to_ascii_lowercase();
            if status.success() {
                return Ok(());
            }
            let reason = if diagnostic.contains("x509") || diagnostic.contains("certificate") {
                "TLS certificate verification failed; configure a trusted CA with --cert-dir"
            } else if diagnostic.contains("unauthorized")
                || diagnostic.contains("denied")
                || diagnostic.contains("authentication")
            {
                "registry rejected authentication or repository permissions; check login and token scope"
            } else if diagnostic.contains("manifest unknown") || diagnostic.contains("name unknown")
            {
                "image or tag not found"
            } else {
                "registry transfer failed; check connectivity, registry permissions and image compatibility"
            };
            Err(format!(
                "{reason} (backend exit {}); raw diagnostics withheld to protect credentials",
                status.code().map_or("signal".into(), |n| n.to_string())
            ))
        }
        pub fn pull(
            &self,
            reference: &str,
            destination: &Path,
            cancelled: &impl Fn() -> bool,
        ) -> Result<()> {
            let mut cmd = self.command()?;
            cmd.args([
                "copy",
                "--src-tls-verify=true",
                "--format",
                "oci",
                "--authfile",
            ])
            .arg(&self.auth);
            if let Some(c) = &self.cert {
                cmd.arg("--src-cert-dir").arg(c);
            }
            cmd.arg(format!("docker://{reference}"))
                .arg(oci(destination)?);
            self.run(cmd, None, false, true, cancelled)
        }
        pub fn push(
            &self,
            reference: &str,
            source: &Path,
            cancelled: &impl Fn() -> bool,
        ) -> Result<()> {
            let mut cmd = self.command()?;
            cmd.args(["copy", "--dest-tls-verify=true", "--authfile"])
                .arg(&self.auth);
            if let Some(c) = &self.cert {
                cmd.arg("--dest-cert-dir").arg(c);
            }
            cmd.arg(oci(source)?).arg(format!("docker://{reference}"));
            self.run(cmd, None, false, true, cancelled)
        }
    }
    fn oci(p: &Path) -> Result<String> {
        let s = p.to_str().ok_or("OCI path must be UTF-8")?;
        if s.contains(':') {
            return Err("OCI path cannot contain ':'".into());
        }
        Ok(format!("oci:{s}"))
    }
    struct Secret(Vec<u8>);
    impl Drop for Secret {
        fn drop(&mut self) {
            for byte in &mut self.0 {
                unsafe {
                    std::ptr::write_volatile(byte, 0);
                }
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
    fn prompt(label: &str, hidden: bool, cancelled: &impl Fn() -> bool) -> Result<Secret> {
        struct Restore(libc::termios);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    libc::tcsetattr(0, libc::TCSANOW, &self.0);
                }
            }
        }
        let mut old = std::mem::MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(0, old.as_mut_ptr()) } != 0 {
            return Err("cannot read terminal settings".into());
        }
        let old = unsafe { old.assume_init() };
        let _restore = Restore(old);
        if hidden {
            let mut settings = old;
            settings.c_lflag &= !(libc::ECHO | libc::ECHONL);
            if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &settings) } != 0 {
                return Err("cannot disable terminal echo".into());
            }
        }
        // Disable echo BEFORE showing the prompt, avoiding a fast-input race.
        std::io::stderr().write_all(label.as_bytes()).map_err(err)?;
        std::io::stderr().flush().map_err(err)?;
        let mut value = Secret(Vec::with_capacity(4096));
        loop {
            if cancelled() {
                return Err("login cancelled".into());
            }
            let mut fd = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut fd, 1, 100) };
            if ready < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err("terminal polling failed".into());
            }
            if ready <= 0 {
                continue;
            }
            let mut byte = 0u8;
            let n = unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) };
            if n <= 0 {
                return Err("terminal input ended".into());
            }
            if byte == b'\n' {
                break;
            }
            if value.0.len() == 4096 {
                return Err("login input exceeds 4096 bytes".into());
            }
            value.0.push(byte);
        }
        if hidden {
            eprintln!();
        }
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) } != 0 {
            return Err("cannot restore terminal echo".into());
        }
        Ok(value)
    }
    pub fn login(
        host: &str,
        user: Option<&str>,
        password_stdin: bool,
        options: &Options,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        use std::io::IsTerminal;
        if password_stdin && user.is_none() {
            return Err("--password-stdin requires --username".into());
        }
        if !password_stdin && !std::io::stdin().is_terminal() {
            return Err("noninteractive login requires --username and --password-stdin".into());
        }
        if password_stdin && std::io::stdin().is_terminal() {
            return Err(
                "redirect --password-stdin from a pipe/file; omit it for a hidden terminal prompt"
                    .into(),
            );
        }
        let path = auth_path(options)?;
        let _lock = lock(&path.with_extension("lock"))?;
        let transport = Transport::new(options)?;
        let mut cmd = transport.command()?;
        cmd.args(["login", "--tls-verify=true", "--authfile"])
            .arg(&transport.auth);
        if let Some(c) = &transport.cert {
            cmd.arg("--cert-dir").arg(c);
        }
        let prompted_user;
        let user = match user {
            Some(u) => u,
            None => {
                prompted_user = prompt("Username: ", false, cancelled)?;
                std::str::from_utf8(&prompted_user.0).map_err(|_| "username must be UTF-8")?
            }
        };
        if user.is_empty()
            || user.len() > 256
            || user.chars().any(char::is_control)
            || user.contains(':')
        {
            return Err("invalid registry username".into());
        }
        cmd.arg("--username").arg(user).arg("--password-stdin");
        let password = if password_stdin {
            None
        } else {
            Some(prompt("Password: ", true, cancelled)?)
        };
        if password.as_ref().is_some_and(|p| p.0.is_empty()) {
            return Err("password cannot be empty".into());
        }
        cmd.arg(host);
        transport.run(
            cmd,
            password.as_ref().map(|p| p.0.as_slice()),
            password_stdin,
            false,
            cancelled,
        )?;
        let bytes =
            read_private(&transport.auth, AUTH_CAP)?.ok_or("backend did not save credentials")?;
        atomic_write(&path, &bytes)
    }
    pub fn logout(host: &str, options: &Options, cancelled: &impl Fn() -> bool) -> Result<()> {
        let path = auth_path(options)?;
        let _lock = lock(&path.with_extension("lock"))?;
        let transport = Transport::new(options)?;
        let mut cmd = transport.command()?;
        cmd.args(["logout", "--authfile"])
            .arg(&transport.auth)
            .arg(host);
        transport.run(cmd, None, false, false, cancelled)?;
        atomic_write(
            &path,
            &read_private(&transport.auth, AUTH_CAP)?
                .ok_or("backend removed authfile unexpectedly")?,
        )
    }
    fn tag_path(store: &Path, reference: &str) -> PathBuf {
        store.join(format!(
            "tag-{:x}.json",
            Sha256::digest(reference.as_bytes())
        ))
    }
    pub fn save_tag(store: &Path, reference: &str, image: &Path) -> Result<()> {
        let path = tag_path(store, reference);
        let _lock = lock(&path.with_extension("lock"))?;
        let image = fs::canonicalize(image).map_err(err)?;
        atomic_write(
            &path,
            &serde_json::to_vec(&serde_json::json!({"reference":reference,"image":image}))
                .map_err(err)?,
        )
    }
    pub fn tagged_image(store: &Path, reference: &str) -> Result<PathBuf> {
        let bytes = read_private(&tag_path(store, reference), AUTH_CAP)?
            .ok_or("local tag not found; build with -t first")?;
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid local tag record")?;
        if v["reference"] != reference {
            return Err("local tag identity mismatch".into());
        }
        let p = PathBuf::from(v["image"].as_str().ok_or("missing local image path")?);
        if !p.is_absolute() {
            return Err("invalid local image path".into());
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn references_are_explicit_and_never_transport_or_credential_strings() {
        assert_eq!(
            reference("ubuntu:24.04", true).unwrap(),
            "docker.io/library/ubuntu:24.04"
        );
        assert_eq!(
            reference("me/app", false).unwrap(),
            "docker.io/me/app:latest"
        );
        assert_eq!(
            reference("localhost:5000/me/app:v1", false).unwrap(),
            "localhost:5000/me/app:v1"
        );
        for s in [
            "https://host/repo",
            "user:secret@host/repo",
            "--creds=x",
            "host/repo\n",
            "Host/repo",
            "a/../b",
            "a//b",
            "a:b:c",
        ] {
            assert!(reference(s, true).is_err(), "{s}");
        }
        for s in [
            "https://docker.io",
            "user@host",
            "host/path",
            "host:0",
            "host:99999",
            "-host",
        ] {
            assert!(registry(s).is_err(), "{s}");
        }
    }
}
