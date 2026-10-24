//! Bounded local OCI image metadata inspection, not extraction or a runnable image.
//!
//! Caller-owned paths and ancestors must remain stable, as required by `BlobStore`.
//! Only OCI image manifests/configs and SHA-256 are supported. Nested indexes and
//! artifact manifests are rejected. Layer bytes are hashed without decompression;
//! diff IDs are checked for syntax/count only, never claimed verified.

use crate::oci::{BlobStore, Descriptor, Sha256Digest};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fmt, fs,
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};

const INDEX: &str = "application/vnd.oci.image.index.v1+json";
const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const REF: &str = "org.opencontainers.image.ref.name";

/// All limits are required from the caller. Metadata budgets include oci-layout,
/// index, selected manifest and config. Descriptor budget includes all index
/// entries plus the selected manifest's config and layers (not unique digests).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_metadata_bytes: u64,
    pub max_total_metadata_bytes: u64,
    pub max_descriptors: usize,
    pub max_layer_bytes: u64,
    pub max_total_layer_bytes: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    Blob(crate::oci::Error),
    Invalid(String),
    Limit(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "image metadata I/O: {e}"),
            Self::Json(e) => write!(f, "image metadata JSON: {e}"),
            Self::Blob(e) => write!(f, "image blob: {e}"),
            Self::Invalid(e) => f.write_str(e),
            Self::Limit(e) => write!(f, "image limit exceeded: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<crate::oci::Error> for Error {
    fn from(e: crate::oci::Error) -> Self {
        Self::Blob(e)
    }
}
fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}

#[derive(Debug)]
pub struct ImageMetadata {
    pub index: Value,
    pub selected: Descriptor,
    pub manifest: Value,
    pub config_descriptor: Descriptor,
    /// Full config, including unknown fields and inherited execution semantics.
    pub config: Value,
    pub layers: Vec<Descriptor>,
    /// Ordered declarations only: their uncompressed content is not verified.
    pub diff_ids: Vec<Sha256Digest>,
}
impl ImageMetadata {
    /// Raw value preserves absent, null, malformed and unsupported values for
    /// future executor policy validation. Absence does not authorize root RUN.
    pub fn user(&self) -> Option<&Value> {
        self.config.get("config")?.get("User")
    }
    pub fn on_build(&self) -> Option<&Value> {
        self.config.get("config")?.get("OnBuild")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u32,
    media_type: Option<String>,
    manifests: Vec<Descriptor>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    media_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

/// Select an exact ref-name annotation, or exactly one native/unspecified-platform
/// descriptor. An unspecified platform is resolved using the verified config;
/// multiple such candidates are ambiguous, not guessed by reading every config.
/// Cancellation is forwarded to every streaming blob verification.
pub fn load_layout(
    root: impl AsRef<Path>,
    reference: Option<&str>,
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> Result<ImageMetadata, Error> {
    let root = root.as_ref();
    let store = BlobStore::open(root)?;
    let mut remaining = limits.max_total_metadata_bytes;
    let layout = read_json(
        open_metadata(&root.join("oci-layout"))?,
        limits,
        &mut remaining,
    )?;
    if layout.get("imageLayoutVersion").and_then(Value::as_str) != Some("1.0.0") {
        return Err(invalid(
            "unsupported OCI imageLayoutVersion (expected 1.0.0)",
        ));
    }
    let index = read_json(
        open_metadata(&root.join("index.json"))?,
        limits,
        &mut remaining,
    )?;
    let parsed: Index = serde_json::from_value(index.clone())?;
    schema(parsed.schema_version, parsed.media_type.as_deref(), INDEX)?;
    if parsed.manifests.len() > limits.max_descriptors {
        return Err(Error::Limit("descriptor count"));
    }
    let mut candidates = Vec::new();
    for descriptor in &parsed.manifests {
        descriptor_valid(descriptor)?;
        if descriptor.media_type == INDEX {
            return Err(invalid("nested OCI indexes are unsupported"));
        }
        if descriptor.media_type != MANIFEST {
            return Err(invalid("unsupported index descriptor media type"));
        }
        let native = match descriptor.extensions.get("platform") {
            Some(platform) => native_platform(platform, false)?,
            None => true,
        };
        if match reference {
            Some(name) => descriptor.annotations.get(REF).is_some_and(|v| v == name),
            None => native,
        } {
            candidates.push(descriptor);
        }
    }
    let selected = match candidates.as_slice() {
        [] => return Err(invalid("no matching image descriptor")),
        [descriptor] => (*descriptor).clone(),
        _ => return Err(invalid("ambiguous image descriptor selection")),
    };
    if let Some(platform) = selected.extensions.get("platform")
        && !native_platform(platform, false)?
    {
        return Err(invalid(
            "selected descriptor platform is not native linux/amd64",
        ));
    }
    let manifest = read_blob_json(&store, &selected, limits, &mut remaining, &cancelled)?;
    let parsed_manifest: Manifest = serde_json::from_value(manifest.clone())?;
    schema(
        parsed_manifest.schema_version,
        parsed_manifest.media_type.as_deref(),
        MANIFEST,
    )?;
    if manifest.get("artifactType").is_some() || manifest.get("subject").is_some() {
        return Err(invalid("artifact/subject manifests are unsupported"));
    }
    let count = parsed
        .manifests
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(parsed_manifest.layers.len()));
    if count.is_none_or(|n| n > limits.max_descriptors) {
        return Err(Error::Limit("descriptor count"));
    }
    if parsed_manifest.config.media_type != CONFIG {
        return Err(invalid("unsupported image config media type"));
    }
    let config = read_blob_json(
        &store,
        &parsed_manifest.config,
        limits,
        &mut remaining,
        &cancelled,
    )?;
    if !native_platform(&config, true)? {
        return Err(invalid("image config platform is not native linux/amd64"));
    }
    if config
        .get("config")
        .is_some_and(|v| !v.is_null() && !v.is_object())
    {
        return Err(invalid("image config.config must be an object or null"));
    }
    let rootfs = config
        .get("rootfs")
        .ok_or_else(|| invalid("missing config rootfs"))?;
    if rootfs.get("type").and_then(Value::as_str) != Some("layers") {
        return Err(invalid("unsupported rootfs type"));
    }
    let diff_ids: Vec<Sha256Digest> = serde_json::from_value(
        rootfs
            .get("diff_ids")
            .ok_or_else(|| invalid("missing rootfs.diff_ids"))?
            .clone(),
    )?;
    if diff_ids.len() != parsed_manifest.layers.len() {
        return Err(invalid("layer and rootfs.diff_ids counts differ"));
    }
    let mut total = 0u64;
    for layer in &parsed_manifest.layers {
        descriptor_valid(layer)?;
        if !matches!(
            layer.media_type.as_str(),
            "application/vnd.oci.image.layer.v1.tar"
                | "application/vnd.oci.image.layer.v1.tar+gzip"
                | "application/vnd.oci.image.layer.v1.tar+zstd"
        ) {
            return Err(invalid("unsupported layer media type"));
        }
        total = total
            .checked_add(layer.size as u64)
            .ok_or(Error::Limit("total layer bytes"))?;
        if total > limits.max_total_layer_bytes {
            return Err(Error::Limit("total layer bytes"));
        }
        if layer.size as u64 > limits.max_layer_bytes {
            return Err(Error::Limit("layer bytes"));
        }
    }
    for layer in &parsed_manifest.layers {
        drop(store.open_verified(layer, limits.max_layer_bytes, &cancelled)?);
    }
    Ok(ImageMetadata {
        index,
        selected,
        manifest,
        config_descriptor: parsed_manifest.config,
        config,
        layers: parsed_manifest.layers,
        diff_ids,
    })
}

fn descriptor_valid(d: &Descriptor) -> Result<(), Error> {
    d.digest.parse::<Sha256Digest>()?;
    if d.size < 0 {
        return Err(invalid("negative descriptor size"));
    }
    Ok(())
}
fn schema(version: u32, media: Option<&str>, expected: &str) -> Result<(), Error> {
    if version != 2 || media.is_some_and(|v| v != expected) {
        return Err(invalid("unsupported OCI schema or media type"));
    }
    Ok(())
}
fn native_platform(value: &Value, config_nulls_are_absent: bool) -> Result<bool, Error> {
    let os = value
        .get("os")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing/invalid platform os"))?;
    let arch = value
        .get("architecture")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing/invalid platform architecture"))?;
    // shortcut: no CPU variant or OS feature negotiation; extend with a host
    // capability contract before accepting constrained native images.
    Ok(os == "linux"
        && arch == "amd64"
        && ["variant", "os.version", "os.features"].iter().all(|key| {
            // OCI config optional null fields have the same meaning as absence.
            value
                .get(key)
                .is_none_or(|v| config_nulls_are_absent && v.is_null())
        }))
}
fn open_metadata(path: &Path) -> Result<fs::File, Error> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("metadata reparse point rejected"));
        }
    }
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid("metadata must be a regular non-symlink file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("metadata must be a regular file"));
    }
    Ok(file)
}
fn read_blob_json(
    store: &BlobStore,
    descriptor: &Descriptor,
    limits: Limits,
    remaining: &mut u64,
    cancelled: &impl Fn() -> bool,
) -> Result<Value, Error> {
    let file = store.open_verified(
        descriptor,
        limits.max_metadata_bytes.min(*remaining),
        cancelled,
    )?;
    read_json(file, limits, remaining)
}
fn read_json(file: fs::File, limits: Limits, remaining: &mut u64) -> Result<Value, Error> {
    let cap = limits.max_metadata_bytes.min(*remaining);
    if file.metadata()?.len() > cap {
        return Err(Error::Limit("metadata bytes"));
    }
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(Error::Limit("metadata bytes"));
    }
    *remaining -= bytes.len() as u64;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        root: PathBuf,
        store: BlobStore,
    }
    impl Fixture {
        fn new() -> Self {
            let root = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "rpweld-image-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir(&root).unwrap();
            let store = BlobStore::open(&root).unwrap();
            fs::write(
                root.join("oci-layout"),
                br#"{"imageLayoutVersion":"1.0.0"}"#,
            )
            .unwrap();
            Self { root, store }
        }
        fn blob(&self, media: &str, bytes: &[u8]) -> Descriptor {
            let d = Descriptor {
                media_type: media.into(),
                digest: format!("sha256:{:x}", Sha256::digest(bytes)),
                size: bytes.len() as i64,
                annotations: BTreeMap::new(),
                extensions: BTreeMap::new(),
            };
            self.store.ingest(bytes, &d, u64::MAX, || false).unwrap();
            d
        }
        fn image(&self, config: Value, layers: Vec<Descriptor>) -> Descriptor {
            let c = self.blob(CONFIG, &serde_json::to_vec(&config).unwrap());
            self.blob(
                MANIFEST,
                &serde_json::to_vec(
                    &json!({"schemaVersion":2,"mediaType":MANIFEST,"config":c,"layers":layers}),
                )
                .unwrap(),
            )
        }
        fn index(&self, descriptors: &[Descriptor]) {
            fs::write(
                self.root.join("index.json"),
                serde_json::to_vec(
                    &json!({"schemaVersion":2,"mediaType":INDEX,"manifests":descriptors}),
                )
                .unwrap(),
            )
            .unwrap();
        }
        fn path(&self, d: &Descriptor) -> PathBuf {
            self.root.join("blobs/sha256").join(&d.digest[7..])
        }
        fn load(&self) -> Result<ImageMetadata, Error> {
            load_layout(&self.root, None, limits(), || false)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn limits() -> Limits {
        Limits {
            max_metadata_bytes: 8192,
            max_total_metadata_bytes: 32768,
            max_descriptors: 16,
            max_layer_bytes: 1024,
            max_total_layer_bytes: 2048,
        }
    }
    fn config() -> Value {
        json!({"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{"User":"1000:1000","OnBuild":["RUN echo inherited"],"future":{"preserve":true}},"unknown":[1,2]})
    }
    fn layered(f: &Fixture) -> (Descriptor, Descriptor) {
        // Deliberately opaque bytes: this loader makes no decompression claim.
        let layer = f.blob(
            "application/vnd.oci.image.layer.v1.tar+gzip",
            b"opaque compressed bytes",
        );
        let mut c = config();
        c["rootfs"]["diff_ids"] = json!([format!(
            "sha256:{:x}",
            Sha256::digest(b"uncompressed declaration")
        )]);
        (f.image(c, vec![layer.clone()]), layer)
    }
    #[test]
    fn valid_scratch_preserves_config_and_execution_fields() {
        let f = Fixture::new();
        f.index(&[f.image(config(), vec![])]);
        let image = f.load().unwrap();
        assert!(image.layers.is_empty());
        assert!(image.diff_ids.is_empty());
        assert_eq!(image.config, config());
        assert_eq!(image.user(), Some(&json!("1000:1000")));
        assert_eq!(image.on_build(), Some(&json!(["RUN echo inherited"])));
    }
    #[test]
    fn optional_config_platform_nulls_are_absent() {
        for field in ["variant", "os.version", "os.features"] {
            let f = Fixture::new();
            let mut c = config();
            c[field] = Value::Null;
            f.index(&[f.image(c.clone(), vec![])]);
            assert_eq!(f.load().unwrap().config, c, "{field}");
            c[field] = if field == "os.features" {
                json!(["unsupported"])
            } else {
                json!("unsupported")
            };
            f.index(&[f.image(c, vec![])]);
            assert!(
                f.load()
                    .unwrap_err()
                    .to_string()
                    .contains("config platform"),
                "{field}"
            );
        }
    }
    #[test]
    fn valid_layered_metadata_and_limits() {
        let f = Fixture::new();
        let (manifest, layer) = layered(&f);
        f.index(&[manifest]);
        let image = f.load().unwrap();
        assert_eq!(image.layers, vec![layer.clone()]);
        assert_eq!(image.diff_ids.len(), 1);
        let mut l = limits();
        l.max_layer_bytes = layer.size as u64 - 1;
        assert!(matches!(
            load_layout(&f.root, None, l, || false),
            Err(Error::Limit("layer bytes"))
        ));
        l = limits();
        l.max_total_layer_bytes = 0;
        assert!(matches!(
            load_layout(&f.root, None, l, || false),
            Err(Error::Limit("total layer bytes"))
        ));
    }
    #[test]
    fn corrupt_and_truncated_layer_blobs() {
        for truncated in [false, true] {
            let f = Fixture::new();
            let (m, layer) = layered(&f);
            f.index(&[m]);
            let bytes = if truncated {
                vec![b'x'; 1]
            } else {
                vec![b'x'; layer.size as usize]
            };
            fs::write(f.path(&layer), bytes).unwrap();
            assert!(matches!(
                f.load(),
                Err(Error::Blob(
                    crate::oci::Error::DigestMismatch | crate::oci::Error::SizeMismatch { .. }
                ))
            ));
        }
    }
    #[test]
    fn manifest_and_config_are_verified() {
        for corrupt_config in [false, true] {
            let f = Fixture::new();
            let m = f.image(config(), vec![]);
            f.index(std::slice::from_ref(&m));
            let d = if corrupt_config {
                f.load().unwrap().config_descriptor
            } else {
                m
            };
            fs::write(f.path(&d), vec![b' '; d.size as usize]).unwrap();
            assert!(matches!(
                f.load(),
                Err(Error::Blob(crate::oci::Error::DigestMismatch))
            ));
        }
    }
    #[test]
    fn platform_mismatch_and_explicit_reference() {
        let f = Fixture::new();
        let mut c = config();
        c["architecture"] = json!("arm64");
        let mut m = f.image(c, vec![]);
        m.extensions.insert(
            "platform".into(),
            json!({"os":"linux","architecture":"amd64"}),
        );
        f.index(&[m]);
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("config platform")
        );
        let mut m = f.image(config(), vec![]);
        m.extensions.insert(
            "platform".into(),
            json!({"os":"linux","architecture":"arm64"}),
        );
        m.annotations.insert(REF.into(), "chosen".into());
        f.index(&[m]);
        assert!(
            load_layout(&f.root, Some("chosen"), limits(), || false)
                .unwrap_err()
                .to_string()
                .contains("descriptor platform")
        );
    }
    #[test]
    fn missing_ambiguous_and_reference_selection() {
        let f = Fixture::new();
        f.index(&[]);
        assert!(f.load().unwrap_err().to_string().contains("no matching"));
        let mut a = f.image(config(), vec![]);
        a.annotations.insert(REF.into(), "a".into());
        let mut b = a.clone();
        b.annotations.insert(REF.into(), "b".into());
        f.index(&[a.clone(), b]);
        assert!(f.load().unwrap_err().to_string().contains("ambiguous"));
        assert_eq!(
            load_layout(&f.root, Some("a"), limits(), || false)
                .unwrap()
                .selected,
            a
        );
        assert!(load_layout(&f.root, Some("missing"), limits(), || false).is_err());
        f.index(&[a.clone(), a]);
        assert!(
            load_layout(&f.root, Some("a"), limits(), || false)
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
    }
    #[test]
    fn unique_native_selection_among_other_platforms() {
        let f = Fixture::new();
        let mut native = f.image(config(), vec![]);
        native.extensions.insert(
            "platform".into(),
            json!({"os":"linux","architecture":"amd64"}),
        );
        let mut other = native.clone();
        other.extensions.insert(
            "platform".into(),
            json!({"os":"linux","architecture":"arm64"}),
        );
        f.index(&[other, native.clone()]);
        assert_eq!(f.load().unwrap().selected, native);
    }
    #[test]
    fn unsupported_manifest_config_and_layer_media() {
        let f = Fixture::new();
        let c = f.blob(CONFIG, &serde_json::to_vec(&config()).unwrap());
        for (schema, media, config_media) in [
            (1, MANIFEST, CONFIG),
            (2, "unknown", CONFIG),
            (2, MANIFEST, "unknown"),
        ] {
            let mut c = c.clone();
            c.media_type = config_media.into();
            let m = f.blob(
                MANIFEST,
                &serde_json::to_vec(
                    &json!({"schemaVersion":schema,"mediaType":media,"config":c,"layers":[]}),
                )
                .unwrap(),
            );
            f.index(&[m]);
            assert!(f.load().unwrap_err().to_string().contains("unsupported"));
        }
        let (_, mut layer) = layered(&f);
        layer.media_type = "unknown".into();
        let mut c = config();
        c["rootfs"]["diff_ids"] = json!([layer.digest]);
        f.index(&[f.image(c, vec![layer])]);
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("unsupported layer")
        );
    }
    #[test]
    fn descriptor_and_diff_id_limits() {
        let f = Fixture::new();
        let (m, layer) = layered(&f);
        f.index(&[m]);
        let mut l = limits();
        l.max_descriptors = 2;
        assert!(matches!(
            load_layout(&f.root, None, l, || false),
            Err(Error::Limit("descriptor count"))
        ));
        l.max_descriptors = 0;
        assert!(matches!(
            load_layout(&f.root, None, l, || false),
            Err(Error::Limit("descriptor count"))
        ));
        f.index(&[f.image(config(), vec![layer])]);
        assert!(f.load().unwrap_err().to_string().contains("counts differ"));
        let mut c = config();
        c["rootfs"]["diff_ids"] = json!(["sha256:bad"]);
        f.index(&[f.image(c, vec![])]);
        assert!(matches!(f.load(), Err(Error::Json(_))));
    }
    #[test]
    fn metadata_caps_and_cancel() {
        let f = Fixture::new();
        f.index(&[f.image(config(), vec![])]);
        let mut l = limits();
        l.max_metadata_bytes = 8;
        assert!(matches!(
            load_layout(&f.root, None, l, || false),
            Err(Error::Limit("metadata bytes"))
        ));
        l = limits();
        l.max_total_metadata_bytes = 40;
        assert!(load_layout(&f.root, None, l, || false).is_err());
        assert!(matches!(
            load_layout(&f.root, None, limits(), || true),
            Err(Error::Blob(crate::oci::Error::Cancelled))
        ));
    }
    #[test]
    fn unsupported_layout_schema_media_and_nested_index() {
        let f = Fixture::new();
        let mut m = f.image(config(), vec![]);
        m.media_type = INDEX.into();
        f.index(&[m]);
        assert!(f.load().unwrap_err().to_string().contains("nested"));
        fs::write(
            f.root.join("index.json"),
            br#"{"schemaVersion":1,"manifests":[]}"#,
        )
        .unwrap();
        assert!(f.load().unwrap_err().to_string().contains("schema"));
        fs::write(
            f.root.join("oci-layout"),
            br#"{"imageLayoutVersion":"2.0.0"}"#,
        )
        .unwrap();
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("imageLayoutVersion")
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_directory_and_fifo_metadata_rejected() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };
        for kind in 0..3 {
            let f = Fixture::new();
            let path = f.root.join("index.json");
            match kind {
                0 => symlink(f.root.join("oci-layout"), &path).unwrap(),
                1 => fs::create_dir(&path).unwrap(),
                _ => {
                    let c = CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                }
            }
            assert!(
                f.load()
                    .unwrap_err()
                    .to_string()
                    .contains("regular non-symlink")
            );
        }
    }
}
