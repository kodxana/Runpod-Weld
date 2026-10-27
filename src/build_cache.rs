//! Private, content-keyed completed-stage cache. Never executes a cache entry.
//! Like COPY, fingerprinting requires a stable context. Reads may update source
//! atimes; key their post-read values, which subsequent COPY preflight observes.
//! Strict-atime mounts and external readers can therefore reduce cache reuse.
use crate::build::{Error, Limits};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Error>;

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

pub(crate) fn key(
    inputs: &[u8],
    context: Option<&Path>,
    limits: Limits,
    policy: &crate::dockerignore::Policy,
    cancelled: &impl Fn() -> bool,
) -> Result<String> {
    let mut hash = Sha256::new();
    field(&mut hash, b"weld-stage-cache-v7-incremental-checkpoints");
    field(&mut hash, inputs);
    // Development builds share a version string: bind cache entries to executable bytes.
    let mut executable = fs::File::open(std::env::current_exe()?)?;
    // Unit-test executables also embed the test harness and its debug data.
    let executable_limit = if cfg!(test) { 256 } else { 64 } * 1024 * 1024;
    if executable.metadata()?.len() > executable_limit {
        return Err("builder executable exceeds cache identity budget".into());
    }
    let mut buf = [0u8; 65536];
    loop {
        if cancelled() {
            return Err("cache hashing cancelled".into());
        }
        let n = executable.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    if let Some(root) = context {
        #[cfg(target_os = "linux")]
        field(
            &mut hash,
            &crate::context::fingerprint(
                root,
                policy,
                crate::context::Limits {
                    max_bytes: limits
                        .max_rootfs_bytes
                        .min(limits.layer.max_uncompressed_bytes),
                    max_entries: limits.max_rootfs_entries.min(limits.layer.max_entries),
                    max_metadata_bytes: limits.layer.max_metadata_bytes,
                },
                cancelled,
            )?,
        );
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, limits, policy);
            return Err("cache requires Linux".into());
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

// The caller includes the executable identity once, plus the previous verified
// manifest and this instruction's evaluated inputs. No later context belongs here.
pub(crate) fn instruction_key(inputs: &[u8]) -> String {
    let mut hash = Sha256::new();
    field(
        &mut hash,
        b"weld-instruction-cache-v3-incremental-checkpoints",
    );
    field(&mut hash, inputs);
    format!("{:x}", hash.finalize())
}

pub(crate) fn lookup(path: &Path, lease: Option<&crate::store_lease::StoreLease>) -> Result<bool> {
    crate::store_access::validate_path(path, lease)?;
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => Ok(true),
        Ok(_) => Err("cache entry must be a real directory".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn publish(
    source: &Path,
    lease: Option<&crate::store_lease::StoreLease>,
    destination: &Path,
    targets: Option<(&[Vec<Vec<u8>>], u64)>,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    publish_created(source, lease, destination, targets, cancelled, || Ok(()))
}

pub(crate) fn publish_created(
    source: &Path,
    lease: Option<&crate::store_lease::StoreLease>,
    destination: &Path,
    targets: Option<(&[Vec<Vec<u8>>], u64)>,
    cancelled: &impl Fn() -> bool,
    created: impl FnOnce() -> std::io::Result<()>,
) -> Result<()> {
    crate::store_access::validate_path(source, lease)?;
    if lookup(destination, lease)? {
        return Ok(());
    }
    let temporary = tempfile::Builder::new()
        .prefix(".publish-")
        .tempdir_in(destination.parent().ok_or("cache parent missing")?)?;
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        if cancelled() {
            return Err("cache publication cancelled".into());
        }
        for e in fs::read_dir(source.join(&relative))? {
            let e = e?;
            if relative.as_os_str().is_empty()
                && (e.file_name() == COPY_TARGETS || e.file_name() == "weld-cache-entry.json")
            {
                continue;
            }
            let child = relative.join(e.file_name());
            let target = temporary.path().join(&child);
            let kind = e.file_type()?;
            if kind.is_dir() {
                fs::create_dir(&target)?;
                pending.push(child);
            } else if kind.is_file() {
                let mut source = fs::File::open(e.path())?;
                let mut output = fs::File::create(target)?;
                let mut buffer = [0u8; 65536];
                loop {
                    if cancelled() {
                        return Err("cache publication cancelled".into());
                    }
                    let size = source.read(&mut buffer)?;
                    if size == 0 {
                        break;
                    }
                    output.write_all(&buffer[..size])?;
                }
            } else {
                return Err("cache publication requires a regular OCI layout".into());
            }
        }
    }
    if let Some((targets, metadata_limit)) = targets {
        let bytes = receipt_bytes(targets, metadata_limit)?;
        fs::write(temporary.path().join(COPY_TARGETS), bytes)?;
    }
    if cancelled() {
        return Err("cache publication cancelled".into());
    }
    match fs::rename(temporary.path(), destination) {
        Ok(()) => {
            let _ = temporary.keep();
            created()?;
            Ok(())
        }
        Err(_) if lookup(destination, lease)? => Ok(()), // A concurrent successful build won publication.
        Err(e) => Err(e.into()),
    }
}

pub(crate) const COPY_TARGETS: &str = "weld-copy-targets.json";

pub(crate) fn receipt_bytes(targets: &[Vec<Vec<u8>>], metadata_limit: u64) -> Result<Vec<u8>> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: u64,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() as u64 > self.limit.saturating_sub(self.bytes.len() as u64) {
                return Err(std::io::Error::other(
                    "cached COPY targets exceed metadata budget",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        limit: receipt_limit(metadata_limit, targets.len())?,
    };
    serde_json::to_writer(&mut output, targets)?;
    validate_receipt(&output.bytes, metadata_limit, targets.len())?;
    Ok(output.bytes)
}

fn receipt_limit(metadata_limit: u64, instructions: usize) -> Result<u64> {
    if instructions > crate::build_plan::MAX_INSTRUCTIONS {
        return Err("cached COPY instruction count exceeds limit".into());
    }
    // Byte-array expansion and path delimiters, plus even empty instruction arrays.
    metadata_limit
        .checked_mul(6)
        .and_then(|n| n.checked_add((instructions as u64).checked_mul(3)?))
        .and_then(|n| n.checked_add(2))
        .filter(|n| *n < usize::MAX as u64)
        .ok_or_else(|| "cached COPY receipt limit overflow".into())
}

// Validate structure and counts without allocating the nested receipt vectors.
fn validate_receipt(bytes: &[u8], metadata_limit: u64, instructions: usize) -> Result<()> {
    use serde::de::{DeserializeSeed, Error as _, SeqAccess, Visitor};
    struct Array<'a> {
        depth: u8,
        count: usize,
        budget: &'a mut u64,
    }
    impl<'de> DeserializeSeed<'de> for Array<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<(), D::Error> {
            d.deserialize_seq(self)
        }
    }
    impl<'de> Visitor<'de> for Array<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bounded COPY receipt array")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
            let mut count = 0usize;
            loop {
                let present = if self.depth == 2 {
                    seq.next_element::<u8>()?.is_some()
                } else {
                    seq.next_element_seed(Array {
                        depth: self.depth + 1,
                        count: if self.depth == 0 {
                            (*self.budget / 512).min(usize::MAX as u64) as usize
                        } else {
                            4096
                        },
                        budget: self.budget,
                    })?
                    .is_some()
                };
                if !present {
                    break;
                }
                if count == self.count {
                    return Err(A::Error::custom("cached COPY receipt count exceeds limit"));
                }
                count += 1;
                let charge = match self.depth {
                    1 => 512,
                    2 => 1,
                    _ => 0,
                };
                *self.budget = self.budget.checked_sub(charge).ok_or_else(|| {
                    A::Error::custom("cached COPY targets exceed metadata budget")
                })?;
            }
            if self.depth == 0 && count != self.count {
                return Err(A::Error::custom("missing cached COPY targets"));
            }
            Ok(())
        }
    }
    let mut budget = metadata_limit;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    Array {
        depth: 0,
        count: instructions,
        budget: &mut budget,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(())
}

pub(crate) fn copy_targets(
    path: &Path,
    lease: Option<&crate::store_lease::StoreLease>,
    metadata_limit: u64,
    instructions: usize,
) -> Result<Vec<Vec<Vec<u8>>>> {
    crate::store_access::validate_path(path, lease)?;
    let limit = receipt_limit(metadata_limit, instructions)?;
    if !fs::symlink_metadata(path.join(COPY_TARGETS))?.is_file() {
        return Err("cached COPY targets must be a regular file".into());
    }
    let file = fs::File::open(path.join(COPY_TARGETS))?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err("cached COPY targets exceed metadata budget".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("cached COPY targets exceed metadata budget".into());
    }
    validate_receipt(&bytes, metadata_limit, instructions)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutable_output_copy_does_not_alias_immutable_source() {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("blob"), b"immutable").unwrap();
        fs::hard_link(source.join("blob"), t.path().join("pool-blob")).unwrap();
        let output = t.path().join("output");
        publish_created(&source, None, &output, None, &|| false, || Ok(())).unwrap();
        fs::write(output.join("blob"), b"mutable output").unwrap();
        assert_eq!(fs::read(source.join("blob")).unwrap(), b"immutable");
        assert_eq!(fs::read(t.path().join("pool-blob")).unwrap(), b"immutable");
    }

    #[test]
    fn cancelled_blob_publication_never_installs_an_entry() {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("blob"), vec![42; 1024 * 1024]).unwrap();
        let destination = t.path().join("entry");
        let checks = std::cell::Cell::new(0);
        let created = std::cell::Cell::new(false);
        let error = publish_created(
            &source,
            None,
            &destination,
            None,
            &|| {
                checks.set(checks.get() + 1);
                checks.get() >= 5
            },
            || {
                created.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(!destination.exists());
        assert!(!created.get());
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
    }

    #[test]
    fn receipt_limits_are_checked_and_include_empty_instructions() {
        assert_eq!(receipt_limit(0, 0).unwrap(), 2);
        assert_eq!(receipt_limit(1024, 3000).unwrap(), 15146);
        assert!(receipt_limit(0, crate::build_plan::MAX_INSTRUCTIONS).is_ok());
        assert!(receipt_limit(0, crate::build_plan::MAX_INSTRUCTIONS + 1).is_err());
        assert!(receipt_limit(0, usize::MAX).is_err());
        assert!(receipt_limit(u64::MAX, 0).is_err());
        assert!(receipt_limit(u64::MAX / 6, 1).is_err());
    }

    #[test]
    fn receipts_reject_oversize_malformed_and_excess_counts() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join(COPY_TARGETS);
        for bytes in [
            b"[[],[]]".as_slice(),
            b"[",
            b"[[[256]]]",
            b"[[]] null",
            b"[[{}]]",
        ] {
            assert!(validate_receipt(bytes, 10000, 1).is_err(), "{bytes:?}");
        }
        for bytes in [
            b"[[],[]]".as_slice(),
            b"[",
            b"[[[256]]]",
            b"[[]] null",
            b"[[[]]]",
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(copy_targets(t.path(), None, 0, 1).is_err(), "{bytes:?}");
        }
        fs::write(&path, b"[[]] ").unwrap(); // Exact serialized cap for one empty COPY.
        assert_eq!(
            copy_targets(t.path(), None, 0, 1).unwrap(),
            vec![Vec::<Vec<u8>>::new()]
        );
        fs::write(&path, b"[[]]  ").unwrap();
        assert!(copy_targets(t.path(), None, 0, 1).is_err());
        fs::write(&path, b"[]").unwrap();
        assert!(copy_targets(t.path(), None, 0, 1).is_err());
        assert!(copy_targets(t.path(), None, u64::MAX, 0).is_err());
    }

    #[test]
    fn publication_and_reads_share_byte_path_and_count_limits() {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source");
        fs::create_dir(&source).unwrap();
        let targets = vec![vec![vec![255; 4096]], vec![]];
        let budget = 512 + 4096;
        let entry = t.path().join("entry");
        publish(&source, None, &entry, Some((&targets, budget)), &|| false).unwrap();
        assert_eq!(copy_targets(&entry, None, budget, 2).unwrap(), targets);
        assert!(copy_targets(&entry, None, budget - 1, 2).is_err());
        let rejected = t.path().join("rejected");
        assert!(
            publish(
                &source,
                None,
                &rejected,
                Some((&targets, budget - 1)),
                &|| false
            )
            .is_err()
        );
        assert!(!rejected.exists());
        let too_long = serde_json::to_vec(&vec![vec![vec![0u8; 4097]]]).unwrap();
        assert!(validate_receipt(&too_long, 10000, 1).is_err());
        assert!(validate_receipt(b"[[[]]]", 511, 1).is_err());
        assert!(validate_receipt(b"[[[]]]", 512, 1).is_ok());
    }
}
