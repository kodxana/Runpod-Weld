//! Development-only OCI replay harness, NOT a builder or container runtime.
//! Usage: cargo run --example replay_layout -- LAYOUT REFERENCE DESTINATION SPOOL
//! All directories must already exist; create a fresh empty disposable destination.
//! Keep paths/ancestors stable, with no concurrent writers, nested mounts or external
//! hardlinks. Use a Linux filesystem and sufficient ownership/xattr permissions.
//! Failure may leave a partial destination: discard it manually, never reuse it.
//! This example never deletes user trees. Config stays in memory; nothing is exported
//! or executed, and successful replay does not establish runnable/buildable semantics.

use rpweld::{image, layer, oci::BlobStore, rootfs};
use serde_json::Value;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const IMAGE_LIMITS: image::Limits = image::Limits {
    max_metadata_bytes: 8 * MIB,
    max_total_metadata_bytes: 32 * MIB,
    max_descriptors: 256,
    max_layer_bytes: GIB,
    max_total_layer_bytes: 4 * GIB,
};
const LAYER_LIMITS: layer::Limits = layer::Limits {
    max_blob_bytes: GIB,
    max_uncompressed_bytes: 2 * GIB,
    max_entries: 250_000,
    max_metadata_bytes: 128 * MIB,
    max_gzip_header_bytes: MIB,
};
const MAX_TOTAL_UNCOMPRESSED: u64 = 8 * GIB;
const MAX_TOTAL_ENTRIES: usize = 1_000_000;

fn directory(path: &Path) -> Result<PathBuf> {
    let path = fs::canonicalize(path)?;
    if !path.is_dir() {
        return Err(format!("not a directory: {}", path.display()).into());
    }
    Ok(path)
}

fn checked_paths(layout: &Path, destination: &Path, spool: &Path) -> Result<[PathBuf; 3]> {
    let paths = [
        directory(layout)?,
        directory(destination)?,
        directory(spool)?,
    ];
    for i in 0..paths.len() {
        for j in i + 1..paths.len() {
            if paths[i].starts_with(&paths[j]) || paths[j].starts_with(&paths[i]) {
                return Err(
                    "layout, destination and spool must not overlap (including aliases)".into(),
                );
            }
        }
    }
    if fs::read_dir(&paths[1])?.next().transpose()?.is_some() {
        return Err("destination must be empty and disposable".into());
    }
    // BlobStore::open may create these; require a populated layout before calling it.
    for relative in ["blobs", "blobs/sha256"] {
        if !fs::symlink_metadata(paths[0].join(relative))?
            .file_type()
            .is_dir()
        {
            return Err("layout blob directories must exist and must not be symlinks".into());
        }
    }
    Ok(paths)
}

fn check_config(user: Option<&Value>, on_build: Option<&Value>) -> Result<()> {
    // shortcut: only absent/null/empty defaults; explicit root spellings and all
    // inherited execution settings need a future builder policy, not this harness.
    if !matches!(user, None | Some(Value::Null))
        && !matches!(user, Some(Value::String(s)) if s.is_empty())
    {
        return Err("unsupported base config.User (only absent/null/empty accepted)".into());
    }
    if !matches!(on_build, None | Some(Value::Null))
        && !matches!(on_build, Some(Value::Array(a)) if a.is_empty())
    {
        return Err(
            "unsupported base config.OnBuild (only absent/null/empty array accepted)".into(),
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: replay_layout LAYOUT REFERENCE EMPTY_DISPOSABLE_DESTINATION SPOOL".into(),
        );
    }
    if !cfg!(target_os = "linux") {
        return Err("replay_layout requires Linux".into());
    }
    let reference = args[1]
        .to_str()
        .filter(|s| !s.is_empty())
        .ok_or("reference must be nonempty UTF-8")?;
    let [layout, destination, spool] = checked_paths(
        Path::new(&args[0]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    )?;
    // Synchronous development harness: no cancellation source is wired up.
    let cancelled = || false;
    let metadata = image::load_layout(&layout, Some(reference), IMAGE_LIMITS, cancelled)?;
    check_config(metadata.user(), metadata.on_build())?;
    let store = BlobStore::open(&layout)?;
    println!(
        "Development replay only: manifest={}, config={}, layers={}",
        metadata.selected.digest,
        metadata.config_descriptor.digest,
        metadata.layers.len()
    );
    println!(
        "Config retained in memory; no execution or image export. Destination: {}",
        destination.display()
    );
    println!(
        "Limits: image={IMAGE_LIMITS:?}, layer={LAYER_LIMITS:?}, total uncompressed={MAX_TOTAL_UNCOMPRESSED}, total entries={MAX_TOTAL_ENTRIES}"
    );
    let mut total_bytes = 0;
    let mut total_entries = 0;
    for (index, (descriptor, diff_id)) in metadata.layers.iter().zip(&metadata.diff_ids).enumerate()
    {
        let limits = layer::Limits {
            max_uncompressed_bytes: LAYER_LIMITS
                .max_uncompressed_bytes
                .min(MAX_TOTAL_UNCOMPRESSED - total_bytes),
            max_entries: LAYER_LIMITS
                .max_entries
                .min(MAX_TOTAL_ENTRIES - total_entries),
            ..LAYER_LIMITS
        };
        eprintln!("Verifying layer {}: {}", index + 1, descriptor.digest);
        let mut verified = layer::verify(&store, descriptor, diff_id, &spool, limits, cancelled)
            .map_err(|e| format!("layer {} verification: {e}", index + 1))?;
        total_bytes += verified.size();
        total_entries += verified.entries().len();
        let summary = rootfs::apply_layer(&destination, &mut verified, cancelled)
            .map_err(|e| format!("layer {} application: {e}", index + 1))?;
        println!(
            "Layer {}: diffID={}, uncompressed={}, {summary:?}",
            index + 1,
            verified.diff_id(),
            verified.size()
        );
        // One verified spool at a time; drop releases it before the next layer.
    }
    println!(
        "Replay complete: {} layers, {total_entries} entries, {total_bytes} uncompressed bytes. Not a build/runtime validation.",
        metadata.layers.len()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "Replay failed: {error}\nDestination may be partial; discard manually. No user tree was automatically deleted."
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preflight_rejects_nonempty_and_overlapping_paths_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let layout = temp.path().join("layout");
        let dest = temp.path().join("dest");
        let spool = temp.path().join("spool");
        for path in [&layout, &dest, &spool] {
            fs::create_dir(path).unwrap();
        }
        fs::write(dest.join("keep"), "untouched").unwrap();
        assert!(checked_paths(&layout, &dest, &spool).is_err());
        assert_eq!(fs::read_to_string(dest.join("keep")).unwrap(), "untouched");
        assert!(!layout.join("blobs").exists());
        assert!(checked_paths(&layout, &layout, &spool).is_err());
        assert!(checked_paths(&layout, &spool, temp.path()).is_err());
        #[cfg(unix)]
        {
            let alias = temp.path().join("alias");
            std::os::unix::fs::symlink(&layout, &alias).unwrap();
            assert!(checked_paths(&layout, &alias, &spool).is_err());
        }
    }

    #[test]
    fn inherited_execution_semantics_are_rejected() {
        assert!(check_config(None, None).is_ok());
        assert!(check_config(Some(&Value::Null), Some(&Value::Null)).is_ok());
        assert!(check_config(Some(&json!("")), Some(&json!([]))).is_ok());
        for user in [json!("1000"), json!("root"), json!(0), json!([])] {
            assert!(check_config(Some(&user), None).is_err());
        }
        for triggers in [json!(["RUN true"]), json!(""), json!({})] {
            assert!(check_config(None, Some(&triggers)).is_err());
        }
    }
}
