use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::os::fd::IntoRawFd;

// fdopendir owns this O_NOATIME descriptor; one name is allocated at a time.
pub(super) struct Names(*mut libc::DIR);
impl Drop for Names {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
impl Iterator for Names {
    type Item = io::Result<OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            loop {
                *libc::__errno_location() = 0;
                let p = libc::readdir(self.0);
                if p.is_null() {
                    let e = io::Error::last_os_error();
                    return if e.raw_os_error() == Some(0) {
                        None
                    } else {
                        Some(Err(e))
                    };
                }
                let name = std::ffi::CStr::from_ptr((*p).d_name.as_ptr()).to_bytes();
                if name != b"." && name != b".." {
                    return Some(Ok(OsString::from_vec(name.to_vec())));
                }
            }
        }
    }
}
pub(super) fn names(path: &Path, c: &impl Fn() -> bool) -> Result<Names, Error> {
    check(c)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOATIME)
        .open(path)?;
    let fd = file.into_raw_fd();
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(e.into());
    }
    Ok(Names(dir))
}

pub(super) struct Node {
    pub(super) metadata: Metadata,
    attrs: Vec<(String, Vec<u8>)>,
    hash: Option<[u8; 32]>,
    pub(super) target: Option<PathBuf>,
    anchor: PathBuf,
}
pub(super) struct Inventory {
    pub(super) entries: BTreeMap<PathBuf, Node>,
}
pub(crate) struct State {
    inventory: Inventory,
    layout: Option<PathBuf>,
    layers: Vec<Descriptor>,
    diff_ids: Vec<crate::oci::Sha256Digest>,
    history: Option<Value>,
    blob_limit: u64,
}

fn inventory(
    root: &Path,
    limits: Limits,
    remaining: &mut u64,
    targets: Option<&Inventory>,
    c: &impl Fn() -> bool,
) -> Result<Inventory, Error> {
    canonical_dir(root)?;
    if root == Path::new("/") {
        return Err(Error::Invalid("host root refused"));
    }
    let mount = mount_id(root)?;
    let mut entries = BTreeMap::new();
    fn visit(
        root: &Path,
        path: &Path,
        depth: usize,
        mount: u64,
        limits: Limits,
        remaining: &mut u64,
        entries: &mut BTreeMap<PathBuf, Node>,
        c: &impl Fn() -> bool,
    ) -> Result<(), Error> {
        check(c)?;
        if depth > 256 {
            return Err(Error::Limit("directory depth"));
        }
        if entries.len() >= limits.max_entries {
            return Err(Error::Limit("entries"));
        }
        charge(remaining, path.as_os_str().len() as u64 * 3 + 2048)?;
        if path
            .file_name()
            .is_some_and(|n| n.as_bytes().starts_with(b".wh."))
        {
            return Err(Error::Invalid("reserved OCI whiteout name"));
        }
        let absolute = root.join(path);
        if mount_id(&absolute)? != mount {
            return Err(Error::Invalid("nested mount"));
        }
        let metadata = fs::symlink_metadata(&absolute)?;
        if !(metadata.is_file() || metadata.is_dir() || metadata.file_type().is_symlink()) {
            return Err(Error::Invalid("unsupported special file"));
        }
        let mut attrs = xattrs(&absolute, remaining)?;
        attrs.sort();
        if metadata.file_type().is_symlink()
            && (!attrs.is_empty() || metadata.mode() & 0o7777 != 0o777)
        {
            return Err(Error::Invalid("unsupported symlink metadata"));
        }
        let directory = metadata.is_dir();
        entries.insert(
            path.to_owned(),
            Node {
                metadata,
                attrs,
                hash: None,
                target: None,
                anchor: path.to_owned(),
            },
        );
        if directory {
            for name in names(&absolute, c)? {
                visit(
                    root,
                    &path.join(name?),
                    depth + 1,
                    mount,
                    limits,
                    remaining,
                    entries,
                    c,
                )?;
            }
        }
        Ok(())
    }
    visit(
        root,
        Path::new(""),
        0,
        mount,
        limits,
        remaining,
        &mut entries,
        c,
    )?;
    // All aliases' metadata is captured before any readlink can touch atime.
    let mut groups: HashMap<(u64, u64), (PathBuf, u64, u64, Option<[u8; 32]>, Option<PathBuf>)> =
        HashMap::new();
    let mut bytes = 0u64;
    for (path, node) in &mut entries {
        check(c)?;
        let m = &node.metadata;
        if m.is_dir() {
            continue;
        }
        if let Some((anchor, count, expected, hash, target)) = groups.get_mut(&identity(m)) {
            if *expected != m.nlink() {
                return Err(Error::Invalid("hardlink topology changed"));
            }
            *count += 1;
            charge(
                remaining,
                anchor.as_os_str().len() as u64
                    + target.as_ref().map_or(0, |p| p.as_os_str().len() as u64),
            )?;
            node.anchor = anchor.clone();
            node.hash = *hash;
            node.target = target.clone();
            continue;
        }
        let absolute = root.join(path);
        if m.is_file() {
            bytes = bytes
                .checked_add(m.len())
                .ok_or(Error::Limit("inventory bytes"))?;
            if bytes > limits.max_layer_bytes {
                return Err(Error::Limit("inventory bytes"));
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOATIME)
                .open(&absolute)?;
            let opened = file.metadata()?;
            if identity(&opened) != identity(m) || !opened.is_file() || opened.len() != m.len() {
                return Err(Error::Invalid("source changed"));
            }
            let mut hash = Sha256::new();
            let mut left = m.len();
            let mut buffer = [0u8; 65536];
            while left != 0 {
                check(c)?;
                let n = left.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..n])?;
                hash.update(&buffer[..n]);
                left -= n as u64;
            }
            let after = file.metadata()?;
            if after.len() != m.len()
                || after.mtime() != m.mtime()
                || after.mtime_nsec() != m.mtime_nsec()
                || after.ctime() != m.ctime()
                || after.ctime_nsec() != m.ctime_nsec()
            {
                return Err(Error::Invalid("source changed"));
            }
            node.hash = Some(hash.finalize().into());
        } else {
            node.target = Some(if let Some(targets) = targets {
                let target = targets
                    .entries
                    .get(path)
                    .and_then(|n| n.target.as_ref())
                    .ok_or(Error::Invalid(
                        "baseline symlink absent from verified replay",
                    ))?;
                if target.as_os_str().len() as u64 != m.len() {
                    return Err(Error::Invalid("baseline symlink size differs"));
                }
                charge(remaining, m.len())?;
                target.clone()
            } else {
                bounded_link(&absolute, m.len(), remaining)?
            });
        }
        charge(
            remaining,
            path.as_os_str().len() as u64
                + node
                    .target
                    .as_ref()
                    .map_or(0, |p| p.as_os_str().len() as u64)
                + 256,
        )?;
        groups.insert(
            identity(m),
            (path.clone(), 1, m.nlink(), node.hash, node.target.clone()),
        );
    }
    if groups
        .values()
        .any(|(_, count, expected, _, _)| count != expected)
    {
        return Err(Error::Invalid("hardlinks outside source tree"));
    }
    Ok(Inventory { entries })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn capture(
    root: &Path,
    layout: &Path,
    reference: Option<&str>,
    workspace: &Path,
    limits: Limits,
    image_limits: crate::image::Limits,
    layer_limits: crate::layer::Limits,
    replay_limits: ReplayLimits,
    c: &impl Fn() -> bool,
) -> Result<Baseline, Error> {
    check(c)?;
    canonical_dir(root)?;
    canonical_dir(layout)?;
    canonical_dir(workspace)?;
    if workspace.starts_with(root) || layout.starts_with(root) || root.starts_with(layout) {
        return Err(Error::Invalid("baseline workspace/layout overlaps root"));
    }
    let mut preflight = Preflight {
        forbidden: workspace
            .ancestors()
            .map(|p| fs::metadata(p).map(|m| identity(&m)))
            .collect::<io::Result<Vec<_>>>()?,
        directories: HashMap::new(),
        mount: mount_id(root)?,
        remaining_entries: limits.max_entries,
        remaining_metadata: limits.max_metadata_bytes,
        cancelled: c,
        noatime: true,
    };
    preflight.visit(root, 0)?;
    drop(preflight);
    let metadata =
        crate::image::load_layout(layout, reference, image_limits, c).map_err(Error::Image)?;
    let store = BlobStore::open(layout)?;
    let temp = tempfile::tempdir_in(workspace)?;
    let result = (|| {
        let replay = temp.path().join("root");
        fs::create_dir(&replay)?;
        let mut bytes = 0u64;
        let mut entries = 0usize;
        for (descriptor, diff_id) in metadata.layers.iter().zip(&metadata.diff_ids) {
            check(c)?;
            let mut bounded = layer_limits;
            bounded.max_uncompressed_bytes = bounded
                .max_uncompressed_bytes
                .min(replay_limits.max_bytes.saturating_sub(bytes));
            bounded.max_entries = bounded
                .max_entries
                .min(replay_limits.max_entries.saturating_sub(entries));
            let mut layer =
                crate::layer::verify(&store, descriptor, diff_id, temp.path(), bounded, c)
                    .map_err(Error::Layer)?;
            bytes = bytes
                .checked_add(layer.size())
                .ok_or(Error::Limit("replay bytes"))?;
            entries = entries
                .checked_add(layer.entries().len())
                .ok_or(Error::Limit("replay entries"))?;
            crate::rootfs::apply_layer(&replay, &mut layer, c).map_err(Error::Replay)?;
        }
        let mut remaining = limits.max_metadata_bytes;
        // Bound the retained base JSON before cloning any caller-controlled fields.
        json_bytes(&metadata.manifest, &mut remaining)?;
        json_bytes(&metadata.config, &mut remaining)?;
        let replay_inventory = inventory(&replay, limits, &mut remaining, None, c)?;
        let inventory = inventory(root, limits, &mut remaining, Some(&replay_inventory), c)?;
        let history = metadata.config.get("history").cloned();
        validate_history(history.as_ref(), metadata.layers.len())?;
        Ok(Baseline {
            state: State {
                inventory,
                layout: Some(layout.to_owned()),
                layers: metadata.layers,
                diff_ids: metadata.diff_ids,
                history,
                blob_limit: image_limits.max_layer_bytes,
            },
        })
    })();
    temp.close()?;
    result
}

pub(crate) fn scratch(
    root: &Path,
    limits: Limits,
    c: &impl Fn() -> bool,
) -> Result<Baseline, Error> {
    canonical_dir(root)?;
    if names(root, c)?.next().transpose()?.is_some() {
        return Err(Error::Invalid("scratch baseline must be empty"));
    }
    let mut remaining = limits.max_metadata_bytes;
    let inventory = inventory(root, limits, &mut remaining, None, c)?;
    if inventory.entries.len() != 1 {
        return Err(Error::Invalid("scratch baseline must be empty"));
    }
    Ok(Baseline {
        state: State {
            inventory,
            layout: None,
            layers: Vec::new(),
            diff_ids: Vec::new(),
            history: None,
            blob_limit: 0,
        },
    })
}

fn validate_history(history: Option<&Value>, layers: usize) -> Result<(), Error> {
    if let Some(history) = history {
        let list = history
            .as_array()
            .ok_or(Error::Invalid("base history must be an array"))?;
        let mut count = 0usize;
        for entry in list {
            let entry = entry
                .as_object()
                .ok_or(Error::Invalid("base history entry must be an object"))?;
            match entry.get("empty_layer") {
                None | Some(Value::Bool(false)) => count += 1,
                Some(Value::Bool(true)) => (),
                _ => return Err(Error::Invalid("base history empty_layer must be boolean")),
            }
        }
        if count != layers {
            return Err(Error::Invalid("base history layer count differs"));
        }
    }
    Ok(())
}

fn equal(a: &Node, b: &Node) -> bool {
    let x = &a.metadata;
    let y = &b.metadata;
    x.mode() == y.mode()
        && x.uid() == y.uid()
        && x.gid() == y.gid()
        && x.mtime() == y.mtime()
        && x.mtime_nsec() == y.mtime_nsec()
        && x.atime() == y.atime()
        && x.atime_nsec() == y.atime_nsec()
        && (x.is_dir() || (x.len() == y.len() && x.nlink() == y.nlink()))
        && a.attrs == b.attrs
        && a.hash == b.hash
        && a.target == b.target
        && a.anchor == b.anchor
}
pub(super) struct Plan {
    pub(super) inventory: Inventory,
    pub(super) changed: BTreeSet<PathBuf>,
    pub(super) whiteouts: Vec<PathBuf>,
}
pub(super) fn plan(
    root: &Path,
    base: &Baseline,
    limits: Limits,
    remaining: &mut u64,
    c: &impl Fn() -> bool,
) -> Result<Plan, Error> {
    let inventory = inventory(root, limits, remaining, None, c)?;
    let mut changed = BTreeSet::new();
    let mut groups = BTreeSet::new();
    for (path, node) in &inventory.entries {
        check(c)?;
        if !base
            .state
            .inventory
            .entries
            .get(path)
            .is_some_and(|old| equal(node, old))
        {
            charge(
                remaining,
                path.as_os_str().len() as u64 + node.anchor.as_os_str().len() as u64 + 256,
            )?;
            changed.insert(path.clone());
            if !node.metadata.is_dir() {
                groups.insert(node.anchor.clone());
            }
        }
    }
    for (path, node) in &inventory.entries {
        check(c)?;
        if groups.contains(&node.anchor) && !changed.contains(path) {
            charge(remaining, path.as_os_str().len() as u64 + 128)?;
            changed.insert(path.clone());
        }
    }
    let mut whiteouts = Vec::new();
    for path in base.state.inventory.entries.keys() {
        check(c)?;
        if inventory.entries.contains_key(path) {
            continue;
        }
        // Removing/replacing an ancestor already removes this lower descendant.
        if path
            .parent()
            .into_iter()
            .flat_map(Path::ancestors)
            .any(|p| {
                !inventory
                    .entries
                    .get(p)
                    .is_some_and(|n| n.metadata.is_dir())
            })
        {
            continue;
        }
        charge(remaining, path.as_os_str().len() as u64 + 132)?;
        let mut name = b".wh.".to_vec();
        name.extend_from_slice(path.file_name().unwrap().as_bytes());
        whiteouts.push(path.parent().unwrap().join(OsString::from_vec(name)));
    }
    let mut parents = BTreeSet::new();
    for path in changed.iter().chain(whiteouts.iter()) {
        check(c)?;
        for parent in path.parent().into_iter().flat_map(Path::ancestors) {
            if !changed.contains(parent) && !parents.contains(parent) {
                charge(remaining, parent.as_os_str().len() as u64 + 128)?;
                parents.insert(parent.to_owned());
            }
        }
    }
    for parent in parents {
        if inventory
            .entries
            .get(&parent)
            .is_some_and(|n| n.metadata.is_dir())
        {
            changed.insert(parent);
        }
    }
    // Root may have no representation in any original base layer.
    changed.insert(PathBuf::new());
    Ok(Plan {
        inventory,
        changed,
        whiteouts,
    })
}

pub(super) fn inherit(
    base: &Baseline,
    store: &BlobStore,
    delta: &Descriptor,
    output: &mut Value,
    remaining: &mut u64,
    c: &impl Fn() -> bool,
) -> Result<Vec<Descriptor>, Error> {
    let state = &base.state;
    // Charge all base descriptor and diff-id copies before allocation.
    for descriptor in &state.layers {
        json_bytes(&serde_json::to_value(descriptor)?, remaining)?;
    }
    charge(remaining, state.diff_ids.len() as u64 * 128)?;
    if let Some(layout) = &state.layout {
        let source = BlobStore::open(layout)?;
        for descriptor in &state.layers {
            check(c)?;
            // Public output is mutable; only ManagedCache may share blob inodes.
            let file = source.open_verified(descriptor, state.blob_limit, c)?;
            store.ingest(file, descriptor, state.blob_limit, c)?;
        }
    }
    let mut ids: Vec<Value> = state
        .diff_ids
        .iter()
        .map(|id| Value::String(id.as_str().to_owned()))
        .collect();
    ids.push(Value::String(delta.digest.clone()));
    output["rootfs"] = json!({"type":"layers", "diff_ids":ids});
    if let Some(history) = &state.history {
        json_bytes(history, remaining)?;
        let mut history = history.as_array().unwrap().clone();
        history.push(json!({"created_by":"Weld cumulative filesystem delta export"}));
        output["history"] = Value::Array(history);
    } else if state.layers.is_empty() {
        output["history"] = json!([{"created_by":"Weld cumulative filesystem delta export"}]);
    } else {
        // Optional history absent in base: do not invent entries for its layers.
        output.as_object_mut().unwrap().remove("history");
    }
    let mut layers = state.layers.clone();
    layers.push(delta.clone());
    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    const LIMITS: Limits = Limits {
        max_layer_bytes: 16 * 1024 * 1024,
        max_entries: 1000,
        max_metadata_bytes: 8 * 1024 * 1024,
    };
    fn image_limits() -> crate::image::Limits {
        crate::image::Limits {
            max_metadata_bytes: LIMITS.max_metadata_bytes,
            max_total_metadata_bytes: LIMITS.max_metadata_bytes,
            max_descriptors: 100,
            max_layer_bytes: LIMITS.max_layer_bytes,
            max_total_layer_bytes: LIMITS.max_layer_bytes * 4,
        }
    }
    fn layer_limits() -> crate::layer::Limits {
        crate::layer::Limits {
            max_blob_bytes: LIMITS.max_layer_bytes,
            max_uncompressed_bytes: LIMITS.max_layer_bytes,
            max_entries: LIMITS.max_entries,
            max_metadata_bytes: LIMITS.max_metadata_bytes,
            max_gzip_header_bytes: 1024,
        }
    }
    fn config() -> Value {
        json!({"os":"linux","architecture":"amd64","config":{"Env":["A=B"]}})
    }
    fn load(path: &Path) -> crate::image::ImageMetadata {
        crate::image::load_layout(path, None, image_limits(), || false).unwrap()
    }
    fn replay(layout: &Path, root: &Path, work: &Path) -> crate::image::ImageMetadata {
        fs::create_dir(root).unwrap();
        let image = load(layout);
        let store = BlobStore::open(layout).unwrap();
        for (d, id) in image.layers.iter().zip(&image.diff_ids) {
            let mut layer =
                crate::layer::verify(&store, d, id, work, layer_limits(), || false).unwrap();
            crate::rootfs::apply_layer(root, &mut layer, || false).unwrap();
        }
        image
    }
    fn capture(root: &Path, layout: &Path, work: &Path) -> Baseline {
        Baseline::capture(
            root,
            layout,
            None,
            work,
            LIMITS,
            image_limits(),
            layer_limits(),
            ReplayLimits {
                max_bytes: LIMITS.max_layer_bytes * 4,
                max_entries: LIMITS.max_entries * 4,
            },
            || false,
        )
        .unwrap()
    }
    fn times(path: &Path, future_atime: bool) {
        let p = CString::new(path.as_os_str().as_bytes()).unwrap();
        let ts = [
            libc::timespec {
                tv_sec: if future_atime { 4_000_000_000 } else { 1 },
                tv_nsec: 123456789,
            },
            libc::timespec {
                tv_sec: 1234,
                tv_nsec: 987654321,
            },
        ];
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    p.as_ptr(),
                    ts.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            },
            0
        );
    }
    fn attr(path: &Path, name: &std::ffi::CStr, value: &[u8]) {
        let p = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::lsetxattr(
                    p.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0
        );
    }
    fn snapshot(root: &Path) -> Inventory {
        inventory(
            root,
            LIMITS,
            &mut LIMITS.max_metadata_bytes.clone(),
            None,
            &|| false,
        )
        .unwrap()
    }
    fn equivalent(a: &Inventory, b: &Inventory) {
        assert_eq!(
            a.entries.keys().collect::<Vec<_>>(),
            b.entries.keys().collect::<Vec<_>>()
        );
        for (path, node) in &a.entries {
            assert!(equal(node, &b.entries[path]), "different entry: {path:?}");
        }
    }
    fn delta_entries(layout: &Path, work: &Path) -> crate::layer::VerifiedLayer {
        let image = load(layout);
        crate::layer::verify(
            &BlobStore::open(layout).unwrap(),
            image.layers.last().unwrap(),
            image.diff_ids.last().unwrap(),
            work,
            layer_limits(),
            || false,
        )
        .unwrap()
    }

    #[test]
    fn delta_replays_replacements_deletes_links_raw_names_and_metadata() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let work = temp.path();
        let seed = work.join("seed");
        fs::create_dir(&seed).unwrap();
        fs::create_dir(seed.join("dir")).unwrap();
        fs::write(seed.join("untouched"), vec![7; 1024 * 1024]).unwrap();
        fs::write(seed.join("dir/change"), b"old").unwrap();
        fs::write(seed.join("remove"), b"gone").unwrap();
        fs::write(seed.join("recreate"), b"old").unwrap();
        fs::write(seed.join("file-to-dir"), b"old").unwrap();
        fs::create_dir(seed.join("dir-to-file")).unwrap();
        fs::write(seed.join("dir-to-file/child"), b"old").unwrap();
        fs::write(seed.join("split-a"), b"linked").unwrap();
        fs::hard_link(seed.join("split-a"), seed.join("split-b")).unwrap();
        fs::write(seed.join("join-a"), b"joined").unwrap();
        fs::write(seed.join("join-b"), b"joined").unwrap();
        fs::write(seed.join("grow-a"), b"grow").unwrap();
        symlink("old-target", seed.join("link")).unwrap();
        fs::hard_link(seed.join("link"), seed.join("link-alias")).unwrap();
        attr(&seed, c"user.root", b"root");
        attr(&seed.join("dir/change"), c"user.remove", b"remove-me");
        times(&seed, false);
        times(&seed.join("link"), false);
        let base = work.join("base");
        export_layout(&seed, &base, &config(), LIMITS, || false).unwrap();
        // Descriptor annotations and unknown descriptor fields must survive exactly.
        let mut original = load(&base);
        original.layers[0]
            .annotations
            .insert("test.annotation".into(), "preserved".into());
        original.layers[0]
            .extensions
            .insert("test.extension".into(), json!({"keep":true}));
        original.manifest["layers"] = serde_json::to_value(&original.layers).unwrap();
        let descriptor = blob(
            &BlobStore::open(&base).unwrap(),
            MANIFEST,
            &serde_json::to_vec(&original.manifest).unwrap(),
            &|| false,
        )
        .unwrap();
        fs::write(
            base.join("index.json"),
            serde_json::to_vec(
                &json!({"schemaVersion":2,"mediaType":INDEX,"manifests":[descriptor]}),
            )
            .unwrap(),
        )
        .unwrap();
        let current = work.join("current");
        replay(&base, &current, work);
        let before_link = fs::symlink_metadata(current.join("link")).unwrap();
        let before_root = fs::metadata(&current).unwrap();
        let baseline = capture(&current, &base, work);
        for (path, before) in [
            (&current, before_root),
            (&current.join("link"), before_link),
        ] {
            let after = fs::symlink_metadata(path).unwrap();
            assert_eq!(
                (
                    before.atime(),
                    before.atime_nsec(),
                    before.ctime(),
                    before.ctime_nsec()
                ),
                (
                    after.atime(),
                    after.atime_nsec(),
                    after.ctime(),
                    after.ctime_nsec()
                )
            );
        }
        fs::write(current.join("dir/change"), b"new contents").unwrap();
        let p = CString::new(current.join("dir/change").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::lremovexattr(p.as_ptr(), c"user.remove".as_ptr()) },
            0
        );
        attr(&current.join("dir/change"), c"user.binary", b"binary\0\n");
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(unsafe { libc::chown(p.as_ptr(), 123, 456) }, 0);
        }
        fs::set_permissions(
            current.join("dir/change"),
            fs::Permissions::from_mode(0o6751),
        )
        .unwrap();
        if unsafe { libc::geteuid() } == 0 {
            attr(
                &current.join("dir/change"),
                c"security.capability",
                &[1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
        }
        fs::remove_file(current.join("remove")).unwrap();
        fs::remove_file(current.join("recreate")).unwrap();
        fs::write(current.join("recreate"), b"new").unwrap();
        fs::remove_file(current.join("file-to-dir")).unwrap();
        fs::create_dir(current.join("file-to-dir")).unwrap();
        fs::write(current.join("file-to-dir/child"), b"new").unwrap();
        fs::remove_dir_all(current.join("dir-to-file")).unwrap();
        fs::write(current.join("dir-to-file"), b"new").unwrap();
        fs::remove_file(current.join("split-b")).unwrap();
        fs::write(current.join("split-b"), b"linked").unwrap();
        fs::remove_file(current.join("join-b")).unwrap();
        fs::hard_link(current.join("join-a"), current.join("join-b")).unwrap();
        fs::hard_link(current.join("grow-a"), current.join("grow-b")).unwrap();
        fs::remove_file(current.join("link")).unwrap();
        fs::remove_file(current.join("link-alias")).unwrap();
        symlink("new-target", current.join("link")).unwrap();
        fs::hard_link(current.join("link"), current.join("link-alias")).unwrap();
        let raw = OsString::from_vec(b"raw\xff:back\\slash".to_vec());
        fs::write(current.join(raw), b"raw").unwrap();
        // Future atime makes the expected-inventory read observationally inert.
        times(&current.join("link"), true);
        times(&current, false);
        let mut expected = snapshot(&current);
        // Force readlink to update live atime, while retaining the pre-read
        // timestamps of both aliases in the expected archived snapshot.
        times(&current.join("link"), false);
        for name in ["link", "link-alias"] {
            expected.entries.get_mut(Path::new(name)).unwrap().metadata =
                fs::symlink_metadata(current.join(name)).unwrap();
        }
        let output = work.join("output");
        export_delta_layout(&current, &output, &config(), &baseline, LIMITS, || false).unwrap();
        let result = work.join("result");
        let image = replay(&output, &result, work);
        equivalent(&expected, &snapshot(&result));
        assert_eq!(image.layers[0], original.layers[0]);
        assert_eq!(image.diff_ids[0], original.diff_ids[0]);
        assert_eq!(image.config["history"][0], original.config["history"][0]);
        assert_eq!(image.config["history"].as_array().unwrap().len(), 2);
        assert!(image.layers[1].size < 40_000);
        let entries = delta_entries(&output, work);
        assert!(!entries.entries().iter().any(|e| e.path == b"untouched"));
        assert!(entries.entries().iter().any(|e| e.path == b".wh.remove"));
        assert!(
            !entries
                .entries()
                .iter()
                .any(|e| e.path == b"dir-to-file/.wh.child")
        );
        assert_eq!(
            entries
                .entries()
                .iter()
                .filter(|e| e.path.is_empty())
                .count(),
            1
        );
        let normalized = work.join("normalized");
        replay(&output, &normalized, work);
        let again = work.join("again");
        export_delta_layout(&normalized, &again, &config(), &baseline, LIMITS, || false).unwrap();
        assert_eq!(
            load(&again).selected,
            image.selected,
            "cold/hit normalization changed export bytes"
        );
    }

    #[test]
    fn scratch_bounds_cancellation_and_exclusive_destination() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let work = temp.path();
        let root = work.join("root");
        fs::create_dir(&root).unwrap();
        let baseline = Baseline::scratch(&root, LIMITS, || false).unwrap();
        fs::write(root.join("app"), b"app").unwrap();
        assert!(Baseline::scratch(&root, LIMITS, || false).is_err());
        let output = work.join("output");
        assert!(matches!(
            export_delta_layout(&root, &output, &config(), &baseline, LIMITS, || true),
            Err(Error::Cancelled)
        ));
        assert!(!output.exists());
        let polls = std::cell::Cell::new(0);
        assert!(matches!(
            export_delta_layout(&root, &output, &config(), &baseline, LIMITS, || {
                polls.set(polls.get() + 1);
                polls.get() > 5
            }),
            Err(Error::Cancelled)
        ));
        assert!(!output.join("index.json").exists());
        let mut small = LIMITS;
        small.max_metadata_bytes = 1;
        assert!(
            export_delta_layout(&root, &output, &config(), &baseline, small, || false).is_err()
        );
        assert!(!output.exists());
        export_delta_layout(&root, &output, &config(), &baseline, LIMITS, || false).unwrap();
        assert!(
            export_delta_layout(&root, &output, &config(), &baseline, LIMITS, || false).is_err()
        );
        let result = work.join("result");
        replay(&output, &result, work);
        equivalent(&snapshot(&root), &snapshot(&result));
        fs::write(root.join(".wh.reserved"), b"no").unwrap();
        assert!(
            export_delta_layout(
                &root,
                &work.join("bad"),
                &config(),
                &baseline,
                LIMITS,
                || false
            )
            .is_err()
        );
    }

    #[test]
    fn unchanged_child_keeps_parent_prefix_and_only_emits_root() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let work = temp.path();
        let root = work.join("root");
        fs::create_dir(&root).unwrap();
        let scratch = Baseline::scratch(&root, LIMITS, || false).unwrap();
        fs::write(root.join("app"), b"payload").unwrap();
        let parent = work.join("parent");
        export_delta_layout(&root, &parent, &config(), &scratch, LIMITS, || false).unwrap();
        let current = work.join("current");
        let original = replay(&parent, &current, work);
        let baseline = capture(&current, &parent, work);
        let child = work.join("child");
        export_delta_layout(&current, &child, &config(), &baseline, LIMITS, || false).unwrap();
        let output = load(&child);
        assert_eq!(
            &output.layers[..original.layers.len()],
            original.layers.as_slice()
        );
        assert_eq!(
            &output.diff_ids[..original.diff_ids.len()],
            original.diff_ids.as_slice()
        );
        let entries = delta_entries(&child, work);
        assert_eq!(entries.entries().len(), 1);
        assert!(entries.entries()[0].path.is_empty());
        let mut bound = ReplayLimits {
            max_bytes: 1,
            max_entries: LIMITS.max_entries,
        };
        assert!(
            Baseline::capture(
                &current,
                &parent,
                None,
                work,
                LIMITS,
                image_limits(),
                layer_limits(),
                bound,
                || false
            )
            .is_err()
        );
        bound.max_bytes = LIMITS.max_layer_bytes;
        bound.max_entries = 0;
        assert!(
            Baseline::capture(
                &current,
                &parent,
                None,
                work,
                LIMITS,
                image_limits(),
                layer_limits(),
                bound,
                || false
            )
            .is_err()
        );
        let grandchild_root = work.join("grandchild-root");
        replay(&child, &grandchild_root, work);
        let inherited = capture(&grandchild_root, &child, work);
        let grandchild = work.join("grandchild");
        export_delta_layout(
            &grandchild_root,
            &grandchild,
            &config(),
            &inherited,
            LIMITS,
            || false,
        )
        .unwrap();
        assert_eq!(&load(&grandchild).layers[..2], output.layers.as_slice());
        bound.max_bytes = output.layers.iter().map(|d| d.size as u64).sum::<u64>() - 1;
        bound.max_entries = LIMITS.max_entries;
        assert!(
            Baseline::capture(
                &grandchild_root,
                &child,
                None,
                work,
                LIMITS,
                image_limits(),
                layer_limits(),
                bound,
                || false
            )
            .is_err()
        );
    }

    #[test]
    fn absent_base_root_header_preserves_actual_root_and_absent_history() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let work = temp.path();
        let base = work.join("base");
        fs::create_dir(&base).unwrap();
        let store = BlobStore::open(&base).unwrap();
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(3);
        header.set_mode(0o644);
        header.set_uid(unsafe { libc::geteuid() } as u64);
        header.set_gid(unsafe { libc::getegid() } as u64);
        header.set_mtime(10);
        tar.append_data(&mut header, "app", &b"app"[..]).unwrap();
        let layer = blob(&store, LAYER, &tar.into_inner().unwrap(), &|| false).unwrap();
        let mut conf = config();
        conf["rootfs"] = json!({"type":"layers","diff_ids":[layer.digest]});
        let config_blob = blob(&store, CONFIG, &serde_json::to_vec(&conf).unwrap(), &|| {
            false
        })
        .unwrap();
        let manifest = blob(&store, MANIFEST, &serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":MANIFEST,"config":config_blob,"layers":[layer]})).unwrap(), &|| false).unwrap();
        fs::write(
            base.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            base.join("index.json"),
            serde_json::to_vec(
                &json!({"schemaVersion":2,"mediaType":INDEX,"manifests":[manifest]}),
            )
            .unwrap(),
        )
        .unwrap();
        let current = work.join("current");
        replay(&base, &current, work);
        times(&current, false);
        attr(&current, c"user.root", b"actual root");
        fs::set_permissions(&current, fs::Permissions::from_mode(0o751)).unwrap();
        let baseline = capture(&current, &base, work);
        let expected = snapshot(&current);
        let output = work.join("output");
        export_delta_layout(&current, &output, &config(), &baseline, LIMITS, || false).unwrap();
        assert!(load(&output).config.get("history").is_none());
        let entries = delta_entries(&output, work);
        assert_eq!(entries.entries().len(), 1);
        let result = work.join("result");
        replay(&output, &result, work);
        equivalent(&expected, &snapshot(&result));
    }

    #[test]
    fn flattened_readable_unowned_directories_keep_original_privilege_contract() {
        const CHILD: &str = "WELD_EXPORT_UNOWNED_CHILD";
        if let Some(work) = std::env::var_os(CHILD) {
            let work = PathBuf::from(work);
            assert_eq!(unsafe { libc::geteuid() }, 65534);
            assert!(
                fs::read_to_string("/proc/self/status")
                    .unwrap()
                    .lines()
                    .any(|line| line == "CapEff:\t0000000000000000")
            );
            export_layout(
                &work.join("root"),
                &work.join("output"),
                &config(),
                LIMITS,
                || false,
            )
            .unwrap();
            assert!(
                Baseline::scratch(&work.join("root"), LIMITS, || false).is_err(),
                "strict baseline must not fall back from O_NOATIME"
            );
            return;
        }
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
        fs::create_dir(temp.path().join("root")).unwrap();
        fs::set_permissions(temp.path().join("root"), fs::Permissions::from_mode(0o755)).unwrap();
        use std::os::unix::process::CommandExt;
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("export::linux::delta::tests::flattened_readable_unowned_directories_keep_original_privilege_contract")
            .arg("--nocapture").env(CHILD, temp.path()).uid(65534).gid(65534).status().unwrap();
        assert!(status.success());
    }

    #[test]
    fn corrupt_retained_base_blob_is_not_published_or_flattened() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let work = temp.path();
        let root = work.join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("app"), b"app").unwrap();
        let base = work.join("base");
        export_layout(&root, &base, &config(), LIMITS, || false).unwrap();
        let current = work.join("current");
        let image = replay(&base, &current, work);
        let baseline = capture(&current, &base, work);
        let blob = base
            .join("blobs/sha256")
            .join(image.layers[0].digest.strip_prefix("sha256:").unwrap());
        fs::write(blob, b"corrupt").unwrap();
        let output = work.join("output");
        assert!(
            export_delta_layout(&current, &output, &config(), &baseline, LIMITS, || false).is_err()
        );
        assert!(!output.join("index.json").exists());
    }

    #[test]
    fn public_base_blobs_have_independent_inodes_and_bidirectional_mutation_isolation() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let work = temp.path();
        let root = work.join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("app"), b"app").unwrap();
        let base = work.join("base");
        export_layout(&root, &base, &config(), LIMITS, || false).unwrap();
        let current = work.join("current");
        let image = replay(&base, &current, work);
        let baseline = capture(&current, &base, work);
        let first = work.join("first");
        let second = work.join("second");
        export_delta_layout(&current, &first, &config(), &baseline, LIMITS, || false).unwrap();
        export_delta_layout_created(
            &current,
            &second,
            &config(),
            &baseline,
            LIMITS,
            || false,
            || Ok(()),
        )
        .unwrap();
        let relative =
            Path::new("blobs/sha256").join(image.layers[0].digest.strip_prefix("sha256:").unwrap());
        let source = base.join(&relative);
        let first_blob = first.join(&relative);
        let second_blob = second.join(&relative);
        let original = fs::read(&source).unwrap();
        assert_eq!(fs::read(&first_blob).unwrap(), original);
        assert_eq!(fs::read(&second_blob).unwrap(), original);
        assert_eq!(load(&first).layers[0], image.layers[0]);
        assert_eq!(load(&second).layers[0], image.layers[0]);
        let identities =
            [&source, &first_blob, &second_blob].map(|p| identity(&fs::metadata(p).unwrap()));
        assert_ne!(identities[0], identities[1]);
        assert_ne!(identities[0], identities[2]);
        assert_ne!(identities[1], identities[2]);
        // Open without truncation/replacement, so this catches shared inodes.
        OpenOptions::new()
            .write(true)
            .open(&first_blob)
            .unwrap()
            .write_all(b"output mutation")
            .unwrap();
        assert_eq!(identity(&fs::metadata(&first_blob).unwrap()), identities[1]);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read(&second_blob).unwrap(), original);
        let mutated_output = fs::read(&first_blob).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap()
            .write_all(b"source mutation")
            .unwrap();
        assert_eq!(identity(&fs::metadata(&source).unwrap()), identities[0]);
        assert_eq!(fs::read(&first_blob).unwrap(), mutated_output);
        assert_eq!(fs::read(&second_blob).unwrap(), original);
        load(&second); // Independent exported bytes still verify after both writes.
    }

    #[test]
    #[ignore = "uses the local Alpine OCI fixture; run explicitly as its owner/root"]
    fn alpine_baseline_capture_overhead() {
        let base = Path::new("/tmp/weld-pod-atime-repro-_atsyth0/alpine");
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let work = temp.path();
        let root = work.join("root");
        let image = replay(base, &root, work);
        let start = std::time::Instant::now();
        let baseline = capture(&root, base, work);
        let capture_time = start.elapsed();
        fs::write(root.join("weld-delta-app"), b"bounded app change\n").unwrap();
        let output = work.join("output");
        let start = std::time::Instant::now();
        export_delta_layout(&root, &output, &config(), &baseline, LIMITS, || false).unwrap();
        let export_time = start.elapsed();
        let result = load(&output);
        assert_eq!(
            &result.layers[..image.layers.len()],
            image.layers.as_slice()
        );
        assert!(result.layers.last().unwrap().size < 10_000);
        let replayed = work.join("replayed");
        replay(&output, &replayed, work);
        assert_eq!(
            fs::read(replayed.join("weld-delta-app")).unwrap(),
            b"bounded app change\n"
        );
        eprintln!(
            "Alpine capture={capture_time:?} export={export_time:?} base_compressed_bytes={} delta_bytes={} entries={}",
            image.layers.iter().map(|d| d.size).sum::<i64>(),
            result.layers.last().unwrap().size,
            baseline.state.inventory.entries.len()
        );
    }
}
