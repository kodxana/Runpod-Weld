//! Explicit cleanup only. No saved plan or caller-supplied deletion path is accepted.
use crate::{
    cleanup_plan::{Item, Plan},
    store_inventory::Limits,
};
use serde::Serialize;
use std::{io, path::Path};

pub use crate::cleanup_plan::Request as Selection;

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub dry_run: bool,
    pub status: &'static str,
    /// Payloads physically removed; status remains failed if finalization fails.
    pub removed: Vec<Item>,
    pub recovered: Vec<Item>,
    pub plan: Option<Plan>,
    pub failure: Option<String>,
}

pub fn apply(
    store: &Path,
    selection: Selection,
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> io::Result<Report> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(store, selection, limits, &cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store, selection, limits, cancelled);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cleanup requires Linux openat2, statx and renameat2",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::{
        build_record::{self, Component, Identity, Record, identity, open_dir},
        cleanup_plan,
        oci::ManagedCache,
        store_inventory::{
            self,
            cache::{self, Kind, Retirement, Snapshot},
        },
        store_lease::{ExclusiveStoreLease, StoreLease},
    };
    use serde::{Deserialize, de::DeserializeOwned};
    use sha2::{Digest, Sha256};
    use std::{
        ffi::{CString, OsString},
        fs::{self, File},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, PermissionsExt},
            },
        },
        path::PathBuf,
    };

    const PREFIX: &str = ".cleanup-txn-";
    const JOURNAL: &str = "journal.json";
    const PAYLOAD: &str = "payload";
    const MAX_JOURNAL: usize = build_record::MAX_BYTES + 8192;

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
    enum Target {
        Build {
            record: Box<Record>,
            component: Vec<Component>,
        },
        Tag {
            reference: String,
            digest: String,
        },
    }
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Journal {
        version: u32,
        store: Identity,
        transaction: Identity,
        parent: Identity,
        object: Identity,
        mount: u64,
        original: Vec<Component>,
        target: Target,
        deleting: bool,
    }
    impl Journal {
        fn path(&self) -> PathBuf {
            self.original.iter().map(Component::as_str).collect()
        }
        fn shape(&self) -> io::Result<()> {
            if self.version != 1 {
                return Err(invalid("unsupported cleanup journal"));
            }
            match &self.target {
                Target::Build { record, component } => {
                    record.validate_shape()?;
                    let mut expected = vec![record.run_id.clone()];
                    expected.extend(component.clone());
                    if self.original != expected
                        || record.store != self.store
                        || component.iter().map(Component::as_str).collect::<Vec<_>>() == ["stages"]
                        || record.removed.contains(component)
                        || !record
                            .owned
                            .iter()
                            .any(|o| o.components == *component && o.identity == self.object)
                    {
                        return Err(invalid("invalid journal ownership"));
                    }
                }
                Target::Tag { reference, digest } => {
                    let canonical =
                        crate::registry::reference(reference, false).map_err(invalid)?;
                    let name = format!("tag-{:x}.json", Sha256::digest(reference.as_bytes()));
                    if canonical != *reference
                        || self.original.len() != 1
                        || self.original[0].as_str() != name
                        || digest.len() != 64
                        || !digest.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(invalid("invalid journal tag"));
                    }
                }
            }
            Ok(())
        }
    }
    fn invalid(message: impl Into<String>) -> io::Error {
        io::Error::other(message.into())
    }
    fn pinned(dir: &File) -> PathBuf {
        format!("/proc/self/fd/{}", dir.as_raw_fd()).into()
    }
    fn cstr(path: &Path) -> io::Result<CString> {
        Ok(CString::new(path.as_os_str().as_bytes())?)
    }
    fn stat(dir: &File, name: &Path) -> io::Result<libc::statx> {
        let name = cstr(name)?;
        let mut st = unsafe { std::mem::zeroed::<libc::statx>() };
        let flags = libc::AT_SYMLINK_NOFOLLOW
            | if name.as_bytes().is_empty() {
                libc::AT_EMPTY_PATH
            } else {
                0
            };
        if unsafe {
            libc::statx(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags,
                libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
                &mut st,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if st.stx_mask & (libc::STATX_BASIC_STATS | libc::STATX_MNT_ID)
            != libc::STATX_BASIC_STATS | libc::STATX_MNT_ID
        {
            return Err(invalid("incomplete cleanup statx"));
        }
        Ok(st)
    }
    fn same(a: &libc::statx, b: &libc::statx) -> bool {
        (
            a.stx_dev_major,
            a.stx_dev_minor,
            a.stx_ino,
            a.stx_mnt_id,
            a.stx_mode,
        ) == (
            b.stx_dev_major,
            b.stx_dev_minor,
            b.stx_ino,
            b.stx_mnt_id,
            b.stx_mode,
        )
    }
    fn absent(dir: &File, name: &Path) -> io::Result<bool> {
        match stat(dir, name) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e),
        }
    }
    fn private(dir: &File) -> io::Result<()> {
        let m = dir.metadata()?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(invalid("nonprivate cleanup metadata"));
        }
        Ok(())
    }
    fn bytes(dir: &File, name: &Path, limit: usize) -> io::Result<Vec<u8>> {
        let name = cstr(name)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        private(&file)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > limit as u64 {
            return Err(invalid("unsafe cleanup metadata file"));
        }
        let mut data = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut data)?;
        if data.len() > limit {
            return Err(invalid("oversized cleanup metadata"));
        }
        Ok(data)
    }
    fn read<T: DeserializeOwned>(dir: &File, name: &str, limit: usize) -> io::Result<T> {
        serde_json::from_slice(&bytes(dir, Path::new(name), limit)?)
            .map_err(|_| invalid("malformed cleanup metadata"))
    }
    fn write<T: Serialize>(dir: &File, name: &str, value: &T, initial: bool) -> io::Result<()> {
        let mut temp = tempfile::Builder::new()
            .prefix(".cleanup-write-")
            .tempfile_in(pinned(dir))?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temp.write_all(&serde_json::to_vec(value)?)?;
        temp.as_file().sync_all()?;
        if initial {
            temp.persist_noclobber(pinned(dir).join(name))
                .map_err(|e| e.error)?;
        } else {
            temp.persist(pinned(dir).join(name)).map_err(|e| e.error)?;
        }
        dir.sync_all()
    }
    fn names(dir: &File) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        let mut bytes = 0usize;
        for entry in fs::read_dir(pinned(dir))? {
            let name = entry?.file_name();
            bytes = bytes.saturating_add(name.as_bytes().len());
            if names.len() >= 100_000 || bytes > 8 * 1024 * 1024 {
                return Err(invalid("cleanup directory enumeration limit"));
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
    fn rename(from: &File, name: &Path, to: &File, new: &Path) -> io::Result<()> {
        let (name, new) = (cstr(name)?, cstr(new)?);
        if unsafe {
            libc::renameat2(
                from.as_raw_fd(),
                name.as_ptr(),
                to.as_raw_fd(),
                new.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        from.sync_all()?;
        to.sync_all()
    }
    fn unlink(parent: &File, name: &Path, directory: bool) -> io::Result<()> {
        let name = cstr(name)?;
        if unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        parent.sync_all()
    }
    fn check_cancel(cancelled: &impl Fn() -> bool) -> io::Result<()> {
        if cancelled() {
            Err(invalid(
                "cleanup cancelled; explicit cleanup can recover the transaction",
            ))
        } else {
            Ok(())
        }
    }
    // No chmod, truncate, link following, or path-based recursive deletion.
    fn erase(
        parent: &File,
        name: &Path,
        mount: u64,
        depth: usize,
        budget: &mut usize,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<()> {
        check_cancel(cancelled)?;
        if name == Path::new("store.lock") {
            return Err(invalid("cleanup refuses nested store lease boundaries"));
        }
        *budget += 1;
        if *budget > limits.max_entries || depth > limits.max_depth {
            return Err(invalid("cleanup traversal limit"));
        }
        let before = stat(parent, name)?;
        if before.stx_mnt_id != mount {
            return Err(invalid("cleanup refuses nested mounts"));
        }
        let directory = before.stx_mode as u32 & libc::S_IFMT == libc::S_IFDIR;
        if directory {
            let child = open_dir(parent.as_raw_fd(), name)?;
            if !same(&before, &stat(&child, Path::new(""))?) {
                return Err(invalid("cleanup directory changed"));
            }
            for entry in names(&child)? {
                erase(
                    &child,
                    Path::new(&entry),
                    mount,
                    depth + 1,
                    budget,
                    limits,
                    cancelled,
                )?;
            }
        }
        check_cancel(cancelled)?;
        if !same(&before, &stat(parent, name)?) {
            return Err(invalid("cleanup entry changed"));
        }
        unlink(parent, name, directory)
    }
    fn parent(root: &File, journal: &Journal) -> io::Result<File> {
        let path = journal.path();
        let p = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = open_dir(root.as_raw_fd(), p)?;
        if identity(&dir.metadata()?) != journal.parent {
            return Err(invalid("cleanup parent changed"));
        }
        Ok(dir)
    }
    fn validate_object(parent: &File, name: &Path, journal: &Journal) -> io::Result<()> {
        let st = stat(parent, name)?;
        let id = Identity {
            device: libc::makedev(st.stx_dev_major, st.stx_dev_minor),
            inode: st.stx_ino,
        };
        let kind = st.stx_mode as u32 & libc::S_IFMT;
        if id != journal.object
            || st.stx_mnt_id != journal.mount
            || kind
                != match journal.target {
                    Target::Build { .. } => libc::S_IFDIR,
                    Target::Tag { .. } => libc::S_IFREG,
                }
        {
            return Err(invalid("cleanup object identity or mount changed"));
        }
        if let Target::Tag { digest, .. } = &journal.target {
            let data = bytes(parent, name, build_record::MAX_BYTES)?;
            if format!("{:x}", Sha256::digest(data)) != *digest {
                return Err(invalid("tag changed during cleanup"));
            }
        }
        Ok(())
    }
    fn record_state(root: &File, journal: &Journal, missing: bool, finish: bool) -> io::Result<()> {
        if let Target::Build { record, component } = &journal.target {
            let run = open_dir(root.as_raw_fd(), Path::new(record.run_id.as_str()))?;
            let current: Record = read(&run, build_record::FILE, build_record::MAX_BYTES)?;
            let mut after = record.clone();
            after.version = 2;
            after.removed.push(component.clone());
            after.validate_shape()?;
            if serde_json::to_vec(&after)?.len() > build_record::MAX_BYTES {
                return Err(invalid(
                    "removal tombstone would exceed ownership record limit",
                ));
            }
            let current_value = serde_json::to_value(&current)?;
            if current_value != serde_json::to_value(record)?
                && !(missing && current_value == serde_json::to_value(&after)?)
            {
                return Err(invalid("ownership record changed during cleanup"));
            }
            let validate = if missing { &after } else { record };
            validate.validate(root, &run, Path::new(record.run_id.as_str()), |_| Ok(()))?;
            if finish {
                write(&run, build_record::FILE, &after, false)?;
            }
        }
        Ok(())
    }
    fn retire(root: &File, name: &Path, dir: &File) -> io::Result<()> {
        if !same(&stat(root, name)?, &stat(dir, Path::new(""))?) {
            return Err(invalid("transaction directory changed"));
        }
        if names(dir)? != [OsString::from(JOURNAL)] {
            return Err(invalid("unknown transaction children protected"));
        }
        unlink(dir, Path::new(JOURNAL), false)?;
        unlink(root, name, true)
    }
    struct Transaction {
        name: PathBuf,
        dir: File,
        journal: Journal,
    }
    // Recovery first validates ALL known journals. Unknown trash is never adopted.
    // Interrupted payloads are restored (possibly partly unlinked) and freshly planned.
    fn validate_transactions(
        root: &File,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<(Vec<Transaction>, bool)> {
        let mount = stat(root, Path::new(""))?.stx_mnt_id;
        let mut transactions = Vec::new();
        let mut targets = std::collections::HashSet::new();
        let mut unknown = false;
        let mut journal_bytes = 0usize;
        for name in names(root)? {
            check_cancel(cancelled)?;
            if !name.as_bytes().starts_with(PREFIX.as_bytes()) {
                continue;
            }
            if transactions.len() >= limits.max_entries {
                return Err(invalid("too many cleanup journals"));
            }
            let dir = open_dir(root.as_raw_fd(), Path::new(&name))?;
            private(&dir)?;
            if absent(&dir, Path::new(JOURNAL))? {
                unknown |= !names(&dir)?.is_empty();
                continue;
            }
            let data = bytes(
                &dir,
                Path::new(JOURNAL),
                MAX_JOURNAL.min(limits.max_metadata_bytes.saturating_sub(journal_bytes)),
            )?;
            journal_bytes += data.len();
            let journal: Journal =
                serde_json::from_slice(&data).map_err(|_| invalid("malformed cleanup metadata"))?;
            journal.shape()?;
            if targets
                .iter()
                .any(|p: &PathBuf| p.starts_with(journal.path()) || journal.path().starts_with(p))
                || transactions
                    .iter()
                    .any(|t: &Transaction| t.journal.object == journal.object)
            {
                return Err(invalid("overlapping cleanup transactions"));
            }
            if journal.store != identity(&root.metadata()?)
                || journal.transaction != identity(&dir.metadata()?)
                || journal.mount != mount
                || stat(&dir, Path::new(""))?.stx_mnt_id != mount
                || !targets.insert(journal.path())
            {
                return Err(invalid("cleanup journal identity mismatch"));
            }
            if names(&dir)?.iter().any(|n| n != JOURNAL && n != PAYLOAD) {
                return Err(invalid("unknown transaction children protected"));
            }
            let source = parent(root, &journal)?;
            let path = journal.path();
            let leaf = Path::new(
                path.file_name()
                    .ok_or_else(|| invalid("empty journal path"))?,
            );
            let source_missing = absent(&source, leaf)?;
            let payload_missing = absent(&dir, Path::new(PAYLOAD))?;
            if !source_missing && !payload_missing {
                return Err(invalid("cleanup source and trash both exist"));
            }
            if source_missing && payload_missing && !journal.deleting {
                return Err(invalid("cleanup payload unexpectedly missing"));
            }
            if !source_missing {
                validate_object(&source, leaf, &journal)?;
            }
            if !payload_missing {
                validate_object(&dir, Path::new(PAYLOAD), &journal)?;
            }
            record_state(root, &journal, source_missing, false)?;
            transactions.push(Transaction {
                name: name.into(),
                dir,
                journal,
            });
        }
        Ok((transactions, unknown))
    }
    fn recover(
        root: &File,
        transactions: Vec<Transaction>,
        report: &mut Report,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<()> {
        for tx in transactions {
            check_cancel(cancelled)?;
            let source = parent(root, &tx.journal)?;
            let path = tx.journal.path();
            let leaf = Path::new(path.file_name().unwrap());
            if !absent(&tx.dir, Path::new(PAYLOAD))? {
                validate_object(&tx.dir, Path::new(PAYLOAD), &tx.journal)?;
                rename(&tx.dir, Path::new(PAYLOAD), &source, leaf)?;
            } else if absent(&source, leaf)? {
                report.removed.push(Item {
                    path: path.clone(),
                    reason: "cleanup_finalization_pending",
                });
                record_state(root, &tx.journal, true, true)?;
            }
            retire(root, &tx.name, &tx.dir)?;
            if let Some(item) = report.removed.last_mut().filter(|i| i.path == path) {
                item.reason = "completed_interrupted_removal";
            }
            report.recovered.push(Item {
                path,
                reason: "interrupted_transaction_recovered_descendants_may_already_be_removed",
            });
        }
        Ok(())
    }

    fn cache_references(
        store: &Path,
        snapshot: &Snapshot,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
        validated_builds: &[(Record, Record)],
        transactions: &[Transaction],
    ) -> io::Result<()> {
        let mut inventory = store_inventory::inspect_recovery_references(
            store,
            limits,
            cancelled,
            validated_builds,
        )?;
        let mut remaining = limits.max_metadata_bytes;
        for tx in transactions {
            if let Target::Tag { reference, digest } = &tx.journal.target {
                if absent(&tx.dir, Path::new(PAYLOAD))? {
                    continue;
                }
                validate_object(&tx.dir, Path::new(PAYLOAD), &tx.journal)?;
                let data = bytes(
                    &tx.dir,
                    Path::new(PAYLOAD),
                    remaining.min(build_record::MAX_BYTES),
                )?;
                remaining = remaining.saturating_sub(data.len());
                #[derive(Deserialize)]
                struct PendingTag {
                    reference: String,
                    image: PathBuf,
                }
                let tag: PendingTag = serde_json::from_slice(&data)?;
                if format!("{:x}", Sha256::digest(&data)) != *digest
                    || tag.reference != *reference
                    || !tag.image.is_absolute()
                    || tag
                        .image
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(invalid("invalid pending tag reference"));
                }
                inventory.tags.push(store_inventory::Tag {
                    record: tx.journal.path(),
                    reference: Some(tag.reference),
                    image: Some(tag.image),
                    status: store_inventory::Status::Present,
                    ownership: store_inventory::Ownership::Unknown,
                    target_status: store_inventory::Status::Unknown,
                });
            }
        }
        let view = snapshot.reference_view();
        let selected = cleanup_plan::cache_selection(store, &inventory, &view, cancelled)?;
        let j = snapshot
            .retirement
            .as_ref()
            .ok_or_else(|| invalid("missing retirement"))?;
        if !selected.contains(&Path::new("cache-v2").join(j.source())) {
            return Err(invalid(
                "retirement target became referenced; nothing recovered",
            ));
        }
        Ok(())
    }
    fn cache_journal(snapshot: &Snapshot, path: &Path, limits: Limits) -> io::Result<Retirement> {
        let relative = path
            .strip_prefix("cache-v2")
            .map_err(|_| invalid("invalid cache candidate"))?;
        let parts = relative
            .iter()
            .map(|p| p.to_str().ok_or_else(|| invalid("invalid cache candidate")))
            .collect::<io::Result<Vec<_>>>()?;
        let (kind, key) = match parts.as_slice() {
            ["entries", key] if snapshot.entries.iter().any(|k| k == key) => (Kind::Entry, *key),
            ["objects", key] if snapshot.unreferenced.iter().any(|k| k == key) => {
                (Kind::Object, *key)
            }
            _ => return Err(invalid("cache target still referenced or unknown")),
        };
        let mut j = Retirement {
            version: 1,
            store: snapshot.store,
            namespace: snapshot.namespace,
            lock: snapshot.nodes["publication.lock"].identity,
            parent: snapshot.nodes[parts[0]].identity,
            kind,
            key: key.into(),
            nodes: Default::default(),
        };
        let source = j.source();
        let pool = j.pool();
        for (p, n) in &snapshot.nodes {
            if p == &source
                || p.starts_with(&(source.clone() + "/"))
                || (j.kind == Kind::Object && p == &pool)
            {
                j.nodes.insert(p.clone(), n.clone());
            }
        }
        let len = serde_json::to_vec(&j)?.len();
        // Reserve the complete recovery read, including longer retired names.
        if len
            .saturating_add(snapshot.scan_bytes)
            .saturating_add(j.nodes.len().saturating_mul(16))
            > limits.max_metadata_bytes
        {
            return Err(invalid("cache retirement journal exceeds recovery budget"));
        }
        Ok(j)
    }
    fn publish_cache_journal(root: &File, cache_dir: &File, j: &Retirement) -> io::Result<()> {
        // Construction outside cache-v2 cannot create an unauthenticated cache child.
        let mut temp = tempfile::Builder::new()
            .prefix(".cache-retirement-write-")
            .tempfile_in(pinned(root))?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temp.write_all(&serde_json::to_vec(j)?)?;
        temp.as_file().sync_all()?;
        let name = Path::new(temp.path().file_name().unwrap());
        rename(root, name, cache_dir, Path::new(cache::JOURNAL))?;
        // TempPath's old name is now absent; dropping it cannot unlink the journal.
        Ok(())
    }
    fn check_cache_snapshot(
        root: &File,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<Snapshot> {
        ManagedCache::maintenance_inspect(root, limits, cancelled, true)?
            .ok_or_else(|| invalid("cache disappeared"))
    }
    fn cache_journal_unchanged(dir: &File, snapshot: &Snapshot) -> io::Result<()> {
        let st = stat(dir, Path::new(cache::JOURNAL))?;
        let id = Identity {
            device: libc::makedev(st.stx_dev_major, st.stx_dev_minor),
            inode: st.stx_ino,
        };
        let expected = serde_json::to_vec(
            snapshot
                .retirement
                .as_ref()
                .ok_or_else(|| invalid("missing retirement"))?,
        )?;
        if Some(id) != snapshot.journal_identity
            || st.stx_mnt_id != stat(dir, Path::new(""))?.stx_mnt_id
            || bytes(dir, Path::new(cache::JOURNAL), expected.len())? != expected
        {
            return Err(invalid("cache retirement journal changed"));
        }
        Ok(())
    }
    fn finish_cache(
        root: &File,
        store: &Path,
        snapshot: Snapshot,
        report: &mut Report,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<()> {
        let j = snapshot
            .retirement
            .as_ref()
            .ok_or_else(|| invalid("missing retirement journal"))?
            .clone();
        cache_references(store, &snapshot, limits, cancelled, &[], &[])?;
        let cache_dir = open_dir(root.as_raw_fd(), Path::new("cache-v2"))?;
        if identity(&cache_dir.metadata()?) != j.namespace {
            return Err(invalid("cache namespace changed"));
        }
        let parent = open_dir(cache_dir.as_raw_fd(), Path::new(j.parent_path()))?;
        if identity(&parent.metadata()?) != j.parent {
            return Err(invalid("cache parent changed"));
        }
        let retired_leaf = format!(".retire-{}", j.key);
        let pool = j.pool();
        check_cancel(cancelled)?;
        cache_journal_unchanged(&cache_dir, &snapshot)?;
        // A prior successful rename may have returned an fsync error.
        cache_dir.sync_all()?;
        if j.kind == Kind::Object {
            let pool_dir = open_dir(cache_dir.as_raw_fd(), Path::new("content/blobs/sha256"))?;
            if snapshot.nodes.contains_key(&pool) {
                let st = stat(&pool_dir, Path::new(&j.key))?;
                if snapshot.nodes[&pool].identity
                    != (Identity {
                        device: libc::makedev(st.stx_dev_major, st.stx_dev_minor),
                        inode: st.stx_ino,
                    })
                    || st.stx_mnt_id != stat(root, Path::new(""))?.stx_mnt_id
                {
                    return Err(invalid("cache pool changed before retirement"));
                }
                unlink(&pool_dir, Path::new(&j.key), false)?;
            }
            // An absent pool name may still be an unsynced unlink from a retry.
            pool_dir.sync_all()?;
            check_cancel(cancelled)?;
            cache_journal_unchanged(&cache_dir, &snapshot)?;
        }
        if !absent(&parent, Path::new(&j.key))? {
            let st = stat(&parent, Path::new(&j.key))?;
            if j.nodes[&j.source()].identity
                != (Identity {
                    device: libc::makedev(st.stx_dev_major, st.stx_dev_minor),
                    inode: st.stx_ino,
                })
                || st.stx_mnt_id != stat(root, Path::new(""))?.stx_mnt_id
            {
                return Err(invalid("cache target changed before retirement"));
            }
            rename(
                &parent,
                Path::new(&j.key),
                &parent,
                Path::new(&retired_leaf),
            )?;
        }
        parent.sync_all()?;
        check_cancel(cancelled)?;
        let source = j.source();
        let retired = j.retired();
        let mut paths: Vec<_> = j.nodes.keys().filter(|p| *p != &pool).cloned().collect();
        // Descendants before parents; retain the provenance record until all
        // payload descendants are gone. The immutable journal survives everything.
        let owner = if j.kind == Kind::Entry {
            "weld-cache-entry.json"
        } else {
            "weld-cache-blob.json"
        };
        paths.sort_by(|a, b| {
            let rank = |p: &String| {
                if p == &source {
                    0
                } else if p == &format!("{source}/{owner}") {
                    1
                } else {
                    p.split('/').count() + 2
                }
            };
            rank(b).cmp(&rank(a)).then_with(|| a.cmp(b))
        });
        for p in paths {
            check_cancel(cancelled)?;
            // Fresh bounded global provenance/alias audit before every unlink.
            let current = check_cache_snapshot(root, limits, cancelled)?;
            cache_journal_unchanged(&cache_dir, &snapshot)?;
            if current.journal_identity != snapshot.journal_identity
                || serde_json::to_vec(current.retirement.as_ref().unwrap())?
                    != serde_json::to_vec(&j)?
            {
                return Err(invalid("cache retirement journal changed"));
            }
            let actual = format!("{retired}{}", p.strip_prefix(&source).unwrap());
            let Some(n) = current.nodes.get(&actual) else {
                continue;
            };
            let path = Path::new(&actual);
            let dir = open_dir(cache_dir.as_raw_fd(), path.parent().unwrap())?;
            let st = stat(&dir, Path::new(path.file_name().unwrap()))?;
            if n.identity
                != (Identity {
                    device: libc::makedev(st.stx_dev_major, st.stx_dev_minor),
                    inode: st.stx_ino,
                })
                || st.stx_mnt_id != stat(root, Path::new(""))?.stx_mnt_id
            {
                return Err(invalid("retired cache identity or mount changed"));
            }
            let result = unlink(&dir, Path::new(path.file_name().unwrap()), n.directory);
            if result.is_err()
                && p == source
                && absent(&dir, Path::new(path.file_name().unwrap())).unwrap_or(false)
            {
                report.removed.push(Item {
                    path: Path::new("cache-v2").join(&source),
                    reason: "cache_retirement_finalization_pending",
                });
            }
            result?;
        }
        report.removed.push(Item {
            path: Path::new("cache-v2").join(&source),
            reason: "cache_retirement_finalization_pending",
        });
        check_cancel(cancelled)?;
        let final_state = check_cache_snapshot(root, limits, cancelled)?;
        if final_state.journal_identity != snapshot.journal_identity
            || serde_json::to_vec(final_state.retirement.as_ref().unwrap())?
                != serde_json::to_vec(&j)?
        {
            return Err(invalid("cache retirement journal changed"));
        }
        cache_references(store, &final_state, limits, cancelled, &[], &[])?;
        // The journal's virtual target validates provenance only; all actual
        // remaining names now constitute an independently valid normal cache.
        if final_state.nodes.keys().any(|p| {
            p == &source
                || p.starts_with(&(source.clone() + "/"))
                || p == &retired
                || p.starts_with(&(retired.clone() + "/"))
                || (j.kind == Kind::Object && p == &pool)
        }) {
            return Err(invalid("cache retirement payload still present"));
        }
        cache_journal_unchanged(&cache_dir, &snapshot)?;
        // Persist target absence even when this retry skipped every missing name.
        parent.sync_all()?;
        unlink(&cache_dir, Path::new(cache::JOURNAL), false)?;
        report.removed.last_mut().unwrap().reason =
            "owned_cache_entry_or_unreferenced_object_removed";
        check_cancel(cancelled)?;
        Ok(())
    }
    fn journal(root: &File, plan: &Plan, path: &Path) -> io::Result<Journal> {
        let inventory = plan
            .inventory
            .as_ref()
            .ok_or_else(|| invalid("missing inventory"))?;
        let original = path
            .iter()
            .map(|s| {
                s.to_str()
                    .ok_or_else(|| invalid("unexpected candidate encoding"))
                    .and_then(|s| Component::try_from(s.to_owned()).map_err(invalid))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let target = if let Some(tag) = inventory.tags.iter().find(|t| t.record == path) {
            Target::Tag {
                reference: tag
                    .reference
                    .clone()
                    .ok_or_else(|| invalid("missing tag reference"))?,
                digest: format!(
                    "{:x}",
                    Sha256::digest(bytes(root, path, build_record::MAX_BYTES)?)
                ),
            }
        } else {
            let record = inventory
                .builds
                .iter()
                .filter_map(|b| b.build_record.as_ref())
                .find(|r| path.starts_with(r.run_id.as_str()))
                .ok_or_else(|| invalid("candidate has no owner"))?
                .clone();
            Target::Build {
                record: Box::new(record),
                component: original[1..].to_vec(),
            }
        };
        let source = open_dir(
            root.as_raw_fd(),
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let st = stat(&source, Path::new(path.file_name().unwrap()))?;
        let j = Journal {
            version: 1,
            store: identity(&root.metadata()?),
            transaction: Identity {
                device: 0,
                inode: 0,
            },
            parent: identity(&source.metadata()?),
            object: Identity {
                device: libc::makedev(st.stx_dev_major, st.stx_dev_minor),
                inode: st.stx_ino,
            },
            mount: stat(root, Path::new(""))?.stx_mnt_id,
            original,
            target,
            deleting: false,
        };
        j.shape()?;
        validate_object(&source, Path::new(path.file_name().unwrap()), &j)?;
        record_state(root, &j, false, false)?;
        Ok(j)
    }
    fn fresh(
        store: &Path,
        request: &Selection,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
        lease: &ExclusiveStoreLease,
    ) -> io::Result<Plan> {
        let p = cleanup_plan::inspect_locked(store, request.clone(), limits, cancelled, lease)?;
        if !p.consistent {
            return Err(invalid(
                "incomplete or malformed cleanup inventory; nothing further removed",
            ));
        }
        Ok(p)
    }
    pub(super) fn apply(
        store: &Path,
        selection: Selection,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<Report> {
        if !store.is_absolute()
            || store
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(invalid("store must be absolute without parent components"));
        }
        let mut report = Report {
            schema_version: 1,
            dry_run: false,
            status: "failed",
            removed: vec![],
            recovered: vec![],
            plan: None,
            failure: None,
        };
        let lease = match StoreLease::try_exclusive_existing(store) {
            Ok(Some(l)) => l,
            Ok(None) => {
                report.status = "store_busy";
                report.failure = Some("store busy; nothing removed".into());
                return Ok(report);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                report.status = "missing_or_unleased";
                report.failure = Some("missing existing store lease; nothing removed".into());
                return Ok(report);
            }
            Err(e) => return Err(e),
        };
        let result = (|| -> io::Result<()> {
            let root = open_dir(libc::AT_FDCWD, store)?;
            let id = lease.root_identity();
            if identity(&root.metadata()?)
                != (Identity {
                    device: id.device,
                    inode: id.inode,
                })
            {
                return Err(invalid("store changed after lease"));
            }
            check_cancel(cancelled)?;
            let _publication = ManagedCache::maintenance_lock(&root, &lease)?;
            let (transactions, unknown) = validate_transactions(&root, limits, cancelled)?;
            let cache_state = ManagedCache::maintenance_inspect(&root, limits, cancelled, true)?;
            let cache_pending = cache_state.as_ref().is_some_and(|s| s.retirement.is_some());
            if unknown && (!transactions.is_empty() || cache_pending) {
                return Err(invalid("unknown cleanup transaction prevents recovery"));
            }
            if let Some(state) = cache_state.as_ref().filter(|s| s.retirement.is_some()) {
                let mut validated_builds = Vec::new();
                for tx in &transactions {
                    if let Target::Build { record, component } = &tx.journal.target {
                        let source = parent(&root, &tx.journal)?;
                        if absent(&source, Path::new(tx.journal.path().file_name().unwrap()))? {
                            let mut after = (**record).clone();
                            after.version = 2;
                            after.removed.push(component.clone());
                            validated_builds.push(((**record).clone(), after));
                        }
                    }
                }
                cache_references(
                    store,
                    state,
                    limits,
                    cancelled,
                    &validated_builds,
                    &transactions,
                )?;
                let cache_dir = open_dir(root.as_raw_fd(), Path::new("cache-v2"))?;
                cache_journal_unchanged(&cache_dir, state)?;
                // Reestablish the durable barrier before even legacy recovery mutates.
                cache_dir.sync_all()?;
            }
            // All journal and reference validation precedes ALL recovery mutation.
            recover(&root, transactions, &mut report, cancelled)?;
            if let Some(state) = cache_state.filter(|s| s.retirement.is_some()) {
                let path = Path::new("cache-v2").join(state.retirement.as_ref().unwrap().source());
                finish_cache(&root, store, state, &mut report, limits, cancelled)?;
                report.recovered.push(Item {
                    path,
                    reason: "cache_retirement_completed",
                });
            }
            let initial = fresh(store, &selection, limits, cancelled, &lease)?;
            let paths = initial
                .candidates
                .iter()
                .map(|i| i.path.clone())
                .collect::<Vec<_>>();
            report.plan = Some(initial);
            for path in paths {
                check_cancel(cancelled)?;
                let plan = fresh(store, &selection, limits, cancelled, &lease)?;
                if !plan.candidates.iter().any(|i| i.path == path) {
                    return Err(invalid(
                        "candidate became protected; nothing further removed",
                    ));
                }
                if path.starts_with("cache-v2") {
                    let snapshot =
                        ManagedCache::maintenance_inspect(&root, limits, cancelled, false)?
                            .ok_or_else(|| invalid("cache disappeared"))?;
                    let j = cache_journal(&snapshot, &path, limits)?;
                    let cache_dir = open_dir(root.as_raw_fd(), Path::new("cache-v2"))?;
                    check_cancel(cancelled)?;
                    publish_cache_journal(&root, &cache_dir, &j)?;
                    check_cancel(cancelled)?;
                    let snapshot = check_cache_snapshot(&root, limits, cancelled)?;
                    finish_cache(&root, store, snapshot, &mut report, limits, cancelled)?;
                    continue;
                }
                let mut j = journal(&root, &plan, &path)?;
                let source = parent(&root, &j)?;
                let leaf = Path::new(path.file_name().unwrap());
                let allocated = tempfile::Builder::new()
                    .prefix(PREFIX)
                    .permissions(fs::Permissions::from_mode(0o700))
                    .tempdir_in(pinned(&root))?
                    .keep();
                let name = Path::new(allocated.file_name().unwrap());
                let tx = open_dir(root.as_raw_fd(), name)?;
                j.transaction = identity(&tx.metadata()?);
                write(&tx, JOURNAL, &j, true)?;
                root.sync_all()?;
                check_cancel(cancelled)?;
                // Repeat the full ownership/reference scan immediately before mutation.
                let latest = fresh(store, &selection, limits, cancelled, &lease)?;
                if !latest.candidates.iter().any(|i| i.path == path) {
                    return Err(invalid("candidate became protected"));
                }
                validate_object(&source, leaf, &j)?;
                record_state(&root, &j, false, false)?;
                rename(&source, leaf, &tx, Path::new(PAYLOAD))?;
                validate_object(&tx, Path::new(PAYLOAD), &j)?;
                check_cancel(cancelled)?;
                j.deleting = true;
                write(&tx, JOURNAL, &j, false)?;
                erase(
                    &tx,
                    Path::new(PAYLOAD),
                    j.mount,
                    0,
                    &mut 0,
                    limits,
                    cancelled,
                )?;
                report.removed.push(Item {
                    path,
                    reason: "cleanup_finalization_pending",
                });
                check_cancel(cancelled)?;
                record_state(&root, &j, true, true)?;
                retire(&root, name, &tx)?;
                report.removed.last_mut().unwrap().reason =
                    "selected_component_or_tag_record_removed";
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                report.status = if report.removed.is_empty() {
                    "no_candidates_protected"
                } else {
                    "complete"
                }
            }
            Err(e) => report.failure = Some(e.to_string()),
        }
        // lease deliberately lives through recovery, final metadata sync, and report creation.
        drop(lease);
        Ok(report)
    }
}
