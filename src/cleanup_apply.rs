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
    fn recover(
        root: &File,
        report: &mut Report,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<()> {
        let mount = stat(root, Path::new(""))?.stx_mnt_id;
        let mut transactions = Vec::new();
        let mut targets = std::collections::HashSet::new();
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
                continue;
            }
            let journal: Journal = read(&dir, JOURNAL, MAX_JOURNAL)?;
            journal.shape()?;
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
            recover(&root, &mut report, limits, cancelled)?;
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
