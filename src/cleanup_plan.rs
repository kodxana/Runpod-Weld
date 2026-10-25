//! Point-in-time observations, never executable deletion instructions.
//! Deliberately Serialize-only: a saved plan cannot be applied.
use crate::{
    build_record::Component,
    store_inventory::{Inventory, Limits},
};
use serde::Serialize;
use std::{
    io,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize)]
pub struct BuildId(Component);
impl BuildId {
    pub fn parse(value: &str) -> Result<Self, String> {
        let component = Component::try_from(value.to_owned()).map_err(str::to_owned)?;
        if !value.starts_with("build-") || value.len() <= 6 {
            return Err("expected a full build ID, not a path".into());
        }
        Ok(Self(component))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TagId(String);
impl TagId {
    pub fn parse(value: &str) -> Result<Self, String> {
        crate::registry::reference(value, false).map(Self)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "operation", content = "id", rename_all = "snake_case")]
pub enum Request {
    CachePrune,
    BuildsPrune,
    BuildRemove(BuildId),
    ImageRemove(TagId),
}

pub(crate) fn path_json<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if let Some(value) = path.to_str() {
        return serializer.serialize_str(value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        serde_json::json!({"unix_bytes": path.as_os_str().as_bytes()}).serialize(serializer)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        serde_json::json!({"windows_wide": path.as_os_str().encode_wide().collect::<Vec<_>>()})
            .serialize(serializer)
    }
    #[cfg(not(any(unix, windows)))]
    Err(serde::ser::Error::custom(
        "unsupported native path encoding",
    ))
}

#[derive(Debug, Serialize)]
pub struct Item {
    #[serde(serialize_with = "path_json")]
    pub path: PathBuf,
    pub reason: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub struct Estimate {
    /// Selected regular file bytes, counted once per inode (not inventory usage).
    pub unique_logical_bytes: u64,
    pub shared_inode_count: u64,
    pub selected_entries: u64,
    /// File blocks with every hardlink selected; not guaranteed physical reclaim.
    pub reclaimable_file_allocated_bytes: u64,
    pub reclaim_lower_bytes: u64,
    /// None means unknown. Directory blocks, reflinks and open files prevent an exact estimate.
    pub reclaim_upper_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub dry_run: bool,
    pub request: Request,
    pub status: &'static str,
    pub consistent: bool,
    pub candidates: Vec<Item>,
    pub protected: Vec<Item>,
    pub estimate: Estimate,
    pub inventory: Option<Inventory>,
}

impl Plan {
    #[cfg(target_os = "linux")]
    fn protect(&mut self, path: &Path, reason: &'static str) {
        self.protected.push(Item {
            path: path.into(),
            reason,
        });
    }
}

pub fn inspect(
    store: &Path,
    request: Request,
    limits: Limits,
    cancelled: impl Fn() -> bool,
) -> io::Result<Plan> {
    #[cfg(target_os = "linux")]
    {
        linux::inspect(store, request, limits, &cancelled, None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store, request, limits, cancelled);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cleanup plans require Linux openat2 and store leases",
        ))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn inspect_locked(
    store: &Path,
    request: Request,
    limits: Limits,
    cancelled: &impl Fn() -> bool,
    lease: &crate::store_lease::ExclusiveStoreLease,
) -> io::Result<Plan> {
    linux::inspect(store, request, limits, cancelled, Some(lease))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::{
        build_record,
        store_inventory::{self, Status},
        store_lease::StoreLease,
    };
    use std::{
        fs,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };

    use std::{
        collections::{HashMap, HashSet},
        ffi::{CString, OsString},
        os::unix::ffi::{OsStrExt, OsStringExt},
    };

    type Key = (u32, u32, u64);
    fn key(st: &libc::statx) -> Key {
        (st.stx_dev_major, st.stx_dev_minor, st.stx_ino)
    }
    fn stat(parent: i32, path: &Path, flags: i32) -> io::Result<libc::statx> {
        let name = CString::new(path.as_os_str().as_bytes())?;
        let mut st: libc::statx = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::statx(
                parent,
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
            return Err(io::Error::other("incomplete statx"));
        }
        Ok(st)
    }
    struct Tree {
        path: PathBuf,
        nodes: Vec<(PathBuf, libc::statx)>,
    }
    struct Budget<'a, F> {
        limits: Limits,
        entries: usize,
        cancelled: &'a F,
    }
    impl<F: Fn() -> bool> Budget<'_, F> {
        fn check(&mut self, depth: usize) -> io::Result<()> {
            self.entries += 1;
            if (self.cancelled)()
                || self.entries > self.limits.max_entries
                || depth > self.limits.max_depth
            {
                return Err(io::Error::other("scan limit or cancellation"));
            }
            Ok(())
        }
        fn walk(
            &mut self,
            dir: &fs::File,
            path: &Path,
            mount: u64,
            depth: usize,
            nodes: &mut Vec<(PathBuf, libc::statx)>,
        ) -> io::Result<()> {
            for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
                self.check(depth + 1)?;
                let name = entry?.file_name();
                if name == "store.lock" {
                    return Err(io::Error::other("nested store lease boundary"));
                }
                let st = stat(dir.as_raw_fd(), Path::new(&name), libc::AT_SYMLINK_NOFOLLOW)?;
                if st.stx_mnt_id != mount {
                    return Err(io::Error::other("nested mount"));
                }
                let child = path.join(&name);
                if st.stx_mode as u32 & libc::S_IFMT == libc::S_IFDIR {
                    let fd = build_record::open_dir(dir.as_raw_fd(), Path::new(&name))?;
                    let pinned = stat(fd.as_raw_fd(), Path::new(""), libc::AT_EMPTY_PATH)?;
                    if key(&pinned) != key(&st) || pinned.stx_mnt_id != mount {
                        return Err(io::Error::other("changed directory"));
                    }
                    self.walk(&fd, &child, mount, depth + 1, nodes)?;
                }
                nodes.push((child, st));
            }
            Ok(())
        }
    }
    fn plan_builds(
        plan: &mut Plan,
        root: &fs::File,
        store: &Path,
        inventory: &Inventory,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
        blocked: Option<&'static str>,
    ) -> io::Result<()> {
        let mut trees = Vec::new();
        let mut budget = Budget {
            limits,
            entries: 0,
            cancelled,
        };
        let mount = stat(root.as_raw_fd(), Path::new(""), libc::AT_EMPTY_PATH)?.stx_mnt_id;
        for entry in &inventory.builds {
            let selected = match &plan.request {
                Request::BuildsPrune => true,
                Request::BuildRemove(id) => entry.path == Path::new(id.0.as_str()),
                _ => false,
            };
            if let Some(reason) = blocked.or(if !selected {
                Some("outside_request")
            } else if entry.build_record.is_none() {
                Some("missing_or_invalid_ownership_record")
            } else {
                None
            }) {
                plan.protect(&entry.path, reason);
                continue;
            }
            let record = entry.build_record.as_ref().unwrap();
            let run = build_record::open_dir(root.as_raw_fd(), &entry.path)?;
            record.validate(root, &run, &entry.path, |_| budget.check(1))?;
            plan.protect(&entry.path, "run_record_and_unlisted_children_protected");
            for owned in &record.owned {
                if record.removed.contains(&owned.components) {
                    continue;
                }
                let relative: PathBuf = owned.components.iter().map(Component::as_str).collect();
                let path = entry.path.join(&relative);
                // The stages container also contains unrecorded siblings; only listed stages qualify.
                if relative == Path::new("stages") {
                    plan.protect(&path, "stage_container_unlisted_children_protected");
                    continue;
                }
                budget.check(path.components().count())?;
                let dir = build_record::open_dir(run.as_raw_fd(), &relative)?;
                if build_record::identity(&dir.metadata()?) != owned.identity {
                    return Err(io::Error::other("changed component"));
                }
                let st = stat(dir.as_raw_fd(), Path::new(""), libc::AT_EMPTY_PATH)?;
                if st.stx_mnt_id != mount {
                    return Err(io::Error::other("component mount"));
                }
                let mut nodes = vec![(path.clone(), st)];
                budget.walk(&dir, &path, mount, path.components().count(), &mut nodes)?;
                trees.push(Tree { path, nodes });
            }
        }
        let mut protected = HashSet::new();
        let mut uncertain = inventory
            .tags
            .iter()
            .any(|t| t.status != Status::Present || t.image.is_none());
        let refs = inventory.tags.iter().filter_map(|t| t.image.clone()).chain(
            inventory
                .builds
                .iter()
                .filter_map(|b| b.build_record.as_ref())
                .flat_map(|r| r.external.iter())
                .map(|e| PathBuf::from(OsString::from_vec(e.unix_bytes.clone()))),
        );
        let canonical_store = fs::canonicalize(store)?;
        for target in refs {
            budget.check(0)?;
            // Resolve only reference/ancestor metadata, never enumerate arbitrary external trees.
            if !target.is_absolute() {
                uncertain = true;
                continue;
            }
            let Ok(canonical) = fs::canonicalize(&target) else {
                uncertain = true;
                continue;
            };
            let Ok(st) = stat(libc::AT_FDCWD, &canonical, libc::AT_SYMLINK_NOFOLLOW) else {
                uncertain = true;
                continue;
            };
            let relative = canonical.strip_prefix(&canonical_store).ok();
            let mut matched = false;
            for (i, tree) in trees.iter().enumerate() {
                if relative.is_some_and(|p| p.starts_with(&tree.path) || tree.path.starts_with(p))
                    || tree.nodes.iter().any(|(_, n)| key(n) == key(&st))
                {
                    protected.insert(i);
                    matched = true;
                }
            }
            // An unscanned directory may contain aliases to any component.
            if !matched && st.stx_mode as u32 & libc::S_IFMT == libc::S_IFDIR {
                uncertain = true;
            }
        }
        let mut files: HashMap<Key, (u64, u64, u32, u32, PathBuf)> = HashMap::new();
        for (i, tree) in trees.into_iter().enumerate() {
            if uncertain || protected.contains(&i) {
                plan.protect(
                    &tree.path,
                    if uncertain {
                        "reference_alias_scope_uncertain"
                    } else {
                        "reference_intersects_owned_component"
                    },
                );
                continue;
            }
            plan.estimate.selected_entries += tree.nodes.len() as u64;
            for (path, st) in tree.nodes {
                if st.stx_mode as u32 & libc::S_IFMT != libc::S_IFREG {
                    continue;
                }
                let value = files.entry(key(&st)).or_insert((
                    st.stx_size,
                    st.stx_blocks * 512,
                    st.stx_nlink,
                    0,
                    path,
                ));
                if value.0 != st.stx_size
                    || value.1 != st.stx_blocks * 512
                    || value.2 != st.stx_nlink
                {
                    return Err(io::Error::other("changed inode"));
                }
                value.3 += 1;
            }
            plan.candidates.push(Item {
                path: tree.path,
                reason: "validated_owned_component",
            });
        }
        for (_, (size, blocks, links, selected, path)) in files {
            plan.estimate.unique_logical_bytes += size;
            if links > 1 {
                plan.estimate.shared_inode_count += 1;
            }
            if links == selected {
                plan.estimate.reclaimable_file_allocated_bytes += blocks;
            } else {
                plan.protect(&path, "unselected_hardlinks_zero_file_reclaim");
            }
        }
        Ok(())
    }

    pub(super) fn inspect(
        store: &Path,
        request: Request,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
        supplied: Option<&crate::store_lease::ExclusiveStoreLease>,
    ) -> io::Result<Plan> {
        let mut plan = Plan {
            schema_version: 1,
            dry_run: true,
            request,
            status: "missing",
            consistent: false,
            candidates: vec![],
            protected: vec![],
            estimate: Estimate {
                reclaim_upper_bytes: Some(0),
                ..Estimate::default()
            },
            inventory: None,
        };
        if !store.is_absolute()
            || store
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(io::Error::other(
                "store must be absolute without parent components",
            ));
        }
        match fs::symlink_metadata(store) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(plan),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        // Never create a lock for legacy stores. Missing locks are not proof of inactivity.
        let acquired = match supplied {
            Some(_) => None,
            None => match StoreLease::try_exclusive_existing(store) {
                Ok(Some(lease)) => Some(lease),
                Ok(None) => {
                    plan.status = "store_busy";
                    plan.protect(Path::new(""), "store_busy_nothing_selected");
                    return Ok(plan);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            },
        };
        let lease = supplied.or(acquired.as_ref());
        let root = build_record::open_dir(libc::AT_FDCWD, store)?;
        if let Some(lease) = &lease {
            let meta = root.metadata()?;
            if (meta.dev(), meta.ino())
                != (lease.root_identity().device, lease.root_identity().inode)
            {
                return Err(io::Error::other("store changed after acquiring lease"));
            }
        }
        let inventory = store_inventory::inspect(store, limits, cancelled)?;
        let check = build_record::open_dir(libc::AT_FDCWD, store)?;
        if build_record::identity(&check.metadata()?) != build_record::identity(&root.metadata()?) {
            return Err(io::Error::other("store changed during inventory"));
        }
        // Inventory deliberately skips symlink/special payloads. The component pass
        // accounts for those entries without following targets; other gaps stay fatal.
        let complete = inventory.scan_complete
            && !inventory.issues_truncated
            && (!inventory.partial
                || (!inventory.issues.is_empty()
                    && inventory.issues.iter().all(|issue| {
                        issue.code == "symlink_or_special_file_skipped"
                            && inventory.builds.iter().any(|entry| {
                                entry.build_record.as_ref().is_some_and(|record| {
                                    record.owned.iter().any(|owned| {
                                        let relative: PathBuf = owned
                                            .components
                                            .iter()
                                            .map(Component::as_str)
                                            .collect();
                                        relative != Path::new("stages")
                                            && issue.path.starts_with(entry.path.join(relative))
                                    })
                                })
                            })
                    })));
        plan.consistent = lease.is_some() && complete && !cancelled();
        plan.status = if lease.is_none() {
            "legacy_unleased"
        } else if !plan.consistent {
            "partial"
        } else {
            "planned"
        };
        let blocked = if lease.is_none() {
            Some("unleased_legacy_store")
        } else if !plan.consistent {
            Some("incomplete_inventory")
        } else {
            None
        };

        for entry in &inventory.protected_entries {
            plan.protect(
                &entry.path,
                "unknown_credentials_certificates_or_lock_always_protected",
            );
        }
        for reference in &inventory.base_refs {
            plan.protect(&reference.record, "base_reference_protected");
        }
        for entry in inventory.generations.iter().chain(&inventory.stages) {
            plan.protect(
                &entry.path,
                if entry.path.starts_with("cache-v2") {
                    "cache_census_only_closure_and_recovery_protocol_required"
                } else if entry.status == Status::Current {
                    "current_base_generation"
                } else {
                    "cache_ownership_provenance_unavailable_structural_status_is_not_ownership"
                },
            );
        }
        let result = plan_builds(
            &mut plan, &root, store, &inventory, limits, cancelled, blocked,
        );
        if result.is_err() {
            plan.status = "partial";
            plan.consistent = false;
            plan.candidates.clear();
            plan.estimate = Estimate::default();
            plan.protect(Path::new(""), "incomplete_component_scan_selection_unknown");
        }
        for tag in &inventory.tags {
            let selected = matches!(&plan.request, Request::ImageRemove(id) if tag.reference.as_ref() == Some(&id.0));
            if selected && plan.consistent && tag.status == Status::Present {
                // The inventory validates the digest-derived filename and private,
                // singly linked record. Target data is never a removal candidate.
                let meta = fs::symlink_metadata(store.join(&tag.record))?;
                if !meta.is_file() || meta.nlink() != 1 {
                    return Err(io::Error::other("tag record changed"));
                }
                plan.estimate.unique_logical_bytes = meta.len();
                plan.estimate.selected_entries = 1;
                plan.estimate.reclaimable_file_allocated_bytes = meta.blocks().saturating_mul(512);
                plan.estimate.reclaim_upper_bytes = Some(meta.blocks().saturating_mul(512));
                plan.candidates.push(Item {
                    path: tag.record.clone(),
                    reason: "tag_record_only_target_unchanged",
                });
            } else {
                plan.protect(
                    &tag.record,
                    blocked.unwrap_or("tag_record_not_selected_or_invalid"),
                );
            }
        }
        if !plan.candidates.is_empty() && !matches!(plan.request, Request::ImageRemove(_)) {
            // Empty directory metadata usage is filesystem-dependent and not inventoried.
            plan.estimate.reclaim_upper_bytes = None;
        }
        if cancelled() {
            plan.status = "partial";
            plan.consistent = false;
            plan.candidates.clear();
            plan.estimate = Estimate::default();
            plan.protect(Path::new(""), "cancelled_selection_unknown");
        }
        if !plan.consistent {
            plan.estimate = Estimate::default();
        }
        plan.inventory = Some(inventory);
        Ok(plan)
    }
}
