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

fn path_json<S: serde::Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
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
        linux::inspect(store, request, limits, &cancelled)
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

    pub(super) fn inspect(
        store: &Path,
        request: Request,
        limits: Limits,
        cancelled: &impl Fn() -> bool,
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
        let lease = match StoreLease::try_exclusive_existing(store) {
            Ok(Some(lease)) => Some(lease),
            Ok(None) => {
                plan.status = "store_busy";
                plan.protect(Path::new(""), "store_busy_nothing_selected");
                return Ok(plan);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
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
        plan.consistent = lease.is_some() && !inventory.partial && !cancelled();
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
                if entry.status == Status::Current {
                    "current_base_generation"
                } else {
                    "cache_ownership_provenance_unavailable_structural_status_is_not_ownership"
                },
            );
        }
        // Do not resolve tag JSON paths (including aliases/external paths). Without a
        // descriptor-based alias index, any tag conservatively protects every build.
        let tags_present = !inventory.tags.is_empty();
        let external_paths_present = inventory.builds.iter().any(|entry| {
            entry
                .build_record
                .as_ref()
                .is_some_and(|r| !r.external.is_empty())
        });
        for entry in &inventory.builds {
            let selected = match &plan.request {
                Request::BuildsPrune => true,
                Request::BuildRemove(id) => entry.path == Path::new(id.0.as_str()),
                _ => false,
            };
            let reason = blocked.or(if !selected {
                Some("outside_request")
            } else if tags_present {
                Some("tag_target_or_alias_may_reference_build")
            } else if external_paths_present {
                Some("explicit_external_path_or_alias_may_reference_build")
            } else if entry.build_record.is_none() {
                Some("missing_or_invalid_ownership_record")
            } else {
                None
            });
            if let Some(reason) = reason {
                plan.protect(&entry.path, reason);
                continue;
            }
            let record = entry.build_record.as_ref().unwrap();
            let run = build_record::open_dir(root.as_raw_fd(), &entry.path)?;
            record.validate(&root, &run, &entry.path, |_| {
                if cancelled() {
                    Err(io::Error::other("cancelled"))
                } else {
                    Ok(())
                }
            })?;
            plan.protect(&entry.path, "run_record_and_unlisted_children_protected");
            for owned in &record.owned {
                let relative: PathBuf = owned.components.iter().map(Component::as_str).collect();
                let path = entry.path.join(&relative);
                let dir = build_record::open_dir(run.as_raw_fd(), &relative)?;
                if build_record::identity(&dir.metadata()?) != owned.identity {
                    return Err(io::Error::other("owned component changed"));
                }
                // Only the directory identity is recorded. Populated subtrees need
                // finer provenance before unknown files can safely be distinguished.
                let mut children = fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?;
                match children.next().transpose()? {
                    None => plan.candidates.push(Item {
                        path,
                        reason: "validated_owned_empty_component",
                    }),
                    Some(_) => {
                        plan.protect(&path, "populated_component_child_ownership_not_proven")
                    }
                }
            }
        }
        for tag in &inventory.tags {
            let selected = matches!(&plan.request, Request::ImageRemove(id) if tag.reference.as_ref() == Some(&id.0));
            if selected && blocked.is_none() && tag.status == Status::Present {
                // The inventory validates the digest-derived filename and private,
                // singly linked record. Target data is never a removal candidate.
                let meta = fs::symlink_metadata(store.join(&tag.record))?;
                if !meta.is_file() || meta.nlink() != 1 {
                    return Err(io::Error::other("tag record changed"));
                }
                plan.estimate.unique_logical_bytes = meta.len();
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
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cleanup plan cancelled",
            ));
        }
        plan.inventory = Some(inventory);
        Ok(plan)
    }
}
