//! Managed CLI workload policy. Observations and planning estimates are not quotas.
use crate::build;
use std::{collections::BTreeMap, path::PathBuf};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
pub const JSON_BYTES: u64 = 16 * MIB;
pub const PLAN_BYTES: u64 = 16 * MIB;

#[derive(Clone, Copy, Debug, Default)]
pub struct Overrides {
    pub rootfs_bytes: Option<u64>,
    pub layer_bytes: Option<u64>,
    pub metadata_bytes: Option<u64>,
    pub entries: Option<u64>,
}

/// Destination roles, not an assumption that every retained stage reaches its ceiling.
#[derive(Clone, Copy, Debug)]
pub struct StoragePlan {
    pub selected_stages: usize,
    pub external_copy_images: usize,
    pub stored_base_images: usize,
    pub cache: bool,
}

#[derive(Clone, Debug)]
pub struct Paths {
    pub work: PathBuf,
    pub output: PathBuf,
    pub store: PathBuf,
}
impl Paths {
    fn all(&self) -> [&PathBuf; 3] {
        [&self.work, &self.output, &self.store]
    }
}

#[derive(Clone, Debug)]
pub struct Filesystem {
    pub path: PathBuf,
    pub device: u64,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: Option<u64>,
    pub available_inodes: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub filesystems: Vec<Filesystem>,
    pub memory_ceiling: Option<u64>,
    pub memory_headroom: Option<u64>,
    pub memory_incomplete: bool,
    pub hard_fds: Option<u64>,
}

impl Snapshot {
    pub fn observe(paths: &Paths) -> Result<Self, String> {
        Self::observe_paths(&paths.all().into_iter().cloned().collect::<Vec<_>>())
    }

    /// Disk/inode-only admission before source leases or workload planning.
    /// Cgroup memory pressure and NOFILE observations are advisory here.
    pub fn check_available(
        &self,
        operation: &str,
        requirements: &[Requirement],
    ) -> Result<(), String> {
        let mut devices: BTreeMap<u64, (&Filesystem, u64, u64)> = BTreeMap::new();
        for fs in &self.filesystems {
            let entry = devices.entry(fs.device).or_insert((fs, 64 * 1024, 8));
            if fs.available_bytes < entry.0.available_bytes {
                entry.0 = fs;
            }
        }
        for requirement in requirements {
            let fs = self.filesystem(&requirement.path)?;
            let entry = devices
                .get_mut(&fs.device)
                .ok_or("missing device observation")?;
            entry.1 = add(entry.1, requirement.bytes, operation)?;
            entry.2 = add(entry.2, requirement.inodes, operation)?;
        }
        for (fs, bytes, inodes) in devices.values() {
            let required = add(*bytes, disk_reserve(fs.total_bytes), operation)?;
            if required > fs.available_bytes {
                return Err(format!(
                    "{operation}: {} requires {required} additional/reserved bytes; available {} (source: current statvfs, automatic reserve {}); free space or choose another work/output/store filesystem; filesystem quota unknown",
                    fs.path.display(),
                    fs.available_bytes,
                    disk_reserve(fs.total_bytes)
                ));
            }
            let available = self
                .filesystems
                .iter()
                .filter(|other| other.device == fs.device)
                .filter_map(|other| other.available_inodes)
                .min();
            let required = add(*inodes, inode_reserve(fs.total_inodes), operation)?;
            if let Some(available) = available
                && required > available
            {
                return Err(format!(
                    "{operation}: {} requires {required} additional/reserved inodes; available {available} (source: current statvfs, automatic inode reserve); remove files or choose another filesystem",
                    fs.path.display()
                ));
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn observe_paths(_: &[PathBuf]) -> Result<Self, String> {
        Err("automatic build resources require Linux".into())
    }

    #[cfg(target_os = "linux")]
    fn observe_paths(paths: &[PathBuf]) -> Result<Self, String> {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let mut filesystems = Vec::new();
        for path in paths {
            let mut ancestor = std::path::absolute(path).map_err(|e| e.to_string())?;
            let file = loop {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&ancestor)
                {
                    Ok(file) => {
                        if !file.metadata().map_err(|e| e.to_string())?.is_dir() {
                            return Err(format!(
                                "resource observation {}: existing ancestor must be a directory",
                                ancestor.display()
                            ));
                        }
                        break file;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound && ancestor.pop() => (),
                    Err(e) => return Err(format!("resource observation {}: {e}", path.display())),
                }
            };
            let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(format!(
                    "statvfs {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            let stat = unsafe { stat.assume_init() };
            filesystems.push(Filesystem {
                path: path.clone(),
                device: file.metadata().map_err(|e| e.to_string())?.dev(),
                total_bytes: multiply(stat.f_blocks, stat.f_frsize, "filesystem capacity")?,
                available_bytes: multiply(stat.f_bavail, stat.f_frsize, "filesystem availability")?,
                total_inodes: (stat.f_files != 0 && stat.f_files != u64::MAX)
                    .then_some(stat.f_files),
                available_inodes: (stat.f_files != 0 && stat.f_favail != u64::MAX)
                    .then_some(stat.f_favail),
            });
        }
        // Reuse the namespace-aware v1/v2 observer; never substitute host RAM totals.
        let resources = crate::resources::discover();
        let memory = &resources["memory"];
        // Rechecks need NOFILE only, not the full doctor capability probe.
        let mut nofile = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let hard_fds = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, nofile.as_mut_ptr()) } == 0
        {
            let hard = unsafe { nofile.assume_init() }.rlim_max;
            (hard != libc::RLIM_INFINITY).then_some(hard)
        } else {
            None
        };
        Ok(Self {
            filesystems,
            memory_ceiling: memory["observed_operating_ceiling_bytes"].as_u64(),
            memory_headroom: memory["observed_operating_headroom_bytes"].as_u64(),
            memory_incomplete: memory["visible_data_incomplete"].as_bool().unwrap_or(true),
            hard_fds,
        })
    }

    fn filesystem(&self, path: &PathBuf) -> Result<&Filesystem, String> {
        self.filesystems
            .iter()
            .find(|f| &f.path == path)
            .ok_or_else(|| format!("missing filesystem observation for {}", path.display()))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ceiling {
    pub value: u64,
    pub origin: &'static str,
}
impl Ceiling {
    fn new(explicit: Option<u64>, auto: u64, flag: &str) -> Result<Self, String> {
        let value = explicit.unwrap_or(auto);
        if value == 0 {
            return Err(format!(
                "{flag}: required positive ceiling; available 0 (source: {})",
                if explicit.is_some() {
                    "explicit flag"
                } else {
                    "automatic resource policy"
                }
            ));
        }
        Ok(Self {
            value,
            origin: if explicit.is_some() {
                "explicit"
            } else {
                "auto"
            },
        })
    }
}

#[derive(Clone, Debug)]
pub struct Requirement {
    pub path: PathBuf,
    /// Additional bytes, including spool/copies/tar overhead, when measured.
    pub bytes: u64,
    /// Additional entries, including directories and transient spool files.
    pub inodes: u64,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub paths: Paths,
    pub rootfs: Ceiling,
    pub layer: Ceiling,
    pub metadata: Ceiling,
    pub entries: Ceiling,
    snapshot: Snapshot,
    storage: StoragePlan,
}

fn add(a: u64, b: u64, what: &str) -> Result<u64, String> {
    a.checked_add(b)
        .ok_or_else(|| format!("{what}: resource estimate overflow"))
}
#[cfg(any(target_os = "linux", test))]
fn multiply(a: u64, b: u64, what: &str) -> Result<u64, String> {
    a.checked_mul(b)
        .ok_or_else(|| format!("{what}: resource estimate overflow"))
}
fn quantize(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        1u64 << (63 - n.leading_zeros())
    }
}
fn disk_reserve(total: u64) -> u64 {
    (total / 20).clamp(256 * MIB, 4 * GIB)
}
fn inode_reserve(total: Option<u64>) -> u64 {
    (total.unwrap_or(0) / 20).clamp(128, 65_536)
}
fn memory_margin(ceiling: u64) -> u64 {
    (ceiling / 4).max(128 * MIB)
}

impl Policy {
    /// Conservative compatibility helper; CLI callers supply actual storage roles.
    pub fn resolve(
        paths: Paths,
        snapshot: &Snapshot,
        overrides: Overrides,
        selected_stages: usize,
        external_images: usize,
    ) -> Result<Self, String> {
        Self::resolve_for_build(
            paths,
            snapshot,
            overrides,
            StoragePlan {
                selected_stages,
                external_copy_images: external_images,
                stored_base_images: external_images,
                cache: true,
            },
        )
    }

    pub fn resolve_for_build(
        paths: Paths,
        snapshot: &Snapshot,
        overrides: Overrides,
        storage: StoragePlan,
    ) -> Result<Self, String> {
        if storage.selected_stages == 0 {
            return Err("resource plan requires a selected stage".into());
        }
        // Only simultaneous per-operation copies constrain ceilings. Retained
        // stages/checkpoints consume current space, checked at each write boundary.
        let store_copies = if storage.selected_stages > 1 {
            3
        } else if storage.external_copy_images > 0
            || storage.stored_base_images > 0
            || storage.cache
        {
            2
        } else {
            0
        };
        let mut devices: BTreeMap<u64, (u64, u64, Option<u64>)> = BTreeMap::new();
        for (path, copies) in [
            (&paths.work, 2),
            (&paths.output, 1),
            (&paths.store, store_copies),
        ] {
            // A bookkeeper/tag-only store still gets availability checks, but
            // its capacity must not shrink an image written on another device.
            if copies == 0 {
                continue;
            }
            let fs = snapshot.filesystem(path)?;
            let item = devices
                .entry(fs.device)
                .or_insert((0, fs.total_bytes, fs.total_inodes));
            item.0 = add(item.0, copies, "shared filesystem copies")?;
            item.1 = item.1.min(fs.total_bytes);
            item.2 = match (item.2, fs.total_inodes) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            };
        }
        let mut bytes = 1024 * GIB;
        let mut inodes = 16 * 1024 * 1024;
        for (copies, total, total_inodes) in devices.values().copied() {
            bytes = bytes.min(total.saturating_sub(disk_reserve(total)) / copies);
            if let Some(total) = total_inodes {
                inodes = inodes.min(total.saturating_sub(inode_reserve(Some(total))) / copies);
            }
        }
        // Logical charges are not allocations. /16 is a provisional allowance for
        // concurrent inventories, path tables and allocator overhead, NOT an RSS
        // conversion. Keep a finite independent cap; calibrate on more workloads.
        let metadata = snapshot
            .memory_ceiling
            .map(|n| n.saturating_sub(memory_margin(n)) / 16)
            .unwrap_or(64 * MIB)
            .clamp(MIB, 4 * GIB);
        let metadata = Ceiling::new(
            overrides.metadata_bytes,
            quantize(metadata),
            "--metadata-budget",
        )?;
        // 1 KiB logical metadata per entry is a planning heuristic. Each subsystem
        // still enforces its actual independent metadata charge.
        let entries = Ceiling::new(
            overrides.entries,
            quantize(inodes.min((metadata.value / 1024).max(1))),
            "--max-entries",
        )?;
        usize::try_from(entries.value).map_err(|_| "--max-entries exceeds platform size")?;
        let policy = Self {
            paths,
            rootfs: Ceiling::new(
                overrides.rootfs_bytes,
                quantize(bytes),
                "--max-rootfs-bytes",
            )?,
            layer: Ceiling::new(overrides.layer_bytes, quantize(bytes), "--max-layer-bytes")?,
            metadata,
            entries,
            snapshot: snapshot.clone(),
            storage,
        };
        policy.check_snapshot(snapshot, "build preflight", &[])?;
        Ok(policy)
    }

    pub fn apply_to(&self, limits: &mut build::Limits) {
        let entries = self.entries.value as usize; // Checked by resolve.
        limits.max_rootfs_bytes = self.rootfs.value;
        limits.max_rootfs_entries = entries;
        limits.max_replay_bytes = self.layer.value;
        limits.max_replay_entries = entries;
        limits.image.max_layer_bytes = self.layer.value;
        limits.image.max_total_layer_bytes = self.layer.value;
        // Untrusted JSON/descriptor structure never grows with workload metadata.
        limits.image.max_metadata_bytes = self.metadata.value.min(JSON_BYTES);
        limits.image.max_total_metadata_bytes = self.metadata.value.min(4 * JSON_BYTES);
        limits.image.max_descriptors = 1024;
        limits.layer.max_blob_bytes = self.layer.value;
        limits.layer.max_uncompressed_bytes = self.layer.value;
        limits.layer.max_entries = entries;
        limits.layer.max_metadata_bytes = self.metadata.value;
        limits.layer.max_gzip_header_bytes = 65536;
        limits.export.max_layer_bytes = self.layer.value;
        limits.export.max_entries = entries;
        limits.export.max_metadata_bytes = self.metadata.value;
        limits.max_plan_bytes = self.metadata.value.min(PLAN_BYTES) as usize;
    }

    /// Current disk/inode checks, not reservations. Memory pressure is advisory.
    /// Call before known-size transfers/replay/COPY/export/checkpoint writes and
    /// after RUN. An unbounded RUN can exhaust resources between these checks.
    pub fn recheck(&self, operation: &str, requirements: &[Requirement]) -> Result<(), String> {
        let mut paths: Vec<_> = self.paths.all().into_iter().cloned().collect();
        paths.extend(requirements.iter().map(|r| r.path.clone()));
        let snapshot = Snapshot::observe_paths(&paths)?;
        self.check_snapshot(&snapshot, operation, requirements)
    }

    /// Pure counterpart to recheck for injected observations; does not mutate state.
    pub fn check_snapshot(
        &self,
        snapshot: &Snapshot,
        operation: &str,
        requirements: &[Requirement],
    ) -> Result<(), String> {
        snapshot.check_available(operation, requirements)
    }

    pub fn diagnostics(&self) -> String {
        let mut text = format!(
            "Build resources: rootfs={} ({}), layer/replay={} ({}), entries={} ({}), logical metadata={} ({})\n",
            self.rootfs.value,
            self.rootfs.origin,
            self.layer.value,
            self.layer.origin,
            self.entries.value,
            self.entries.origin,
            self.metadata.value,
            self.metadata.origin
        );
        text.push_str(&format!("Resource planning: {} selected stages, {} external COPY roots, {} stored base images; instruction cache={}. Per-operation destination allowances: work root+spool, output, and active store payload roles. Retained stages/checkpoints are advisory planning inputs, not multipliers on the ceiling or a full-build fit guarantee; measured write rechecks account for their growth.\n", self.storage.selected_stages, self.storage.external_copy_images, self.storage.stored_base_images, self.storage.cache));
        for fs in &self.snapshot.filesystems {
            text.push_str(&format!("Filesystem {:?}: device={}, capacity={}, available={}, reserve={}, inodes available={:?}, inode reserve={}; quota unknown (shared capacity is not reserved).\n", fs.path, fs.device, fs.total_bytes, fs.available_bytes, disk_reserve(fs.total_bytes), fs.available_inodes, inode_reserve(fs.total_inodes)));
        }
        text.push_str(&format!("Memory: cgroup ceiling={:?}, headroom={:?}, incomplete={}; hard NOFILE={:?} (None means unknown or unlimited; exact replay check remains required).\n", self.snapshot.memory_ceiling, self.snapshot.memory_headroom, self.snapshot.memory_incomplete, self.snapshot.hard_fds));
        text.push_str("Memory headroom is advisory: memory.high is a pressure threshold and memory.current can include reclaimable cache; saturation does not refuse or abort a build. NOFILE is enforced by exact replay checks only when replay occurs.\n");
        if self.snapshot.memory_ceiling.is_none() {
            text.push_str("Memory capacity unknown: automatic logical metadata uses a bounded 64 MiB fallback; large workloads may need explicit --metadata-budget. No host RAM capacity inferred.\n");
        }
        text.push_str("Logical metadata is not RSS: provisional /16 sizing, independent 4 GiB automatic cap; JSON 16 MiB/document, 64 MiB total and plan 16 MiB stay structurally bounded (smaller explicit metadata still applies). Observations/rechecks are best effort, not disk quotas or OOM prevention.\n");
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Paths, Snapshot) {
        let paths = Paths {
            work: "/work".into(),
            output: "/output".into(),
            store: "/store".into(),
        };
        let snapshot = Snapshot {
            filesystems: paths
                .all()
                .iter()
                .map(|p| Filesystem {
                    path: (*p).clone(),
                    device: 1,
                    total_bytes: 1024 * GIB,
                    available_bytes: 256 * GIB,
                    total_inodes: Some(16 * 1024 * 1024),
                    available_inodes: Some(8 * 1024 * 1024),
                })
                .collect(),
            memory_ceiling: Some(50 * GIB),
            memory_headroom: Some(40 * GIB),
            memory_incomplete: false,
            hard_fds: Some(1_048_576),
        };
        (paths, snapshot)
    }
    fn resolve(paths: Paths, snapshot: &Snapshot) -> Policy {
        Policy::resolve(paths, snapshot, Overrides::default(), 1, 0).unwrap()
    }
    fn limits() -> build::Limits {
        build::Limits {
            image: crate::image::Limits {
                max_metadata_bytes: 1,
                max_total_metadata_bytes: 1,
                max_descriptors: 1,
                max_layer_bytes: 1,
                max_total_layer_bytes: 1,
            },
            layer: crate::layer::Limits {
                max_blob_bytes: 1,
                max_uncompressed_bytes: 1,
                max_entries: 1,
                max_metadata_bytes: 1,
                max_gzip_header_bytes: 1,
            },
            export: crate::export::Limits {
                max_layer_bytes: 1,
                max_entries: 1,
                max_metadata_bytes: 1,
            },
            max_replay_bytes: 1,
            max_replay_entries: 1,
            max_rootfs_bytes: 1,
            max_rootfs_entries: 1,
            max_plan_bytes: 1,
            run_timeout_seconds: 300,
        }
    }

    #[test]
    fn stable_capacity_not_transient_availability_sets_limits() {
        let (paths, mut snapshot) = fixture();
        let a = resolve(paths.clone(), &snapshot);
        snapshot.filesystems.iter_mut().for_each(|f| {
            f.available_bytes /= 4;
            f.available_inodes = Some(1_000_000);
        });
        snapshot.memory_headroom = Some(20 * GIB);
        let b = resolve(paths, &snapshot);
        assert_eq!(a.rootfs.value, b.rootfs.value);
        assert_eq!(a.metadata.value, b.metadata.value);
        assert_eq!(a.entries.value, b.entries.value);
        assert!(a.rootfs.value > 2 * GIB);
        assert_eq!(a.metadata.value, 2 * GIB);
        assert!(a.entries.value > 230_217);
    }

    #[test]
    fn memory_and_disk_are_independent_and_structural_bounds_do_not_expand() {
        let (paths, mut snapshot) = fixture();
        let a = resolve(paths.clone(), &snapshot);
        snapshot.memory_ceiling = Some(2 * GIB);
        snapshot.memory_headroom = Some(GIB);
        let b = resolve(paths.clone(), &snapshot);
        assert_eq!(a.rootfs.value, b.rootfs.value);
        assert!(a.metadata.value > b.metadata.value);
        snapshot
            .filesystems
            .iter_mut()
            .for_each(|f| f.total_bytes /= 8);
        let c = resolve(paths, &snapshot);
        assert!(c.rootfs.value < b.rootfs.value);
        assert_eq!(b.metadata.value, c.metadata.value);
        let mut limits = limits();
        a.apply_to(&mut limits);
        assert_eq!(limits.layer.max_metadata_bytes, 2 * GIB);
        assert_eq!(limits.image.max_metadata_bytes, JSON_BYTES);
        assert_eq!(limits.image.max_total_metadata_bytes, 4 * JSON_BYTES);
        assert_eq!(limits.max_plan_bytes, PLAN_BYTES as usize);
        assert_eq!(limits.layer.max_gzip_header_bytes, 65536);
    }

    #[test]
    fn explicit_ceilings_never_grow_and_large_values_are_not_reservations() {
        let (paths, snapshot) = fixture();
        let p = Policy::resolve(
            paths,
            &snapshot,
            Overrides {
                rootfs_bytes: Some(123),
                layer_bytes: Some(456),
                metadata_bytes: Some(789),
                entries: Some(3),
            },
            1,
            0,
        )
        .unwrap();
        let mut limits = limits();
        p.apply_to(&mut limits);
        assert_eq!(limits.max_rootfs_bytes, 123);
        assert_eq!(limits.max_replay_bytes, 456);
        assert_eq!(limits.max_rootfs_entries, 3);
        assert_eq!(limits.max_replay_entries, 3);
        assert_eq!(limits.export.max_entries, 3);
        assert_eq!(limits.layer.max_metadata_bytes, 789);
        assert_eq!(limits.image.max_metadata_bytes, 789);
        assert!(p.diagnostics().contains("entries=3 (explicit)"));
        let p = Policy::resolve(
            p.paths,
            &snapshot,
            Overrides {
                rootfs_bytes: Some(u64::MAX),
                ..Overrides::default()
            },
            1,
            0,
        )
        .unwrap();
        assert_eq!(p.rootfs.value, u64::MAX);
    }

    #[test]
    fn unknown_cgroups_remain_unknown_and_fallback_is_bounded() {
        let (paths, mut snapshot) = fixture();
        snapshot.memory_ceiling = None;
        snapshot.memory_headroom = None;
        snapshot.memory_incomplete = true;
        let p = resolve(paths.clone(), &snapshot);
        assert_eq!(p.metadata.value, 64 * MIB);
        assert!(p.diagnostics().contains("Memory capacity unknown"));
        assert!(p.snapshot.memory_headroom.is_none());
        let p = Policy::resolve(
            paths,
            &snapshot,
            Overrides {
                metadata_bytes: Some(2 * GIB),
                ..Overrides::default()
            },
            1,
            0,
        )
        .unwrap();
        assert_eq!(p.metadata.value, 2 * GIB);
    }

    #[test]
    fn reserves_apply_to_empty_rechecks_and_measured_requirements_sum_per_device() {
        let (paths, mut snapshot) = fixture();
        let p = resolve(paths.clone(), &snapshot);
        for available in [0, disk_reserve(snapshot.filesystems[0].total_bytes)] {
            snapshot.filesystems[0].available_bytes = available;
            let error = p
                .check_snapshot(&snapshot, "copy checkpoint", &[])
                .unwrap_err();
            assert!(
                error.contains("copy checkpoint")
                    && error.contains("available")
                    && error.contains("source: current statvfs")
            );
        }
        snapshot
            .filesystems
            .iter_mut()
            .for_each(|f| f.available_bytes = disk_reserve(f.total_bytes) + 3 * MIB);
        let requirements = [
            Requirement {
                path: paths.work,
                bytes: 2 * MIB,
                inodes: 0,
            },
            Requirement {
                path: paths.output,
                bytes: 2 * MIB,
                inodes: 0,
            },
        ];
        assert!(
            p.check_snapshot(&snapshot, "export", &requirements[..1])
                .is_ok()
        );
        assert!(
            p.check_snapshot(&snapshot, "export", &requirements)
                .is_err()
        );
        snapshot.filesystems[1].device = 2;
        assert!(p.check_snapshot(&snapshot, "export", &requirements).is_ok());
    }

    #[test]
    fn inode_exhaustion_refuses_but_memory_pressure_and_fds_are_advisory() {
        let (paths, mut snapshot) = fixture();
        let p = resolve(paths, &snapshot);
        snapshot.memory_headroom = Some(0);
        snapshot.hard_fds = Some(200);
        assert!(p.check_snapshot(&snapshot, "prepare", &[]).is_ok());
        snapshot.filesystems[2].available_inodes = Some(0);
        assert!(
            p.check_snapshot(&snapshot, "prepare", &[])
                .unwrap_err()
                .contains("inodes")
        );
        snapshot.filesystems[2].available_inodes = None;
        assert!(p.check_snapshot(&snapshot, "prepare", &[]).is_ok());
    }

    #[test]
    fn saturated_memory_high_including_reclaimable_cache_does_not_refuse_tiny_budget() {
        let (paths, mut snapshot) = fixture();
        // memory.high=4 GiB, current=4 GiB (possibly reclaimable page cache).
        snapshot.memory_ceiling = Some(4 * GIB);
        snapshot.memory_headroom = Some(0);
        let p = Policy::resolve(
            paths,
            &snapshot,
            Overrides {
                rootfs_bytes: Some(1024),
                layer_bytes: Some(MIB),
                metadata_bytes: Some(1024),
                entries: Some(2),
            },
            1,
            0,
        )
        .unwrap();
        assert_eq!(p.metadata.value, 1024);
        assert!(
            p.check_snapshot(&snapshot, "memory.high saturated during build", &[])
                .is_ok()
        );
    }

    #[test]
    fn separate_bookkeeping_store_does_not_limit_no_cache_scratch_payload() {
        let (paths, mut snapshot) = fixture();
        snapshot.filesystems[2].device = 2;
        snapshot.filesystems[2].total_bytes = GIB;
        snapshot.filesystems[2].available_bytes = GIB;
        let p = Policy::resolve_for_build(
            paths.clone(),
            &snapshot,
            Overrides::default(),
            StoragePlan {
                selected_stages: 1,
                external_copy_images: 0,
                stored_base_images: 0,
                cache: false,
            },
        )
        .unwrap();
        assert!(
            p.rootfs.value > 300 * MIB && p.layer.value > 300 * MIB,
            "{p:?}"
        );
        snapshot.filesystems[2].available_bytes = 0;
        assert!(
            p.check_snapshot(&snapshot, "bookkeeping still needs space", &[])
                .is_err()
        );
    }

    #[test]
    fn retained_stage_count_is_not_a_hard_capacity_multiplier() {
        let (paths, snapshot) = fixture();
        let a = Policy::resolve_for_build(
            paths.clone(),
            &snapshot,
            Overrides::default(),
            StoragePlan {
                selected_stages: 2,
                external_copy_images: 1,
                stored_base_images: 1,
                cache: true,
            },
        )
        .unwrap();
        let b = Policy::resolve_for_build(
            paths,
            &snapshot,
            Overrides::default(),
            StoragePlan {
                selected_stages: 100,
                external_copy_images: 100,
                stored_base_images: 100,
                cache: true,
            },
        )
        .unwrap();
        assert_eq!(a.rootfs.value, b.rootfs.value);
        assert_eq!(a.entries.value, b.entries.value);
    }

    #[test]
    fn multiple_filesystems_limit_the_actual_destination_operation() {
        let (paths, mut snapshot) = fixture();
        snapshot.filesystems[1].device = 2;
        snapshot.filesystems[1].total_bytes = 16 * GIB;
        let c = resolve(paths.clone(), &snapshot);
        assert_eq!(c.rootfs.value, 8 * GIB);
        snapshot.filesystems[1].total_inodes = Some(1000);
        let d = resolve(paths, &snapshot);
        assert_eq!(d.entries.value, 512);
    }

    #[test]
    fn checked_overflow_and_finite_caps() {
        assert!(multiply(u64::MAX, 2, "statvfs").is_err());
        let (paths, mut snapshot) = fixture();
        let p = resolve(paths.clone(), &snapshot);
        let requirements = [Requirement {
            path: paths.work.clone(),
            bytes: u64::MAX,
            inodes: 0,
        }];
        assert!(
            p.check_snapshot(&snapshot, "export", &requirements)
                .unwrap_err()
                .contains("overflow")
        );
        snapshot.memory_ceiling = Some(u64::MAX);
        snapshot.memory_headroom = Some(u64::MAX);
        snapshot.filesystems.iter_mut().for_each(|f| {
            f.total_bytes = u64::MAX;
            f.available_bytes = u64::MAX;
            f.total_inodes = None;
            f.available_inodes = None;
        });
        let p = resolve(paths, &snapshot);
        assert_eq!(p.metadata.value, 4 * GIB);
        assert_eq!(p.rootfs.value, 1024 * GIB);
        assert!(p.entries.value <= 16 * 1024 * 1024);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observation_of_missing_output_uses_existing_ancestor_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("missing/child");
        let paths = Paths {
            work: path.clone(),
            output: path.clone(),
            store: path,
        };
        let snapshot = Snapshot::observe(&paths).unwrap();
        assert_eq!(snapshot.filesystems.len(), 3);
        assert!(snapshot.filesystems[0].total_bytes > 0);
        assert!(!temp.path().join("missing").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_directory_resource_paths_fail_without_opening_a_fifo_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fifo");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let paths = Paths {
            work: path.clone(),
            output: path.clone(),
            store: path,
        };
        let error = Snapshot::observe(&paths).unwrap_err();
        assert!(error.contains("must be a directory"));
    }
}
