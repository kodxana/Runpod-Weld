//! Read-only resource observations. No observation is a reserved allocation.
#[cfg(not(target_os = "linux"))]
pub fn discover() -> serde_json::Value {
    serde_json::json!({"supported": false, "status": "unsupported", "reason": "resource discovery requires Linux", "enforcement": "observe_only",
        "warnings": ["No resource capacity inferred from host totals."]})
}

#[cfg(target_os = "linux")]
pub fn discover() -> serde_json::Value {
    observations::discover()
}

#[cfg(any(target_os = "linux", test))]
mod observations {
    use serde::Serialize;
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};

    const MAX_CPU_ID: u32 = 1_048_575;
    const MAX_INPUT: usize = 1024 * 1024;

    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[serde(tag = "state", content = "value", rename_all = "snake_case")]
    enum Reading<T> {
        Finite(T),
        UnlimitedAtThisLevel,
        Unavailable(String),
        Malformed(String),
    }

    fn number(raw: &str, unlimited: Option<&str>) -> Reading<u64> {
        let s = raw.trim();
        if unlimited == Some(s) {
            Reading::UnlimitedAtThisLevel
        } else if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse()
                .map(Reading::Finite)
                .unwrap_or_else(|_| Reading::Malformed(raw.into()))
        } else {
            Reading::Malformed(raw.into())
        }
    }

    fn cpu_set(raw: &str) -> Result<BTreeSet<u32>, String> {
        if raw.len() > MAX_INPUT {
            return Err("CPU list exceeds parser bound".into());
        }
        let mut result = BTreeSet::new();
        if raw.trim().is_empty() {
            return Ok(result);
        }
        let mut expanded = 0u64;
        for item in raw.trim().split(',') {
            let parts: Vec<_> = item.split('-').collect();
            if parts.is_empty() || parts.len() > 2 {
                return Err("invalid CPU range".into());
            }
            let parse = |s: &str| -> Result<u32, String> {
                if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid CPU ID".into());
                }
                s.parse::<u32>()
                    .ok()
                    .filter(|n| *n <= MAX_CPU_ID)
                    .ok_or_else(|| "CPU ID exceeds parser bound".into())
            };
            let first = parse(parts[0])?;
            let last = if parts.len() == 2 {
                parse(parts[1])?
            } else {
                first
            };
            if last < first {
                return Err("descending CPU range".into());
            }
            expanded += u64::from(last - first) + 1;
            if expanded > u64::from(MAX_CPU_ID) + 1 {
                return Err("CPU expansion exceeds parser bound".into());
            }
            result.extend(first..=last);
        }
        Ok(result)
    }

    fn quota(raw: &str) -> Reading<f64> {
        let fields: Vec<_> = raw.split_whitespace().collect();
        if fields.len() != 2 {
            return Reading::Malformed(raw.into());
        }
        let period = match number(fields[1], None) {
            Reading::Finite(n) if n > 0 => n,
            _ => return Reading::Malformed(raw.into()),
        };
        match number(fields[0], Some("max")) {
            Reading::Finite(n) if n > 0 => Reading::Finite(n as f64 / period as f64),
            Reading::UnlimitedAtThisLevel => Reading::UnlimitedAtThisLevel,
            _ => Reading::Malformed(raw.into()),
        }
    }

    #[derive(Clone, Debug, Serialize)]
    struct Mount {
        id: String,
        device: String,
        root: Vec<u8>,
        point: Vec<u8>,
        version: u8,
        controllers: Vec<String>,
    }

    fn unescape(raw: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'\\' {
                let code = raw.get(i + 1..i + 4).ok_or("truncated mount escape")?;
                let byte = match code {
                    b"040" => b' ',
                    b"011" => b'\t',
                    b"012" => b'\n',
                    b"134" => b'\\',
                    _ => return Err("invalid mount escape".into()),
                };
                out.push(byte);
                i += 4;
            } else {
                out.push(raw[i]);
                i += 1;
            }
        }
        Ok(out)
    }

    fn valid_path(path: &[u8]) -> bool {
        path == b"/"
            || (path.starts_with(b"/")
                && !path.contains(&0)
                && !path.ends_with(b"/")
                && !path
                    .split(|b| *b == b'/')
                    .skip(1)
                    .any(|p| p.is_empty() || p == b"." || p == b".."))
    }

    fn within(path: &[u8], root: &[u8]) -> bool {
        path == root
            || (root == b"/" && path.starts_with(b"/"))
            || (path.starts_with(root) && path.get(root.len()) == Some(&b'/'))
    }

    fn parse_mounts(raw: &[u8]) -> Result<Vec<Mount>, String> {
        let mut mounts = Vec::new();
        for line in raw.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let f: Vec<_> = line.split(|b| *b == b' ').collect();
            let sep = f
                .iter()
                .position(|s| *s == b"-")
                .ok_or("mountinfo separator missing")?;
            if sep < 6 || f.len() < sep + 4 {
                return Err("short mountinfo record".into());
            }
            let version = match f[sep + 1] {
                b"cgroup" => 1,
                b"cgroup2" => 2,
                _ => 0,
            };
            mounts.push(Mount {
                id: String::from_utf8_lossy(f[0]).into_owned(),
                device: String::from_utf8_lossy(f[2]).into_owned(),
                root: unescape(f[3])?,
                point: unescape(f[4])?,
                version,
                controllers: String::from_utf8_lossy(f[sep + 3])
                    .split(',')
                    .map(str::to_owned)
                    .collect(),
            });
        }
        Ok(mounts)
    }

    #[derive(Debug)]
    struct Membership {
        controllers: Vec<String>,
        path: Vec<u8>,
        unified: bool,
    }

    fn parse_memberships(raw: &[u8]) -> Result<Vec<Membership>, String> {
        raw.split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|line| {
                let f: Vec<_> = line.splitn(3, |b| *b == b':').collect();
                if f.len() != 3 || f[0].is_empty() || !f[0].iter().all(u8::is_ascii_digit) {
                    return Err("invalid cgroup membership record".into());
                }
                Ok(Membership {
                    controllers: String::from_utf8_lossy(f[1])
                        .split(',')
                        .map(str::to_owned)
                        .collect(),
                    path: f[2].to_vec(),
                    unified: f[0] == b"0" && f[1].is_empty(),
                })
            })
            .collect()
    }

    #[derive(Debug, Serialize)]
    struct Resolution {
        mount: Mount,
        membership: Vec<u8>,
        leaf: Vec<u8>,
    }

    fn resolve(
        mounts: &[Mount],
        members: &[Membership],
        controller: &str,
    ) -> Result<Resolution, String> {
        let v1: Vec<_> = members
            .iter()
            .filter(|m| m.controllers.iter().any(|c| c == controller))
            .collect();
        let matches: Vec<_> = if v1.is_empty() {
            members.iter().filter(|m| m.unified).collect()
        } else {
            v1
        };
        if matches.len() != 1 {
            return Err(format!("{controller}: missing or ambiguous membership"));
        }
        let member = matches[0];
        if !valid_path(&member.path) {
            return Err(format!("{controller}: ambiguous namespace membership path"));
        }
        let mut candidates = Vec::new();
        for mount in mounts {
            if (member.unified && mount.version != 2)
                || (!member.unified
                    && (mount.version != 1 || !mount.controllers.iter().any(|c| c == controller)))
            {
                continue;
            }
            if !valid_path(&mount.root)
                || !valid_path(&mount.point)
                || !within(&member.path, &mount.root)
            {
                continue;
            }
            let relative = if mount.root == b"/" {
                &member.path[1..]
            } else {
                member.path[mount.root.len()..]
                    .strip_prefix(b"/")
                    .unwrap_or(b"")
            };
            let mut leaf = mount.point.clone();
            if !relative.is_empty() {
                if leaf != b"/" {
                    leaf.push(b'/');
                }
                leaf.extend_from_slice(relative);
            }
            // Any nested/stacked mount makes a path walk ambiguous; never read through it.
            if mounts.iter().any(|other| {
                other.id != mount.id
                    && within(&other.point, &mount.point)
                    && within(&leaf, &other.point)
            }) {
                continue;
            }
            candidates.push(Resolution {
                mount: mount.clone(),
                membership: member.path.clone(),
                leaf,
            });
        }
        candidates.sort_by_key(|r| r.mount.root.len());
        if candidates.is_empty() {
            return Err(format!("{controller}: no unambiguous visible mount"));
        }
        if candidates
            .iter()
            .any(|r| r.mount.device != candidates[0].mount.device)
        {
            return Err(format!("{controller}: conflicting mount devices"));
        }
        Ok(candidates.remove(0))
    }

    #[derive(Debug, Serialize)]
    struct Level {
        path: Vec<u8>,
        files: BTreeMap<String, Reading<String>>,
    }

    fn collect(
        resolution: &Resolution,
        mut read: impl FnMut(&[u8], &str) -> Result<String, String>,
    ) -> Vec<Level> {
        let files: &[&str] = if resolution.mount.version == 2 {
            &[
                "memory.current",
                "memory.max",
                "memory.high",
                "memory.stat",
                "memory.events",
                "memory.events.local",
                "memory.swap.current",
                "memory.swap.max",
                "cpu.max",
                "cpu.stat",
                "cpuset.cpus.effective",
            ]
        } else {
            &[
                "memory.limit_in_bytes",
                "memory.usage_in_bytes",
                "memory.use_hierarchy",
                "memory.stat",
                "memory.failcnt",
                "memory.max_usage_in_bytes",
                "memory.memsw.limit_in_bytes",
                "memory.memsw.usage_in_bytes",
                "memory.oom_control",
                "cpu.cfs_quota_us",
                "cpu.cfs_period_us",
                "cpu.stat",
                "cpuset.effective_cpus",
                "cpuset.cpus",
            ]
        };
        let mut levels = Vec::new();
        let mut path = resolution.leaf.clone();
        loop {
            let values = files
                .iter()
                .map(|name| {
                    (
                        (*name).into(),
                        match read(&path, name) {
                            Ok(raw) => Reading::Finite(raw),
                            Err(e) => Reading::Unavailable(e),
                        },
                    )
                })
                .collect();
            levels.push(Level {
                path: path.clone(),
                files: values,
            });
            if path == resolution.mount.point {
                break;
            }
            let end = path.iter().rposition(|b| *b == b'/').unwrap_or(0);
            path.truncate(end.max(1));
        }
        levels
    }

    fn raw<'a>(level: &'a Level, name: &str) -> Result<&'a str, String> {
        match level.files.get(name) {
            Some(Reading::Finite(s)) => Ok(s),
            Some(Reading::Unavailable(e)) => Err(e.clone()),
            _ => Err(format!("{name} unavailable")),
        }
    }

    fn value(level: &Level, name: &str, unlimited: Option<&str>) -> Reading<u64> {
        match raw(level, name) {
            Ok(s) => number(s, unlimited),
            Err(e) => Reading::Unavailable(e),
        }
    }

    fn minimum<T: PartialOrd + Copy>(old: &mut Option<T>, new: T) {
        if old.is_none_or(|n| new < n) {
            *old = Some(new);
        }
    }

    fn v1_sentinel(long_bits: u32, page_size: u64) -> Option<u64> {
        if !page_size.is_power_of_two() {
            return None;
        }
        // Linux v6.8 page_counter.h: 32-bit LONG_MAX pages, 64-bit LONG_MAX / PAGE_SIZE pages.
        let pages = match long_bits {
            32 => i32::MAX as u64,
            64 => i64::MAX as u64 / page_size,
            _ => return None,
        };
        pages.checked_mul(page_size).filter(|n| *n > 0)
    }

    fn v1_limit(level: &Level, sentinel: Option<u64>) -> Reading<u64> {
        match value(level, "memory.limit_in_bytes", None) {
            Reading::Finite(n) => match sentinel {
                Some(max) if n == max => Reading::UnlimitedAtThisLevel,
                Some(max) if n < max => Reading::Finite(n),
                Some(_) => {
                    Reading::Malformed("v1 memory limit exceeds validated kernel maximum".into())
                }
                None => Reading::Unavailable(
                    "v1 memory sentinel unresolved: kernel ABI/page size not validated".into(),
                ),
            },
            other => other,
        }
    }

    fn memory_with_sentinel(levels: &[Level], version: u8, sentinel: Option<u64>) -> Value {
        let mut hard_ceiling = None;
        let mut operating_ceiling = None;
        let mut hard_headroom = None;
        let mut operating_headroom = None;
        let mut incomplete = levels.is_empty();
        let mut observations = Vec::new();
        for (index, level) in levels.iter().enumerate() {
            let max = if version == 2 {
                value(level, "memory.max", Some("max"))
            } else {
                v1_limit(level, sentinel)
            };
            let high = if version == 2 {
                value(level, "memory.high", Some("max"))
            } else {
                Reading::UnlimitedAtThisLevel
            };
            let usage = value(
                level,
                if version == 2 {
                    "memory.current"
                } else {
                    "memory.usage_in_bytes"
                },
                None,
            );
            let hierarchy_enabled = version == 2
                || matches!(
                    value(level, "memory.use_hierarchy", None),
                    Reading::Finite(1)
                );
            let hierarchical = index == 0 || hierarchy_enabled;
            if !hierarchy_enabled {
                incomplete = true;
            }
            let mut operating = None;
            if !hierarchical {
                incomplete = true;
            }
            for (limit, hard) in [(&max, true), (&high, false)] {
                match limit {
                    Reading::Finite(n) if hierarchical => {
                        minimum(&mut operating, *n);
                        if hard {
                            minimum(&mut hard_ceiling, *n);
                        }
                        if let Reading::Finite(used) = &usage {
                            if hard {
                                minimum(&mut hard_headroom, n.saturating_sub(*used));
                            }
                        } else {
                            incomplete = true;
                        }
                    }
                    Reading::UnlimitedAtThisLevel => (),
                    _ => incomplete = true,
                }
            }
            if let Some(n) = operating {
                minimum(&mut operating_ceiling, n);
                if let Reading::Finite(used) = &usage {
                    minimum(&mut operating_headroom, n.saturating_sub(*used));
                }
            }
            observations.push(json!({"path_bytes": level.path, "max": max, "high": high, "usage": usage, "hierarchical_accounting_usable": hierarchical}));
        }
        json!({"levels": observations, "observed_hard_ceiling_bytes": hard_ceiling,
        "observed_operating_ceiling_bytes": operating_ceiling, "observed_hard_headroom_bytes": hard_headroom,
        "observed_operating_headroom_bytes": operating_headroom, "visible_data_incomplete": incomplete,
        "v1_sentinels_normalized": version == 1 && sentinel.is_some(),
        "v1_sentinel_bytes": if version == 1 { sentinel } else { None },
        "explicit_budget_required": operating_headroom.is_none()})
    }

    fn cpu(
        cpu_levels: &[Level],
        cpu_version: u8,
        sets: &[Level],
        set_version: u8,
        affinity: Result<BTreeSet<u32>, String>,
    ) -> Value {
        let mut capacity = None;
        let mut quota_incomplete = cpu_levels.is_empty();
        let mut quotas = Vec::new();
        for level in cpu_levels {
            let q = if cpu_version == 2 {
                raw(level, "cpu.max").map(quota)
            } else {
                raw(level, "cpu.cfs_quota_us").and_then(|q| {
                    raw(level, "cpu.cfs_period_us").map(|p| {
                        quota(&format!(
                            "{} {}",
                            if q.trim() == "-1" { "max" } else { q.trim() },
                            p.trim()
                        ))
                    })
                })
            }
            .unwrap_or_else(Reading::Unavailable);
            match &q {
                Reading::Finite(n) => minimum(&mut capacity, *n),
                Reading::UnlimitedAtThisLevel => (),
                _ => quota_incomplete = true,
            }
            quotas.push(json!({"path_bytes": level.path, "quota_cpus": q}));
        }
        let mut mask = affinity.as_ref().ok().cloned();
        let mut cpuset_known = false;
        let mut cpuset_incomplete = sets.is_empty();
        let mut set_observations = Vec::new();
        for level in sets {
            let effective = if set_version == 2 {
                "cpuset.cpus.effective"
            } else {
                "cpuset.effective_cpus"
            };
            let parsed = match raw(level, effective) {
                Ok(s) => cpu_set(s),
                Err(_) if set_version == 1 => raw(level, "cpuset.cpus").and_then(|s| {
                    if s.trim().is_empty() {
                        Err("configured empty cpuset: inherits visible parent".into())
                    } else {
                        cpu_set(s)
                    }
                }),
                Err(e) => Err(e),
            };
            match &parsed {
                Ok(set) => {
                    cpuset_known = true;
                    mask = Some(match mask {
                        Some(ref prior) => prior.intersection(set).copied().collect(),
                        None => set.clone(),
                    });
                }
                Err(_) => cpuset_incomplete = true,
            }
            set_observations.push(json!({"path_bytes": level.path, "cpus": parsed.as_ref().ok(), "error": parsed.as_ref().err()}));
        }
        if let Some(set) = &mask {
            minimum(&mut capacity, set.len() as f64);
        }
        json!({"observed_capacity_cpus": capacity, "suggested_cpu_workers": capacity.filter(|c| *c > 0.0).map(|c| (c.floor() as u64).max(1)),
        "empty_available_set": mask.as_ref().map(|m| m.is_empty()), "affinity_cpus": affinity.as_ref().ok(),
        "affinity_error": affinity.as_ref().err(), "intersection_cpus": mask, "quota_levels": quotas,
        "cpuset_levels": set_observations, "quota_data_incomplete": quota_incomplete,
        "cpuset_data_incomplete": cpuset_incomplete || !cpuset_known})
    }

    #[cfg(target_os = "linux")]
    pub(super) fn discover() -> Value {
        linux::discover()
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::{
            ffi::{CString, OsStr},
            fs,
            io::Read,
            os::unix::{ffi::OsStrExt, fs::MetadataExt},
            path::Path,
        };

        fn native_v1_sentinel() -> Option<u64> {
            // shortcut: only native x86-64/AArch64 ABIs are validated; extend with ABI/page-size evidence.
            if std::mem::size_of::<libc::c_long>() != 8 {
                return None;
            }
            let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
            if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
                return None;
            }
            let uts = unsafe { uts.assume_init() };
            let machine = unsafe { std::ffi::CStr::from_ptr(uts.machine.as_ptr()) }.to_bytes();
            let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
            let validated =
                (cfg!(target_arch = "x86_64") && machine == b"x86_64" && page_size == 4096)
                    || (cfg!(target_arch = "aarch64")
                        && machine == b"aarch64"
                        && matches!(page_size, 4096 | 16384 | 65536));
            if validated {
                v1_sentinel(64, page_size)
            } else {
                None
            }
        }

        fn monotonic_ns() -> Option<u64> {
            let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
            if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
                return None;
            }
            let time = unsafe { time.assume_init() };
            u64::try_from(time.tv_sec)
                .ok()?
                .checked_mul(1_000_000_000)?
                .checked_add(u64::try_from(time.tv_nsec).ok()?)
        }

        fn read(path: &Path) -> Result<Vec<u8>, String> {
            let mut data = Vec::new();
            fs::File::open(path)
                .and_then(|f| f.take(MAX_INPUT as u64 + 1).read_to_end(&mut data))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            if data.len() > MAX_INPUT {
                return Err(format!("{} exceeds read bound", path.display()));
            }
            Ok(data)
        }

        fn affinity() -> Result<BTreeSet<u32>, String> {
            let mut words = 16usize;
            loop {
                let mut mask = vec![0usize; words];
                let bytes = words * std::mem::size_of::<usize>();
                // The buffer is aligned and has exactly the supplied writable size.
                if unsafe { libc::sched_getaffinity(0, bytes, mask.as_mut_ptr().cast()) } == 0 {
                    let mut cpus = BTreeSet::new();
                    for (word, bits) in mask.into_iter().enumerate() {
                        for bit in 0..usize::BITS {
                            if bits & (1usize << bit) != 0 {
                                cpus.insert((word * usize::BITS as usize + bit as usize) as u32);
                            }
                        }
                    }
                    return Ok(cpus);
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINVAL)
                    || bytes >= (MAX_CPU_ID as usize + 1) / 8
                {
                    return Err(error.to_string());
                }
                words *= 2;
            }
        }

        fn controller_read(mount: &Mount, dir: &[u8], file: &str) -> Result<String, String> {
            let path = Path::new(OsStr::from_bytes(dir));
            let canonical = fs::canonicalize(path).map_err(|e| e.to_string())?;
            if canonical.as_os_str().as_bytes() != dir {
                return Err("controller path has symlink or ambiguous components".into());
            }
            let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
            let device = format!(
                "{}:{}",
                libc::major(metadata.dev()),
                libc::minor(metadata.dev())
            );
            if device != mount.device {
                return Err("controller device differs from mountinfo".into());
            }
            let cpath = CString::new(dir).map_err(|e| e.to_string())?;
            let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
            if unsafe { libc::statfs(cpath.as_ptr(), stat.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let kind = unsafe { stat.assume_init() }.f_type as u64;
            let expected = if mount.version == 2 {
                0x63677270
            } else {
                0x27e0eb
            };
            if kind != expected {
                return Err("controller filesystem type mismatch".into());
            }
            String::from_utf8(read(&path.join(file))?).map_err(|e| e.to_string())
        }

        pub(super) fn discover() -> Value {
            let start = std::time::Instant::now();
            let sampled_at = monotonic_ns();
            for attempt in 0..2 {
                let mut warnings = vec!["Only visible ancestors are observed; hidden limits and competing workloads may reduce capacity.".to_string(),
                "Headroom is a non-atomic observation, not reserved memory or OOM prevention.".to_string()];
                let membership_bytes = read(Path::new("/proc/self/cgroup"));
                let mount_bytes = read(Path::new("/proc/self/mountinfo"));
                let parsed = membership_bytes
                    .as_ref()
                    .map_err(Clone::clone)
                    .and_then(|b| parse_memberships(b))
                    .and_then(|members| {
                        mount_bytes
                            .as_ref()
                            .map_err(Clone::clone)
                            .and_then(|b| parse_mounts(b))
                            .map(|mounts| (members, mounts))
                    });
                let (members, mounts) = match parsed {
                    Ok(p) => p,
                    Err(e) => {
                        return json!({"supported": true, "status": "unavailable", "visibility": "visible_ancestors_only", "enforcement": "observe_only", "warnings": [e]});
                    }
                };
                let mut observations = BTreeMap::new();
                let mut levels = BTreeMap::new();
                for name in ["memory", "cpu", "cpuset"] {
                    match resolve(&mounts, &members, name) {
                        Ok(r) => {
                            let data =
                                collect(&r, |path, file| controller_read(&r.mount, path, file));
                            observations.insert(name, json!({"resolution": r, "raw_levels": data}));
                            levels.insert(name, (r.mount.version, data));
                        }
                        Err(e) => {
                            warnings.push(e.clone());
                            observations.insert(name, json!({"error": e}));
                        }
                    }
                }
                let empty = Vec::new();
                let (mv, ml) = levels
                    .get("memory")
                    .map(|(v, l)| (*v, l))
                    .unwrap_or((2, &empty));
                let (cv, cl) = levels
                    .get("cpu")
                    .map(|(v, l)| (*v, l))
                    .unwrap_or((2, &empty));
                let (sv, sl) = levels
                    .get("cpuset")
                    .map(|(v, l)| (*v, l))
                    .unwrap_or((2, &empty));
                let cpu = cpu(cl, cv, sl, sv, affinity());
                let changed = read(Path::new("/proc/self/cgroup")) != membership_bytes
                    || read(Path::new("/proc/self/mountinfo")) != mount_bytes;
                let empty_cpu = cpu["empty_available_set"] == true;
                if attempt == 0 && (changed || empty_cpu) {
                    continue;
                }
                if changed {
                    return json!({"supported": true, "status": "unstable", "visibility": "visible_ancestors_only", "enforcement": "observe_only", "warnings": ["Membership or mounts changed twice; capacity is unresolved."]});
                }
                if empty_cpu {
                    warnings.push(
                        "Available CPU intersection is empty after refresh; do not schedule work."
                            .into(),
                    );
                }
                let sentinel = if mv == 1 { native_v1_sentinel() } else { None };
                if mv == 1 {
                    warnings.push(if sentinel.is_some() {
                    "v1 memory is approximate; the validated native kernel sentinel is unlimited at that level. Raw values are retained."
                } else {
                    "v1 kernel ABI/page size is unvalidated; numeric limits are unresolved and require an explicit advisory build budget. Raw values are retained."
                }.into());
                }
                let memory = memory_with_sentinel(ml, mv, sentinel);
                if memory["explicit_budget_required"] == true {
                    warnings.push(
                        "No usable memory headroom: require an explicit advisory build budget."
                            .into(),
                    );
                }
                if memory["visible_data_incomplete"] == true || ml.is_empty() {
                    warnings.push("Memory observations are incomplete; reported headroom uses only known limit/usage pairs.".into());
                }
                if cpu["quota_data_incomplete"] == true || cpu["cpuset_data_incomplete"] == true {
                    warnings.push(
                        "CPU observations are incomplete; capacity uses only known restrictions."
                            .into(),
                    );
                }
                if !cpu["affinity_error"].is_null() {
                    warnings.push(
                        "Thread affinity is unavailable; CPU capacity omits that restriction."
                            .into(),
                    );
                }
                return json!({"supported": true, "status": "observed", "visibility": "visible_ancestors_only", "enforcement": "observe_only",
                "sample_started_monotonic_ns": sampled_at,
                "sample_duration_ns": start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                "controllers": observations, "memory": memory, "cpu": cpu, "warnings": warnings});
            }
            unreachable!()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn memory(levels: &[Level], version: u8) -> Value {
            memory_with_sentinel(levels, version, v1_sentinel(64, 4096))
        }

        fn level(entries: &[(&str, &str)]) -> Level {
            Level {
                path: b"/fixture".to_vec(),
                files: entries
                    .iter()
                    .map(|(k, v)| ((*k).into(), Reading::Finite((*v).into())))
                    .collect(),
            }
        }

        #[test]
        fn kernel_sentinel_formula_depends_on_long_width_and_page_size() {
            assert_eq!(v1_sentinel(32, 4096), Some(8_796_093_018_112));
            assert_eq!(v1_sentinel(32, 65536), Some(140_737_488_289_792));
            assert_eq!(v1_sentinel(64, 4096), Some(9_223_372_036_854_771_712));
            assert_eq!(v1_sentinel(64, 16384), Some(9_223_372_036_854_759_424));
            assert_eq!(v1_sentinel(64, 65536), Some(9_223_372_036_854_710_272));
            for (bits, page_size) in [(16, 4096), (64, 0), (64, 3000), (32, 1u64 << 63)] {
                assert_eq!(v1_sentinel(bits, page_size), None);
            }
        }

        #[test]
        fn unlimited_v1_never_becomes_allocatable_headroom_and_raw_is_retained() {
            for bits in [32, 64] {
                for page_size in [4096, 16384, 65536] {
                    let sentinel = v1_sentinel(bits, page_size).unwrap();
                    let raw_limit = format!("{sentinel}\n");
                    let unlimited = level(&[
                        ("memory.limit_in_bytes", &raw_limit),
                        ("memory.usage_in_bytes", "10"),
                        ("memory.use_hierarchy", "1"),
                    ]);
                    let result =
                        memory_with_sentinel(std::slice::from_ref(&unlimited), 1, Some(sentinel));
                    assert_eq!(
                        result["levels"][0]["max"]["state"],
                        "unlimited_at_this_level"
                    );
                    assert!(result["observed_hard_ceiling_bytes"].is_null());
                    assert!(result["observed_operating_headroom_bytes"].is_null());
                    assert_eq!(result["explicit_budget_required"], true);
                    assert_eq!(result["visible_data_incomplete"], false);
                    assert_eq!(result["v1_sentinels_normalized"], true);
                    assert_eq!(raw(&unlimited, "memory.limit_in_bytes").unwrap(), raw_limit);
                    let parent = level(&[
                        ("memory.limit_in_bytes", "100"),
                        ("memory.usage_in_bytes", "60"),
                        ("memory.use_hierarchy", "1"),
                    ]);
                    let bounded = memory_with_sentinel(&[unlimited, parent], 1, Some(sentinel));
                    assert_eq!(bounded["observed_hard_ceiling_bytes"], 100);
                    assert_eq!(bounded["observed_operating_headroom_bytes"], 40);
                    assert_eq!(bounded["explicit_budget_required"], false);
                }
            }
        }

        #[test]
        fn unvalidated_v1_abi_requires_budget_even_for_small_numeric_limits() {
            for limit in ["100", "8796093018112", "9223372036854771712"] {
                let l = level(&[
                    ("memory.limit_in_bytes", limit),
                    ("memory.usage_in_bytes", "10"),
                    ("memory.use_hierarchy", "1"),
                ]);
                let result = memory_with_sentinel(&[l], 1, None);
                assert_eq!(result["levels"][0]["max"]["state"], "unavailable");
                assert!(result["observed_operating_headroom_bytes"].is_null());
                assert_eq!(result["explicit_budget_required"], true);
                assert_eq!(result["visible_data_incomplete"], true);
                assert_eq!(result["v1_sentinels_normalized"], false);
            }
        }

        #[test]
        fn v1_normalization_matches_exact_sentinel_only() {
            let sentinel = v1_sentinel(64, 4096).unwrap();
            let near = (sentinel - 4096).to_string();
            let l = level(&[("memory.limit_in_bytes", &near)]);
            assert_eq!(
                v1_limit(&l, Some(sentinel)),
                Reading::Finite(sentinel - 4096)
            );
            let above = (sentinel + 1).to_string();
            assert!(matches!(
                v1_limit(&level(&[("memory.limit_in_bytes", &above)]), Some(sentinel)),
                Reading::Malformed(_)
            ));
            assert!(matches!(
                v1_limit(&level(&[("memory.limit_in_bytes", "max")]), Some(sentinel)),
                Reading::Malformed(_)
            ));
            assert!(matches!(
                v1_limit(&level(&[]), Some(sentinel)),
                Reading::Unavailable(_)
            ));
            // The same numeric value in v2 is finite; only its textual "max" is unlimited.
            let numeric = sentinel.to_string();
            let v2 = memory_with_sentinel(
                &[level(&[
                    ("memory.max", &numeric),
                    ("memory.current", "0"),
                    ("memory.high", "max"),
                ])],
                2,
                None,
            );
            assert_eq!(v2["observed_hard_ceiling_bytes"], sentinel);
        }

        #[test]
        fn valid_paths_reject_empty_trailing_and_dot_components() {
            for path in [b"/".as_slice(), b"/one", b"/one/two"] {
                assert!(valid_path(path));
            }
            for path in [
                b"".as_slice(),
                b"relative",
                b"/one/",
                b"//",
                b"/./one",
                b"/one/..",
                b"/one\0",
            ] {
                assert!(!valid_path(path));
            }
        }

        #[test]
        fn nested_memory_uses_each_levels_usage() {
            let gib = 1024u64.pow(3);
            let levels = [
                level(&[
                    ("memory.max", "8589934592"),
                    ("memory.current", "2147483648"),
                    ("memory.high", "max"),
                ]),
                level(&[
                    ("memory.max", "12884901888"),
                    ("memory.current", "11811160064"),
                    ("memory.high", "max"),
                ]),
            ];
            assert_eq!(memory(&levels, 2)["observed_hard_headroom_bytes"], gib);
            assert_eq!(memory(&levels, 2)["observed_hard_ceiling_bytes"], 8 * gib);
        }

        #[test]
        fn high_missing_unlimited_overflow_and_exhaustion() {
            let l = level(&[
                ("memory.max", "100"),
                ("memory.high", "60"),
                ("memory.current", "70"),
            ]);
            let result = memory(&[l], 2);
            assert_eq!(result["observed_hard_headroom_bytes"], 30);
            assert_eq!(result["observed_operating_headroom_bytes"], 0);
            let unknown = memory(
                &[level(&[("memory.max", "max"), ("memory.current", "5")])],
                2,
            );
            assert!(unknown["observed_hard_headroom_bytes"].is_null());
            assert_eq!(unknown["visible_data_incomplete"], true);
            assert!(matches!(
                number("18446744073709551616", None),
                Reading::Malformed(_)
            ));
            assert!(matches!(number("-1", None), Reading::Malformed(_)));
            assert!(matches!(
                number("9223372036854771712", None),
                Reading::Finite(9223372036854771712)
            ));
            let missing_usage =
                memory(&[level(&[("memory.max", "10"), ("memory.high", "max")])], 2);
            assert!(missing_usage["observed_hard_headroom_bytes"].is_null());
        }

        #[test]
        fn quotas_cpuset_and_affinity_intersect() {
            let qs = [
                level(&[("cpu.max", "250000 100000")]),
                level(&[("cpu.max", "150000 100000")]),
            ];
            let sets = [level(&[("cpuset.cpus.effective", "2-4")])];
            let result = cpu(&qs, 2, &sets, 2, cpu_set("0-7"));
            assert_eq!(result["observed_capacity_cpus"], 1.5);
            assert_eq!(result["suggested_cpu_workers"], 1);
            let fractional = cpu(
                &[
                    level(&[("cpu.max", "max 100000")]),
                    level(&[("cpu.max", "50000 100000")]),
                ],
                2,
                &sets,
                2,
                cpu_set("0-7"),
            );
            assert_eq!(fractional["observed_capacity_cpus"], 0.5);
            assert_eq!(fractional["suggested_cpu_workers"], 1);
            assert!(matches!(quota("max 0"), Reading::Malformed(_)));
            assert!(matches!(quota("1 2 extra"), Reading::Malformed(_)));
        }

        #[test]
        fn cpu_unknown_is_not_unlimited_and_empty_is_not_unknown() {
            let unknown = cpu(&[], 2, &[], 2, Err("unavailable".into()));
            assert!(unknown["observed_capacity_cpus"].is_null());
            let empty = cpu(
                &[],
                2,
                &[level(&[("cpuset.cpus.effective", "")])],
                2,
                cpu_set("0-7"),
            );
            assert_eq!(empty["observed_capacity_cpus"], 0.0);
            assert!(empty["suggested_cpu_workers"].is_null());
            assert_eq!(cpu_set("0-8191").unwrap().len(), 8192);
            assert!(cpu_set("0-4294967295").is_err());
            assert!(cpu_set("2-1").is_err());
            assert!(cpu_set("1,,2").is_err());
            assert!(cpu_set("0-1048575,0-1048575").is_err());
        }

        #[test]
        fn v1_hierarchy_and_inherited_cpuset() {
            let m = memory(
                &[
                    level(&[
                        ("memory.limit_in_bytes", "100"),
                        ("memory.usage_in_bytes", "10"),
                    ]),
                    level(&[
                        ("memory.limit_in_bytes", "20"),
                        ("memory.usage_in_bytes", "19"),
                        ("memory.use_hierarchy", "0"),
                    ]),
                ],
                1,
            );
            assert_eq!(m["observed_hard_headroom_bytes"], 90);
            assert_eq!(m["visible_data_incomplete"], true);
            let c = cpu(
                &[level(&[
                    ("cpu.cfs_quota_us", "-1"),
                    ("cpu.cfs_period_us", "100000"),
                ])],
                1,
                &[
                    level(&[("cpuset.cpus", "")]),
                    level(&[("cpuset.cpus", "2-3")]),
                ],
                1,
                cpu_set("0-7"),
            );
            assert_eq!(c["observed_capacity_cpus"], 2.0);
        }

        #[test]
        fn mount_escape_bind_root_and_visible_ancestors() {
            let mounts = parse_mounts(
                b"30 1 0:25 /tenant /odd\\040mount\\134name rw shared:1 - cgroup2 cgroup rw\n",
            )
            .unwrap();
            let members = parse_memberships(b"0::/tenant/build:one\n").unwrap();
            let r = resolve(&mounts, &members, "memory").unwrap();
            assert_eq!(r.leaf, b"/odd mount\\name/build:one");
            let levels = collect(&r, |_, _| Err("permission denied".into()));
            assert_eq!(levels.len(), 2);
            assert_eq!(levels[1].path, b"/odd mount\\name");
            assert!(memory(&levels, 2)["observed_hard_headroom_bytes"].is_null());
        }

        #[test]
        fn namespace_and_overmount_ambiguity_fail_closed() {
            let mounts = parse_mounts(b"30 1 0:25 / /cg rw - cgroup2 cgroup rw\n").unwrap();
            assert_eq!(
                resolve(&mounts, &parse_memberships(b"0::/\n").unwrap(), "cpu")
                    .unwrap()
                    .leaf,
                b"/cg"
            );
            for path in ["/../host", "/a/../b", "/a//b"] {
                assert!(
                    resolve(
                        &mounts,
                        &parse_memberships(format!("0::{path}\n").as_bytes()).unwrap(),
                        "cpu"
                    )
                    .is_err()
                );
            }
            let over = parse_mounts(
                b"30 1 0:25 / /cg rw - cgroup2 cgroup rw\n31 1 0:26 / /cg/a rw - tmpfs tmpfs rw\n",
            )
            .unwrap();
            assert!(resolve(&over, &parse_memberships(b"0::/a/b\n").unwrap(), "memory").is_err());
            let rooted = parse_mounts(b"30 1 0:25 /tenant /cg rw - cgroup2 cgroup rw\n").unwrap();
            assert!(
                resolve(
                    &rooted,
                    &parse_memberships(b"0::/tenant2\n").unwrap(),
                    "memory"
                )
                .is_err()
            );
        }

        #[test]
        fn hybrid_and_comounted_v1_resolve_independently() {
            let mounts = parse_mounts(b"30 1 0:25 / /cg rw - cgroup2 cgroup rw\n31 1 0:26 / /legacy rw - cgroup cgroup rw,cpu,cpuacct\n").unwrap();
            let members = parse_memberships(b"0::/unified\n4:cpu,cpuacct:/legacy-task\n").unwrap();
            assert_eq!(
                resolve(&mounts, &members, "cpu").unwrap().leaf,
                b"/legacy/legacy-task"
            );
            assert_eq!(
                resolve(&mounts, &members, "memory").unwrap().leaf,
                b"/cg/unified"
            );
            assert!(
                resolve(
                    &mounts,
                    &parse_memberships(b"0::/a\n0::/b\n").unwrap(),
                    "memory"
                )
                .is_err()
            );
        }

        #[test]
        fn duplicate_mounts_prefer_more_visible_ancestors() {
            let mounts = parse_mounts(b"30 1 0:25 /tenant /narrow rw - cgroup2 cgroup rw\n31 1 0:25 / /wide rw - cgroup2 cgroup rw\n").unwrap();
            let members = parse_memberships(b"0::/tenant/work\n").unwrap();
            let resolved = resolve(&mounts, &members, "memory").unwrap();
            assert_eq!(resolved.leaf, b"/wide/tenant/work");
            assert_eq!(collect(&resolved, |_, _| Ok("max".into())).len(), 3);
            let conflicting = parse_mounts(
                b"30 1 0:25 / /a rw - cgroup2 cgroup rw\n31 1 0:26 / /b rw - cgroup2 cgroup rw\n",
            )
            .unwrap();
            assert!(resolve(&conflicting, &members, "memory").is_err());
        }

        #[test]
        fn malformed_mounts_and_non_utf8_paths() {
            assert!(parse_mounts(b"30 1 0:25 / /bad\\999 rw - cgroup2 cgroup rw\n").is_err());
            assert!(parse_mounts(b"30 1 0:25 / /bad rw\n").is_err());
            let mounts = parse_mounts(b"30 1 0:25 / /cg\xff rw - cgroup2 cgroup rw\n").unwrap();
            let members = parse_memberships(b"0::/job\xfe\n").unwrap();
            assert_eq!(
                resolve(&mounts, &members, "memory").unwrap().leaf,
                b"/cg\xff/job\xfe"
            );
            let invalid_root =
                parse_mounts(b"30 1 0:25 /../outside /cg rw - cgroup2 cgroup rw\n").unwrap();
            assert!(resolve(&invalid_root, &members, "memory").is_err());
        }
    }
}
