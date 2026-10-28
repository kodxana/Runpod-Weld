//! Ephemeral evidence for the closed managed publication path only.
use super::{BlobStore, Descriptor, Sha256Digest, check_cancel, check_directories, verify_stream};
use crate::{build::Error, export::OwnedCheckpoint, image, managed_control::ManagedControl};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::{self, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::Path,
};

type Result<T> = std::result::Result<T, Error>;
// Includes tree nodes, digest storage and file bookkeeping; no descriptor JSON is retained.
const BYTES_PER_OBJECT: usize = 512;
const MAX_HANDLES: usize = 1024;
// Reserve worker/forwarder, exporter capability (three directories), lock and I/O handles.
const FD_HEADROOM: usize = 272;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Boundary {
    #[cfg(test)]
    Inherited,
    #[cfg(test)]
    Checkpoint,
    Source,
    IngestSource,
    #[cfg(test)]
    Ingest,
    Fresh,
    Anchor,
    PoolLink,
    Pending,
    FinalPool,
}

impl Boundary {
    fn source(self) -> bool {
        matches!(self, Self::Source | Self::IngestSource)
    }
}

struct Object {
    file: File,
    size: u64,
    modified: (i64, i64),
    generation: u64,
}

impl Object {
    fn validate(&self, control: &ManagedControl<'_>, actual: &Metadata) -> Result<()> {
        let retained = self.file.metadata()?;
        control.check_payload(&self.file)?;
        if !retained.is_file()
            || retained.dev() != actual.dev()
            || retained.ino() != actual.ino()
            || retained.len() != self.size
            || (retained.mtime(), retained.mtime_nsec()) != self.modified
        {
            return Err("retained publication payload changed".into());
        }
        Ok(())
    }
}

fn layer_payload(descriptor: &Descriptor) -> bool {
    matches!(
        descriptor.media_type.as_str(),
        "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.oci.image.layer.v1.tar+zstd"
    )
}

fn same_payload(actual: &Metadata, expected: &Metadata) -> bool {
    actual.is_file()
        && actual.dev() == expected.dev()
        && actual.ino() == expected.ino()
        && actual.len() == expected.len()
        && (actual.mtime(), actual.mtime_nsec()) == (expected.mtime(), expected.mtime_nsec())
}

// Re-opened descriptors and fresh names must still denote the checked object.
fn check_binding(
    store: &BlobStore,
    digest: &Sha256Digest,
    file: &File,
    expected: &Metadata,
) -> Result<()> {
    check_directories(&store.directory)?;
    let named = fs::symlink_metadata(store.directory.join(digest.encoded()))?;
    if !same_payload(&named, expected) || !same_payload(&file.metadata()?, expected) {
        return Err("checkpoint payload binding changed".into());
    }
    Ok(())
}

type ObjectKey = (bool, String, u64, u64);

pub(super) struct Evidence {
    objects: BTreeMap<ObjectKey, Object>,
    generation: u64,
    committed_generation: u64,
    capacity: usize,
    #[cfg(test)]
    pub(super) reads: Vec<(Boundary, u64, u64, u64)>,
    #[cfg(test)]
    pub(super) reused: usize,
}

impl Evidence {
    // Loading and inheritance consume only source evidence from a successful
    // publication, including its durability checks; they never admit objects.
    fn reuses_source(
        &self,
        control: &ManagedControl<'_>,
        descriptor: &Descriptor,
        size: u64,
        actual: &Metadata,
    ) -> Result<bool> {
        if self.capacity == 0 || !layer_payload(descriptor) || !fd_available() {
            return Ok(false);
        }
        let key = (true, descriptor.digest.clone(), actual.dev(), actual.ino());
        let Some(held) = self.objects.get(&key) else {
            return Ok(false);
        };
        held.validate(control, actual)?;
        Ok(held.generation <= self.committed_generation
            && size == held.size
            && actual.len() == size
            && (actual.mtime(), actual.mtime_nsec()) == held.modified)
    }

    pub(super) fn try_link_inherited(
        &self,
        control: &ManagedControl<'_>,
        source: &OwnedCheckpoint,
        destination: &BlobStore,
        descriptor: &Descriptor,
        cap: u64,
    ) -> Result<bool> {
        check_cancel(&|| control.poll())?;
        source.validate()?;
        let (digest, size) = descriptor.expected(cap)?;
        if self.capacity == 0 || self.objects.is_empty() || !fd_available() {
            return Ok(false);
        }
        let store = BlobStore::open(source.path())?;
        #[cfg(test)]
        let _fault_scope = faults::enter(&store, descriptor, Boundary::Inherited);
        #[cfg(test)]
        faults::hit(faults::Timing::Before)?;
        let (_, _, file) = store.open_blob(descriptor, cap, &|| control.poll())?;
        control.check_payload(&file)?;
        let actual = file.metadata()?;
        if !self.reuses_source(control, descriptor, size, &actual)? {
            return Ok(false);
        }
        file.sync_all()?;
        check_cancel(&|| control.poll())?;
        source.validate()?;
        check_binding(&store, &digest, &file, &actual)?;
        check_directories(&destination.directory)?;
        let target = destination.directory.join(digest.encoded());
        match fs::hard_link(store.directory.join(digest.encoded()), &target) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !same_payload(&fs::symlink_metadata(&target)?, &actual) {
                    return Ok(false);
                }
            }
            Err(error) => return Err(error.into()),
        }
        #[cfg(test)]
        faults::hit(faults::Timing::After)?;
        check_binding(destination, &digest, &file, &actual)?;
        check_binding(&store, &digest, &file, &actual)?;
        source.validate()?;
        control.check()?;
        Ok(true)
    }

    pub(super) fn load_checkpoint(
        &self,
        control: &ManagedControl<'_>,
        checkpoint: &OwnedCheckpoint,
        limits: image::Limits,
    ) -> Result<image::ImageMetadata> {
        let cancelled = || control.poll();
        check_cancel(&cancelled)?;
        checkpoint.validate()?;
        let store = BlobStore::open(checkpoint.path())?;
        let metadata =
            image::load_layout_metadata(checkpoint.path(), &store, None, limits, &cancelled)?;
        for layer in &metadata.layers {
            #[cfg(test)]
            let _fault_scope = faults::enter(&store, layer, Boundary::Checkpoint);
            #[cfg(test)]
            faults::hit(faults::Timing::Before)?;
            checkpoint.validate()?;
            let (digest, size, mut file) =
                store.open_blob(layer, limits.max_layer_bytes, &cancelled)?;
            control.check_payload(&file)?;
            let actual = file.metadata()?;
            if !self.reuses_source(control, layer, size, &actual)? {
                verify_stream(&mut file, None, &digest, size, &cancelled)?;
            }
            #[cfg(test)]
            faults::hit(faults::Timing::After)?;
            check_binding(&store, &digest, &file, &actual)?;
        }
        checkpoint.validate()?;
        control.check()?;
        Ok(metadata)
    }

    #[cfg(test)]
    pub(super) fn files(&self) -> impl Iterator<Item = &File> {
        self.objects.values().map(|object| &object.file)
    }

    pub(super) fn new(limits: image::Limits) -> Self {
        let capacity = limits
            .max_descriptors
            .saturating_mul(2)
            .min(MAX_HANDLES)
            .min(
                usize::try_from(limits.max_total_metadata_bytes).unwrap_or(usize::MAX)
                    / BYTES_PER_OBJECT,
            );
        Self {
            objects: BTreeMap::new(),
            generation: 0,
            committed_generation: 0,
            capacity,
            #[cfg(test)]
            reads: Vec::new(),
            #[cfg(test)]
            reused: 0,
        }
    }

    pub(super) fn clear(&mut self) {
        self.objects.clear();
        self.capacity = 0;
        self.committed_generation = 0;
    }

    pub(super) fn commit(&mut self) {
        self.committed_generation = self.generation;
    }

    pub(super) fn begin(&mut self) {
        if !fd_available() {
            self.clear();
        }
        if let Some(next) = self.generation.checked_add(1) {
            self.generation = next;
        } else {
            self.clear();
        }
    }

    fn retain(&mut self, key: ObjectKey, file: &File) -> Result<()> {
        if self.capacity == 0 || self.objects.contains_key(&key) {
            return Ok(());
        }
        if self.objects.len() >= self.capacity || !fd_available() {
            self.clear();
            return Ok(());
        }
        let Ok(held) = file.try_clone() else {
            self.clear();
            return Ok(());
        };
        let Ok(metadata) = held.metadata() else {
            self.clear();
            return Ok(());
        };
        if self
            .objects
            .keys()
            .any(|other| other.0 != key.0 && other.2 == metadata.dev() && other.3 == metadata.ino())
        {
            return Err("source checkpoint aliases cache payload".into());
        }
        self.objects.insert(
            key,
            Object {
                file: held,
                size: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                generation: self.generation,
            },
        );
        Ok(())
    }
}

fn fd_available() -> bool {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the supplied rlimit on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: the preceding call succeeded.
    let limit = unsafe { limit.assume_init() }.rlim_cur;
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return false;
    };
    let mut count = 0usize;
    for entry in entries {
        if entry.is_err() {
            return false;
        }
        count = count.saturating_add(1);
    }
    (count.saturating_add(FD_HEADROOM) as u64) < limit
}

// Only the session constructs Managed. The callback accepted by shared cache
// code is then closed progress/resource polling, never caller code.
pub(super) struct Verification<'state, 'control> {
    managed: Option<Managed<'state, 'control>>,
}

struct Managed<'state, 'control> {
    control: &'state ManagedControl<'control>,
    source: &'state OwnedCheckpoint,
    evidence: &'state mut Evidence,
}

impl<'state, 'control> Verification<'state, 'control> {
    pub(super) fn conservative() -> Self {
        Self { managed: None }
    }

    pub(super) fn managed(
        control: &'state ManagedControl<'control>,
        source: &'state OwnedCheckpoint,
        evidence: &'state mut Evidence,
    ) -> Self {
        Self {
            managed: Some(Managed {
                control,
                source,
                evidence,
            }),
        }
    }

    pub(super) fn no_reuse(&mut self) {
        if let Some(managed) = &mut self.managed {
            managed.evidence.clear();
        }
    }

    pub(super) fn winner(&mut self, destination: &Path) -> Result<()> {
        if self.managed.is_some() {
            match fs::symlink_metadata(destination) {
                Ok(_) => self.no_reuse(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<()> {
        if let Some(managed) = &self.managed {
            managed.source.validate()?;
            for object in managed.evidence.objects.values() {
                managed.control.check_payload(&object.file)?;
                let metadata = object.file.metadata()?;
                if !metadata.is_file()
                    || metadata.len() != object.size
                    || (metadata.mtime(), metadata.mtime_nsec()) != object.modified
                {
                    return Err("retained publication payload changed".into());
                }
            }
        }
        Ok(())
    }

    pub(super) fn layout(
        &mut self,
        root: &Path,
        limits: image::Limits,
        boundary: Boundary,
        cancelled: &impl Fn() -> bool,
    ) -> Result<image::ImageMetadata> {
        let Some(managed) = &self.managed else {
            return Ok(image::load_layout(root, None, limits, cancelled)?);
        };
        if boundary.source() {
            managed.source.validate()?;
        }
        let store = BlobStore::open(root)?;
        let metadata = image::load_layout_metadata(root, &store, None, limits, cancelled)?;
        for layer in &metadata.layers {
            self.open(&store, layer, limits.max_layer_bytes, boundary, cancelled)?;
        }
        if boundary.source() {
            self.managed
                .as_ref()
                .expect("managed verification is stable")
                .source
                .validate()?;
        }
        Ok(metadata)
    }

    pub(super) fn open(
        &mut self,
        store: &BlobStore,
        descriptor: &Descriptor,
        cap: u64,
        boundary: Boundary,
        cancelled: &impl Fn() -> bool,
    ) -> Result<File> {
        let Some(managed) = &mut self.managed else {
            return Ok(store.open_verified(descriptor, cap, cancelled)?);
        };
        #[cfg(test)]
        let _fault_scope = faults::enter(store, descriptor, boundary);
        #[cfg(test)]
        faults::hit(faults::Timing::Before)?;
        if boundary.source() {
            managed.source.validate()?;
        }
        let (digest, size, mut file) = store.open_blob(descriptor, cap, cancelled)?;
        managed.control.check_payload(&file)?;
        let metadata = file.metadata()?;
        let key = (
            boundary.source(),
            digest.as_str().to_owned(),
            metadata.dev(),
            metadata.ino(),
        );
        let payload = layer_payload(descriptor);
        let mut reuse = false;
        if payload && let Some(held) = managed.evidence.objects.get(&key) {
            held.validate(managed.control, &metadata)?;
            reuse = held.generation < managed.evidence.generation
                && size == held.size
                && metadata.len() == size;
        }
        if !reuse {
            verify_stream(&mut file, None, &digest, size, cancelled)?;
            let after = file.metadata()?;
            if after.len() != metadata.len()
                || (after.mtime(), after.mtime_nsec()) != (metadata.mtime(), metadata.mtime_nsec())
            {
                return Err("publication payload changed during verification".into());
            }
            file.seek(SeekFrom::Start(0))?;
            #[cfg(test)]
            if payload {
                managed
                    .evidence
                    .reads
                    .push((boundary, metadata.dev(), metadata.ino(), size));
            }
            if payload {
                managed.evidence.retain(key, &file)?;
            }
        } else {
            #[cfg(test)]
            {
                managed.evidence.reused += 1;
            }
        }
        if boundary.source() {
            managed.source.validate()?;
        }
        #[cfg(test)]
        faults::hit(faults::Timing::After)?;
        Ok(file)
    }

    pub(super) fn link(
        &mut self,
        store: &BlobStore,
        destination: &BlobStore,
        descriptor: &Descriptor,
        cap: u64,
        boundary: Boundary,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        if self.managed.is_none() {
            return Ok(store.link_verified(destination, descriptor, cap, cancelled)?);
        }
        let file = self.open(store, descriptor, cap, boundary, cancelled)?;
        file.sync_all()?;
        check_cancel(cancelled)?;
        check_directories(&destination.directory)?;
        let (digest, _) = descriptor.expected(cap)?;
        let target = destination.directory.join(digest.encoded());
        match fs::hard_link(store.directory.join(digest.encoded()), &target) {
            Ok(()) => {
                let metadata = fs::symlink_metadata(&target)?;
                let retained = file.metadata()?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.dev() != retained.dev()
                    || metadata.ino() != retained.ino()
                    || metadata.len() != retained.len()
                {
                    return Err("publication link identity changed".into());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                self.open(destination, descriptor, cap, boundary, cancelled)?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    pub(super) fn ingest(
        &mut self,
        destination: &BlobStore,
        reader: File,
        descriptor: &Descriptor,
        cap: u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        #[cfg(test)]
        let identity = reader.metadata()?;
        destination.ingest(reader, descriptor, cap, cancelled)?;
        #[cfg(test)]
        if let Some(managed) = &mut self.managed {
            managed.evidence.reads.push((
                Boundary::Ingest,
                identity.dev(),
                identity.ino(),
                identity.len(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn source_evidence_is_ineligible_until_publication_commits() {
        let temp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(temp.path()).unwrap();
        let descriptor = Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .into(),
            size: 0,
            annotations: Default::default(),
            extensions: Default::default(),
        };
        store.ingest(&b""[..], &descriptor, 0, || false).unwrap();
        let file = store.open_verified(&descriptor, 0, || false).unwrap();
        let actual = file.metadata().unwrap();
        let cancelled = AtomicBool::new(false);
        let control = ManagedControl::for_test(&cancelled).unwrap();
        let mut evidence = Evidence::new(image::Limits {
            max_metadata_bytes: 4096,
            max_total_metadata_bytes: 8192,
            max_descriptors: 4,
            max_layer_bytes: 4096,
            max_total_layer_bytes: 4096,
        });
        evidence.begin();
        evidence
            .retain(
                (true, descriptor.digest.clone(), actual.dev(), actual.ino()),
                &file,
            )
            .unwrap();
        assert!(
            !evidence
                .reuses_source(&control, &descriptor, 0, &actual)
                .unwrap()
        );
        evidence.commit();
        assert!(
            evidence
                .reuses_source(&control, &descriptor, 0, &actual)
                .unwrap()
        );
        evidence.begin();
        assert_eq!(evidence.committed_generation, 1);
        assert_eq!(evidence.generation, 2);
        evidence.clear();
        assert!(
            !evidence
                .reuses_source(&control, &descriptor, 0, &actual)
                .unwrap()
        );
    }
}

#[cfg(test)]
pub(super) mod faults {
    use super::*;
    use std::{cell::RefCell, io::Write, path::PathBuf};

    #[derive(Clone, Copy, PartialEq, Debug)]
    pub(crate) enum Timing {
        Before,
        Buffered,
        After,
    }

    struct Fault {
        boundary: Boundary,
        timing: Timing,
        digest: String,
        remaining: usize,
        fired: bool,
    }
    std::thread_local! {
        static FAULT: RefCell<Option<Fault>> = const { RefCell::new(None) };
        static ACTIVE: RefCell<Option<(PathBuf, String, Boundary)>> = const { RefCell::new(None) };
    }

    pub(super) struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            ACTIVE.with_borrow_mut(|active| *active = None);
        }
    }
    pub(super) fn enter(store: &BlobStore, descriptor: &Descriptor, boundary: Boundary) -> Scope {
        ACTIVE.with_borrow_mut(|active| {
            *active = Some((
                store.directory.join(
                    descriptor
                        .digest
                        .strip_prefix("sha256:")
                        .unwrap_or("invalid"),
                ),
                descriptor.digest.clone(),
                boundary,
            ))
        });
        Scope
    }
    pub(in crate::oci) fn hit(timing: Timing) -> io::Result<()> {
        ACTIVE.with_borrow(|active| {
            FAULT.with_borrow_mut(|fault| {
                let (Some((path, digest, boundary)), Some(fault)) = (active, fault) else {
                    return Ok(());
                };
                if fault.fired
                    || fault.digest != *digest
                    || fault.boundary != *boundary
                    || fault.timing != timing
                {
                    return Ok(());
                }
                if fault.remaining > 0 {
                    fault.remaining -= 1;
                    return Ok(());
                }
                let mut file = fs::OpenOptions::new().write(true).open(path)?;
                file.write_all(b"!")?;
                file.sync_all()?;
                fault.fired = true;
                Ok(())
            })
        })
    }
    pub(crate) struct Armed;
    impl Armed {
        pub(crate) fn fired(&self) -> bool {
            FAULT.with_borrow(|fault| fault.as_ref().is_some_and(|fault| fault.fired))
        }
    }
    impl Drop for Armed {
        fn drop(&mut self) {
            FAULT.with_borrow_mut(|fault| *fault = None);
        }
    }
    pub(crate) fn arm(boundary: Boundary, timing: Timing, digest: &str, remaining: usize) -> Armed {
        FAULT.with_borrow_mut(|fault| {
            assert!(fault.is_none(), "nested managed publication fault");
            *fault = Some(Fault {
                boundary,
                timing,
                digest: digest.into(),
                remaining,
                fired: false,
            });
        });
        Armed
    }
}
