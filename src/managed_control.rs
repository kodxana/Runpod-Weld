//! Closed managed-build provenance. Held descriptors are identities, not confinement.
use std::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub(crate) struct ManagedControl<'a> {
    cancelled: &'a AtomicBool,
    resources: Option<&'a crate::build_resources::Policy>,
    last: Cell<Option<Instant>>,
    failure: RefCell<Option<String>>,
    progress: bool,
    #[cfg(target_os = "linux")]
    output: crate::progress::Output,
}

impl<'a> ManagedControl<'a> {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn for_test(cancelled: &'a AtomicBool) -> crate::build::Result<Self> {
        Ok(Self {
            cancelled,
            resources: None,
            last: Cell::new(None),
            failure: RefCell::new(None),
            progress: false,
            output: crate::progress::Output::current_or_capture()?,
        })
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Closed resource polling: no caller code, immediately due on first poll.
    pub(crate) fn poll(&self) -> bool {
        if self.cancelled() || self.failure.borrow().is_some() {
            return true;
        }
        if self
            .last
            .get()
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(1))
        {
            self.last.set(Some(Instant::now()));
            if let Some(policy) = self.resources
                && let Err(error) = policy.recheck("build in progress", &[])
            {
                *self.failure.borrow_mut() = Some(error);
                return true;
            }
        }
        false
    }

    /// Read sticky failure only. Never observe new capacity after publication.
    pub(crate) fn check(&self) -> crate::build::Result<()> {
        self.check_output()?;
        if let Some(error) = self.failure.borrow().as_ref() {
            return Err(error.clone().into());
        }
        Ok(())
    }

    pub(crate) fn progress_enabled(&self) -> bool {
        self.progress
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn check_payload(&self, file: &std::fs::File) -> crate::build::Result<()> {
        self.output.check_payload(file).map_err(Into::into)
    }

    pub(crate) fn check_output(&self) -> crate::build::Result<()> {
        #[cfg(target_os = "linux")]
        self.output.check()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn output(&self) -> &crate::progress::Output {
        &self.output
    }
}

/// Concrete managed CLI entry. Unlike the callback APIs, this accepts no caller
/// code. Current-capacity checks are observations, not allocation quotas.
///
/// The caller must uphold the engine's cooperative stable-store contract. An
/// [`crate::progress::Output`] scope retains checked reporting through final/error
/// messages. No descriptor here prevents external, proc-mediated or mapped writes.
#[cfg(target_os = "linux")]
pub fn build_managed_recorded(
    source: &str,
    options: &crate::build::BuildOptions,
    lease: &crate::store_lease::StoreLease,
    record: &mut crate::build_record::BuildRecord,
    resources: &crate::build_resources::Policy,
    cancelled: &AtomicBool,
) -> Result<crate::build::BuildResult, crate::build::Error> {
    let output = crate::progress::Output::current_or_capture()?;
    let _scope = output.enter();
    let control = ManagedControl {
        cancelled,
        resources: Some(resources),
        last: Cell::new(None),
        failure: RefCell::new(None),
        progress: options.progress,
        output,
    };
    crate::build::build_managed_inner(source, options, lease, record, resources, &control)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::build_resources::{Paths, Policy, Snapshot};

    #[test]
    fn closed_poll_preserves_atomic_order_cadence_and_sticky_resource_failure() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("resource");
        std::fs::create_dir(&directory).unwrap();
        let paths = Paths {
            work: directory.clone(),
            output: directory.clone(),
            store: directory.clone(),
        };
        let policy = Policy::resolve(
            paths.clone(),
            &Snapshot::observe(&paths).unwrap(),
            Default::default(),
            1,
            0,
        )
        .unwrap();
        let cancelled = AtomicBool::new(true);
        let mut control = ManagedControl::for_test(&cancelled).unwrap();
        control.resources = Some(&policy);
        assert!(!control.progress_enabled());
        assert!(control.poll());
        assert!(
            control.last.get().is_none(),
            "atomic cancellation must precede resource observation"
        );
        cancelled.store(false, Ordering::Relaxed);
        assert!(!control.poll());
        let saved = temp.path().join("saved");
        std::fs::rename(&directory, &saved).unwrap();
        std::fs::write(&directory, b"not a directory").unwrap();
        // Completed-publication checks do not manufacture a new resource failure.
        control.check().unwrap();
        control.last.set(Some(Instant::now()));
        assert!(!control.poll());
        control.last.set(None);
        assert!(control.poll());
        assert!(
            control
                .check()
                .unwrap_err()
                .to_string()
                .contains("resource observation")
        );
        std::fs::remove_file(&directory).unwrap();
        std::fs::rename(saved, directory).unwrap();
        assert!(control.poll());
        assert!(
            control.check().is_err(),
            "failure must survive restored capacity"
        );
        assert!(
            !control.cancelled(),
            "resource failure must not change the atomic token"
        );
    }
}
