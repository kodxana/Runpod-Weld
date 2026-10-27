//! Core components of Runpod Weld. Image building is under development.
pub mod build;
mod build_cache;
pub mod build_plan;
pub mod build_record;
pub mod build_resources;
pub mod capabilities;
pub mod cleanup_apply;
pub mod cleanup_plan;
pub mod context;
pub mod devices;
pub mod dockerfile;
// The public context API returns Unsupported outside Linux; keep its policy type
// available there without requiring the Linux-only matcher to have callers.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod dockerignore;
pub mod executor;
pub mod export;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod export_compression;
pub mod image;
pub mod layer;
mod lease_guard;
#[cfg(target_os = "linux")]
pub mod lease_process;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod managed_control;
pub mod oci;
pub mod progress;
pub mod registry;
pub mod resources;
pub mod rootfs;
pub mod run_mounts;
pub mod store_access;
pub mod store_inventory;
pub mod store_lease;
pub mod trace_worker;
pub mod user;
