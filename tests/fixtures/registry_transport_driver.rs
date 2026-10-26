//! Local HTTPS harness driver: compile against the just-built rpweld rlib.
//! rustc --edition=2024 tests/fixtures/registry_transport_driver.rs \
//!   --extern rpweld=/target/debug/deps/librpweld-HASH.rlib \
//!   -L dependency=/target/debug/deps -o /target/debug/registry-transport-driver
//! Pass that executable as --transport-driver to tests/registry_preflight_https.py.
use rpweld::{image::Limits, registry, store_lease::StoreLease};
use std::{cell::Cell, os::unix::fs::PermissionsExt, path::PathBuf};

fn run(args: &[String]) -> Result<(), String> {
    let mode = &args[0];
    let reference = registry::reference(&args[1], true)?;
    let auth = PathBuf::from(&args[2]);
    let options = registry::Options {
        authfile: Some(auth.clone()),
        cert_dir: Some(PathBuf::from(&args[3])),
    };
    let destination = PathBuf::from(&args[4]);
    let store = registry::store_dir()?;
    let lease = StoreLease::shared(&store, &|| false).map_err(|e| e.to_string())?;
    let transport = registry::Transport::new(&options)?;
    if mode == "old" {
        return transport.pull(&lease, &reference, &destination, &|| false);
    }
    let cancelled = Cell::new(false);
    transport.pull_checked_with_pre_copy(
        &lease,
        &reference,
        &destination,
        Limits {
            max_metadata_bytes: 4 * 1024 * 1024,
            max_total_metadata_bytes: 12 * 1024 * 1024,
            max_descriptors: 4096,
            max_layer_bytes: u64::MAX,
            max_total_layer_bytes: u64::MAX,
        },
        &|| cancelled.get(),
        |summary| {
            assert_eq!(
                summary.declared_compressed_bytes,
                args[5].parse::<u64>().unwrap()
            );
            assert_eq!(summary.layer_count, args[6].parse::<usize>().unwrap());
            let mut transport_found = false;
            for dir in std::fs::read_dir(auth.parent().unwrap()).unwrap() {
                let dir = dir.unwrap();
                if dir
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".rpweld-registry-")
                {
                    transport_found = true;
                    assert_eq!(dir.metadata().unwrap().permissions().mode() & 0o777, 0o700);
                    let mut policy_found = false;
                    for file in std::fs::read_dir(dir.path()).unwrap() {
                        let file = file.unwrap();
                        if file.metadata().unwrap().is_file() {
                            assert_eq!(
                                file.metadata().unwrap().permissions().mode() & 0o777,
                                0o600
                            );
                            let data = std::fs::read(file.path()).unwrap();
                            policy_found |= data.windows(9).any(|w| w == b"\"default\"");
                        }
                    }
                    assert!(
                        policy_found,
                        "missing private policy snapshot before callback"
                    );
                }
            }
            assert!(transport_found, "missing private transport directory");
            match mode.as_str() {
                "abort" => Err("fixture pre-copy rejected".into()),
                "cancel" => {
                    cancelled.set(true);
                    Ok(())
                }
                "checked" => Ok(()),
                _ => panic!("invalid fixture driver mode"),
            }
        },
    )
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|a| a == "__lease-guard") {
        rpweld::lease_process::entry(args);
    }
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
