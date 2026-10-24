//! Explicit device setup for a disposable, trusted private rootfs.
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = args
        .next()
        .map(PathBuf::from)
        .ok_or("usage: prepare_root ROOTFS")?;
    if args.next().is_some() {
        return Err("usage: prepare_root ROOTFS".into());
    }
    rpweld::devices::prepare(&root)?;
    println!("Prepared standard character devices in {}", root.display());
    Ok(())
}
