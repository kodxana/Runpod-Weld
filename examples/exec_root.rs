//! Explicitly experimental trusted-root execution probe, not a container runtime.
use rpweld::executor::{RunOptions, run_with_cancel};
use std::{path::PathBuf, sync::atomic::AtomicBool, time::Duration};

static CANCEL: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn cancel(_: libc::c_int) {
    CANCEL.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 6 {
        return Err(
            "usage: exec_root ROOTFS STATE_DIR UID GID TIMEOUT_SECONDS SHELL_COMMAND".into(),
        );
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = cancel as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let result = run_with_cancel(
        &RunOptions {
            rootfs: PathBuf::from(&args[0]),
            state_dir: PathBuf::from(&args[1]),
            uid: args[2].parse()?,
            gid: args[3].parse()?,
            timeout: Duration::from_secs(args[4].parse()?),
            term_grace: Duration::from_secs(2),
            command: args[5].clone(),
        },
        &CANCEL,
    )?;
    eprintln!("{}", serde_json::to_string(&result)?);
    let code = if result.timed_out {
        124
    } else if result.cancelled {
        130
    } else {
        result.exit_code.unwrap_or(1)
    };
    std::process::exit(code);
}
