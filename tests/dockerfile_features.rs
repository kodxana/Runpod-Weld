//! Docker 29.7.2 oracle, generated without invoking the candidate builder.
//! Run on Linux as root for ownership-preserving OCI replay; individual builds
//! deliberately remove CAP_CHOWN below. See fixtures/dockerfile-features/README.md.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use serde_json::{Value, json};
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    temp: tempfile::TempDir,
    context: PathBuf,
}

impl Fixture {
    fn new(case: &Value) -> Self {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let context = temp.path().join("context");
        fs::create_dir(&context).unwrap();
        let files = case["files"].as_object().unwrap();
        for (name, spec) in files {
            let path = context.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            if spec["dir"] == true {
                fs::create_dir_all(path).unwrap();
            } else {
                let data = spec.as_str().or_else(|| spec["data"].as_str()).unwrap();
                fs::write(path, data).unwrap();
            }
        }
        for (name, spec) in files {
            fs::set_permissions(
                context.join(name),
                fs::Permissions::from_mode(spec["mode"].as_u64().unwrap_or(0o644) as u32),
            )
            .unwrap();
        }
        fs::write(
            context.join("Dockerfile"),
            case["dockerfile"].as_str().unwrap(),
        )
        .unwrap();
        Self { temp, context }
    }

    fn build(&self, case: &Value, extra: &[&str], no_chown: bool) -> (Output, PathBuf) {
        let output = self.temp.path().join("output");
        let log = self.temp.path().join("stderr");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rpweld"));
        command
            .env("HOME", self.temp.path())
            .env("RPWELD_HOME", self.temp.path().join("store"))
            .args([
                "build",
                "--no-cache",
                "--platform",
                "linux/amd64",
                "--output",
            ])
            .arg(&output)
            .arg("--work-dir")
            .arg(self.temp.path().join("work"));
        for arg in case["args"].as_array().unwrap() {
            command.arg("--build-arg").arg(arg.as_str().unwrap());
        }
        command
            .args(extra)
            .arg(&self.context)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap());
        if no_chown {
            // Bounding removal prevents root exec from reacquiring the dropped bit.
            unsafe {
                command.pre_exec(drop_chown);
            }
        }
        let mut child = command.spawn().unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(25) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "bounded feature build timed out: {}",
                    fs::read_to_string(log).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut result = child.wait_with_output().unwrap();
        result.stderr = fs::read(log).unwrap();
        (result, output)
    }
}

fn drop_chown() -> std::io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    unsafe {
        if libc::prctl(libc::PR_CAPBSET_DROP, 0, 0, 0, 0) != 0
            || libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        data[0].effective &= !1;
        data[0].permitted &= !1;
        data[0].inheritable &= !1;
        if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if data[0].effective & 1 != 0
            || data[0].permitted & 1 != 0
            || libc::prctl(libc::PR_CAPBSET_READ, 0, 0, 0, 0) != 0
        {
            return Err(std::io::Error::other("CAP_CHOWN was not removed"));
        }
    }
    Ok(())
}

fn oracle(name: &str) -> Value {
    let all: Value = serde_json::from_str(include_str!(
        "fixtures/dockerfile-features/docker-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        all["engine"], "29.7.2",
        "review refreshed oracle semantics/version"
    );
    all["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
        .clone()
}

fn metadata(output: &Path) -> rpweld::image::ImageMetadata {
    rpweld::image::load_layout(
        output,
        None,
        rpweld::image::Limits {
            max_metadata_bytes: 1 << 20,
            max_total_metadata_bytes: 4 << 20,
            max_descriptors: 100,
            max_layer_bytes: 16 << 20,
            max_total_layer_bytes: 32 << 20,
        },
        || false,
    )
    .unwrap()
}

fn replay(output: &Path, metadata: &rpweld::image::ImageMetadata) -> PathBuf {
    let store = rpweld::oci::BlobStore::open(output).unwrap();
    let root = output.with_extension("replay");
    fs::create_dir(&root).unwrap();
    for (descriptor, diff_id) in metadata.layers.iter().zip(&metadata.diff_ids) {
        let mut layer = rpweld::layer::verify(
            &store,
            descriptor,
            diff_id,
            output.parent().unwrap(),
            rpweld::layer::Limits {
                max_blob_bytes: 16 << 20,
                max_uncompressed_bytes: 16 << 20,
                max_entries: 1000,
                max_metadata_bytes: 1 << 20,
                max_gzip_header_bytes: 1024,
            },
            || false,
        )
        .unwrap();
        rpweld::rootfs::apply_layer(&root, &mut layer, || false).unwrap();
    }
    root
}

fn check(case: &Value, result: &Output, output: &Path) {
    assert_eq!(
        result.status.success(),
        case["success"].as_bool().unwrap(),
        "{}: {}",
        case["name"],
        String::from_utf8_lossy(&result.stderr)
    );
    if !result.status.success() {
        assert!(!output.exists(), "failed build published an image");
        return;
    }
    let meta = metadata(output);
    for key in ["Cmd", "Entrypoint", "Shell", "Labels"] {
        let got = &meta.config["config"][key];
        let expected = &case["config"][key];
        // Docker/OCI permit absent, null and empty command/map defaults.
        if expected.is_null() && (got.is_null() || got == &json!([]) || got == &json!({})) {
            continue;
        }
        assert_eq!(got, expected, "{} config {key}", case["name"]);
    }
    let root = replay(output, &meta);
    for (path, expected) in case["entries"].as_object().unwrap() {
        let p = root.join(path);
        let m = fs::symlink_metadata(&p).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(
            m.is_dir(),
            expected["dir"].as_bool().unwrap(),
            "{path} type"
        );
        assert_eq!(
            m.mode() & 0o7777,
            expected["mode"].as_u64().unwrap() as u32,
            "{path} mode"
        );
        assert_eq!(
            m.uid(),
            expected["uid"].as_u64().unwrap() as u32,
            "{path} uid"
        );
        assert_eq!(
            m.gid(),
            expected["gid"].as_u64().unwrap() as u32,
            "{path} gid"
        );
        if let Some(data) = expected["data"].as_str() {
            assert_eq!(fs::read(&p).unwrap(), data.as_bytes(), "{path} contents");
        }
    }
    for path in case["absent"].as_array().unwrap() {
        assert!(
            !root.join(path.as_str().unwrap()).exists(),
            "unexpected {path}"
        );
    }
}

fn run(name: &str) {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run feature tests as Linux root for OCI replay"
    );
    let case = oracle(name);
    let fixture = Fixture::new(&case);
    let (result, output) = fixture.build(&case, &[], false);
    check(&case, &result, &output);
}

macro_rules! cases {
    ($($name:ident),* $(,)?) => { $(#[test] fn $name() { run(stringify!($name)); })* };
}
cases!(
    arg_default,
    arg_override,
    arg_scope,
    arg_stage_reset,
    arg_redeclare_override,
    arg_missing,
    arg_invalid,
    arg_stage_not_global,
    shell_default,
    shell_exec,
    shell_later,
    shell_inherited,
    entrypoint_resets_cmd,
    label_expansion,
    wildcard_multiple,
    wildcard_slash,
    wildcard_brackets,
    wildcard_ignore,
    wildcard_missing,
    wildcard_all_ignored,
    wildcard_multiple_file_dest,
    wildcard_one_file_dest,
    numeric_chown,
    named_chown,
    named_image_account,
    chown_absent_passwd,
    chown_absent_passwd_materialized,
    chown_absent_group_scratch,
    literal_missing,
    chown_absent_group,
    chown_unknown_user,
    chown_unknown_group,
    chmod_octal_arg,
    chmod_invalid,
    multistage_owner_default,
    directory_metadata
);

#[test]
fn inherited_shell_from_literal_local_layout() {
    let mut case = oracle("shell_inherited");
    case["dockerfile"] =
        json!("ARG BASE=bad@@\nFROM $BASE\nENTRYPOINT echo child\nCMD echo child-arg\n");
    case["args"] = json!(["BASE=local"]);
    let f = Fixture::new(&case);
    let root = f.temp.path().join("base-root");
    let base = f.temp.path().join("base");
    fs::create_dir(&root).unwrap();
    rpweld::export::export_layout(
        &root,
        &base,
        &json!({"os":"linux", "architecture":"amd64", "config": {
            "Shell":["/custom", "-c"], "Cmd":["/custom", "-c", "echo parent"]
        }}),
        rpweld::export::Limits {
            max_layer_bytes: 16 << 20,
            max_entries: 1000,
            max_metadata_bytes: 1 << 20,
        },
        || false,
    )
    .unwrap();
    let binding = format!("local={}", base.display());
    let (result, output) = f.build(&case, &["--base", &binding], false);
    check(&case, &result, &output);
}

#[test]
fn chmod_owned_file_without_cap_chown() {
    let case = oracle("chmod_octal_arg");
    let f = Fixture::new(&case);
    let (result, output) = f.build(&case, &[], true);
    check(&case, &result, &output);
}

#[test]
fn arbitrary_chown_without_cap_chown_fails_without_export() {
    let case = oracle("numeric_chown");
    let f = Fixture::new(&case);
    let (result, output) = f.build(&case, &[], true);
    assert!(
        !result.status.success(),
        "arbitrary chown silently succeeded without CAP_CHOWN"
    );
    assert!(
        !output.exists(),
        "failed ownership change exported a false-success image"
    );
    let error = String::from_utf8_lossy(&result.stderr).to_lowercase();
    assert!(
        error.contains("chown") || error.contains("ownership"),
        "missing operation: {error}"
    );
    assert!(
        error.contains("permitted") || error.contains("permission") || error.contains("cap_chown"),
        "missing permission failure: {error}"
    );
}
