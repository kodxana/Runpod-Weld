#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture {
    temp: tempfile::TempDir,
    context: PathBuf,
    count: usize,
}
impl Fixture {
    fn new(source: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let context = temp.path().join("context");
        fs::create_dir(&context).unwrap();
        fs::write(context.join("Dockerfile"), source).unwrap();
        Self {
            temp,
            context,
            count: 0,
        }
    }
    fn build(&mut self, extra: &[&str]) -> (Output, PathBuf, PathBuf) {
        self.count += 1;
        let output = self.temp.path().join(format!("output-{}", self.count));
        let work = self.temp.path().join(format!("work-{}", self.count));
        let result = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .env("HOME", self.temp.path())
            .env("RPWELD_HOME", self.temp.path().join("store"))
            .args(["build", "--output"])
            .arg(&output)
            .arg("--work-dir")
            .arg(&work)
            .args(extra)
            .arg(&self.context)
            .output()
            .unwrap();
        (result, output, work.join("rootfs"))
    }
}
fn success(result: &Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
fn config(layout: &Path) -> Value {
    let read = |p| serde_json::from_slice::<Value>(&fs::read(p).unwrap()).unwrap();
    let index = read(layout.join("index.json"));
    let blob = |digest: &str| layout.join("blobs").join(digest.replace(':', "/"));
    let manifest = read(blob(index["manifests"][0]["digest"].as_str().unwrap()));
    read(blob(manifest["config"]["digest"].as_str().unwrap()))["config"].clone()
}

#[test]
fn independent_docker_config_oracle() {
    let oracle: Value =
        serde_json::from_str(include_str!("fixtures/runtime-metadata/docker-oracle.json")).unwrap();
    for case in oracle["cases"].as_array().unwrap() {
        let mut f = Fixture::new(case["dockerfile"].as_str().unwrap());
        let (r, out, root) = f.build(&[]);
        if case["success"] == false || case["name"] == "flags_none_divergence" {
            assert!(!r.status.success(), "{}", case["name"]);
            assert!(!out.exists());
            assert!(!root.exists());
        } else {
            success(&r);
            let cfg = config(&out);
            for key in ["StopSignal", "Healthcheck", "Shell"] {
                assert_eq!(cfg[key], case["config"][key], "{} {key}", case["name"]);
            }
            assert_eq!(
                cfg["User"].as_str().unwrap_or(""),
                case["config"]["User"].as_str().unwrap_or("")
            );
            // None of the recorded commands/executables exist in scratch.
            assert!(fs::read_dir(&root).unwrap().next().is_none());
        }
    }
}

#[test]
fn local_base_inherits_then_replaces_healthcheck() {
    let mut f = Fixture::new(
        "FROM scratch\nUSER missing\nSTOPSIGNAL SIGUSR1\nHEALTHCHECK --interval=2s --timeout=9s --retries=8 CMD nonexistent\n",
    );
    let (r, base, _) = f.build(&[]);
    success(&r);
    let binding = format!("local={}", base.display());
    for (source, health) in [
        (
            "FROM local\nLABEL child=yes\n",
            json!({"Test":["CMD-SHELL","nonexistent"],"Interval":2000000000i64,"Timeout":9000000000i64,"Retries":8}),
        ),
        ("FROM local\nHEALTHCHECK NONE\n", json!({"Test":["NONE"]})),
        (
            "FROM local\nHEALTHCHECK CMD new\n",
            json!({"Test":["CMD-SHELL","new"]}),
        ),
    ] {
        fs::write(f.context.join("Dockerfile"), source).unwrap();
        let (r, out, _) = f.build(&["--base", &binding]);
        success(&r);
        let cfg = config(&out);
        assert_eq!(cfg["User"], "missing");
        assert_eq!(cfg["StopSignal"], "SIGUSR1");
        assert_eq!(cfg["Healthcheck"], health);
    }
}

#[test]
fn metadata_only_cache_hits_keep_final_config_and_invalidate_on_changes() {
    use std::time::{Duration, UNIX_EPOCH};
    let mut f = Fixture::new(
        "FROM scratch\nARG SIGNAL=SIGTERM\nSTOPSIGNAL $SIGNAL\nHEALTHCHECK --interval=2s CMD missing\n",
    );
    let future = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    for name in ["", "Dockerfile"] {
        fs::File::open(f.context.join(name))
            .unwrap()
            .set_times(fs::FileTimes::new().set_accessed(future))
            .unwrap();
    }
    let (r, first, _) = f.build(&["-t", "test/runtime-metadata:latest"]);
    success(&r);
    let (r, cached, _) = f.build(&["-t", "test/runtime-metadata:latest"]);
    success(&r);
    assert!(String::from_utf8_lossy(&r.stderr).contains("CACHED ("));
    assert_eq!(config(&first), config(&cached));
    let (r, changed, _) = f.build(&[
        "-t",
        "test/runtime-metadata:latest",
        "--build-arg",
        "SIGNAL=SIGQUIT",
    ]);
    success(&r);
    assert_eq!(config(&changed)["StopSignal"], "SIGQUIT");
    assert_eq!(
        config(&changed)["Healthcheck"],
        config(&first)["Healthcheck"]
    );
    fs::write(
        f.context.join("Dockerfile"),
        "FROM scratch\nSTOPSIGNAL SIGQUIT\nHEALTHCHECK NONE\n",
    )
    .unwrap();
    let (r, changed, _) = f.build(&["-t", "test/runtime-metadata:latest"]);
    success(&r);
    assert_eq!(config(&changed)["Healthcheck"], json!({"Test":["NONE"]}));
}

#[test]
fn expanded_invalid_signal_reports_line_and_leaves_no_output() {
    let mut f = Fixture::new("FROM scratch\nARG SIGNAL=0\nSTOPSIGNAL $SIGNAL\n");
    let (r, out, root) = f.build(&[]);
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("line 3"));
    assert!(!out.exists());
    assert!(!root.exists());
}

#[test]
fn metadata_at_copy_boundary_and_final_tail_survive_cache() {
    use std::time::{Duration, UNIX_EPOCH};
    let mut f = Fixture::new(
        "FROM scratch\nARG S=SIGTERM\nSTOPSIGNAL $S\nHEALTHCHECK CMD before\nCOPY payload /payload\nHEALTHCHECK NONE\n",
    );
    fs::write(f.context.join("payload"), "data").unwrap();
    let future = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    for name in ["", "Dockerfile", "payload"] {
        fs::File::open(f.context.join(name))
            .unwrap()
            .set_times(fs::FileTimes::new().set_accessed(future))
            .unwrap();
    }
    for signal in ["SIGTERM", "SIGTERM", "SIGQUIT"] {
        let arg = format!("S={signal}");
        let (r, out, root) = f.build(&["-t", "test/runtime-copy:latest", "--build-arg", &arg]);
        success(&r);
        assert_eq!(config(&out)["StopSignal"], signal);
        assert_eq!(config(&out)["Healthcheck"], json!({"Test":["NONE"]}));
        assert_eq!(fs::read(root.join("payload")).unwrap(), b"data");
    }
    fs::write(f.context.join("Dockerfile"), "FROM scratch\nARG S=SIGTERM\nSTOPSIGNAL $S\nHEALTHCHECK CMD before\nCOPY payload /payload\nHEALTHCHECK CMD after\n").unwrap();
    let (r, out, _) = f.build(&["-t", "test/runtime-copy:latest", "--build-arg", "S=SIGQUIT"]);
    success(&r);
    assert!(String::from_utf8_lossy(&r.stderr).contains("CACHED instruction 5 COPY"));
    assert_eq!(
        config(&out)["Healthcheck"],
        json!({"Test":["CMD-SHELL","after"]})
    );
}
