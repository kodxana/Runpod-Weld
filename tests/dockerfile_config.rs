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
fn global_from_overrides_select_dependencies_without_pulling_unused_bases() {
    let mut f = Fixture::new(
        "ARG BASE=nonexistent.invalid/not-pulled\nARG PICK=seed\nARG GLOBAL=global\nFROM scratch AS seed\nARG LOCAL=inherited\nLABEL origin=seed\nFROM nonexistent.invalid/unused AS unused\nRUN false\nFROM $BASE AS final\nLABEL hidden=$GLOBAL inherited=$LOCAL\nARG GLOBAL\nLABEL visible=$GLOBAL\n",
    );
    let (r, out, _) = f.build(&["--build-arg", "BASE=seed"]);
    success(&r);
    assert_eq!(
        config(&out)["Labels"],
        json!({"origin":"seed", "hidden":"", "inherited":"inherited", "visible":"global"})
    );
    assert!(!String::from_utf8_lossy(&r.stdout).contains("Pulling"));
    let (r, out, _) = f.build(&["--build-arg", "BASE=scratch"]);
    success(&r);
    assert_eq!(
        config(&out)["Labels"],
        json!({"hidden":"", "inherited":"", "visible":"global"})
    );
}

#[test]
fn shell_config_is_inherited_and_commands_capture_shell_at_declaration() {
    let mut f = Fixture::new(
        "FROM scratch AS base\nSHELL [\"/custom\",\"--flag\",\"-c\"]\nENV VALUE=build\nLABEL org.example.note=\"a $VALUE\" literal='$VALUE'\nCMD echo $VALUE\nFROM base\nENTRYPOINT echo 'entry' $VALUE\nSHELL [\"/later\",\"-c\"]\n",
    );
    let (r, out, _) = f.build(&[]);
    success(&r);
    let cfg = config(&out);
    assert_eq!(
        cfg["Entrypoint"],
        json!(["/custom", "--flag", "-c", "echo 'entry' $VALUE"])
    );
    assert!(cfg["Cmd"].is_null());
    assert_eq!(cfg["Shell"], json!(["/later", "-c"]));
    assert_eq!(
        cfg["Labels"],
        json!({"org.example.note":"a build", "literal":"$VALUE"})
    );
    let (r, out, _) = f.build(&["--target", "base"]);
    success(&r);
    assert_eq!(
        config(&out)["Cmd"],
        json!(["/custom", "--flag", "-c", "echo $VALUE"])
    );
}

#[test]
fn local_base_shell_labels_and_expanded_binding_are_used() {
    let mut f = Fixture::new(
        "FROM scratch\nSHELL [\"/base-shell\",\"-c\"]\nLABEL inherited=yes overridden=old\nCMD [\"inherited\"]\n",
    );
    let (r, base, _) = f.build(&[]);
    success(&r);
    fs::write(f.context.join("Dockerfile"), "ARG IMAGE=wrong\nFROM ${IMAGE}\nARG V=new\nLABEL overridden=$V\nCMD echo $V\nENTRYPOINT [\"literal\",\"$V\"]\n").unwrap();
    let binding = format!("local={}", base.display());
    let (r, out, _) = f.build(&["--base", &binding, "--build-arg", "IMAGE=local"]);
    success(&r);
    let cfg = config(&out);
    assert_eq!(cfg["Cmd"], json!(["/base-shell", "-c", "echo $V"]));
    assert_eq!(cfg["Entrypoint"], json!(["literal", "$V"]));
    assert_eq!(
        cfg["Labels"],
        json!({"inherited":"yes", "overridden":"new"})
    );
}

#[test]
fn arg_redeclaration_globals_defaults_and_env_shadowing() {
    let mut f = Fixture::new(
        "ARG A=global\nFROM scratch AS seed\nARG A=stage\nARG B=parent\nFROM seed\nLABEL before=$A\nARG A\nARG B\nLABEL after=$A parent=$B\nARG A=local\nENV A=environment\nARG A=other\nLABEL shadowed=$A\n",
    );
    let (r, out, _) = f.build(&[]);
    success(&r);
    assert_eq!(
        config(&out)["Labels"],
        json!({"before":"stage", "after":"global", "parent":"parent", "shadowed":"environment"})
    );
}

#[test]
fn flags_expand_and_stage_copy_preserves_applied_modes() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new(
        "FROM scratch AS seed\nARG MODE=640\nCOPY --chmod=$MODE --chown=0:0 *.txt /out/\nFROM scratch\nCOPY --chmod=0600 --from=seed /out/*.txt /final/\n",
    );
    fs::write(f.context.join("one.txt"), "one").unwrap();
    fs::write(f.context.join("two.txt"), "two").unwrap();
    let (r, _, root) = f.build(&[]);
    success(&r);
    for name in ["one.txt", "two.txt"] {
        assert_eq!(
            fs::metadata(root.join("final").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

#[test]
fn copy_flag_arguments_invalidate_stage_cache() {
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        time::{Duration, UNIX_EPOCH},
    };
    let mut f = Fixture::new(
        "FROM scratch\nARG MODE=640\nARG OWNER=0:0\nCOPY --chmod=$MODE --chown=$OWNER *.txt /out/\n",
    );
    fs::write(f.context.join("one.txt"), "one").unwrap();
    // Keep source atime stable across the cache fingerprint and COPY reads.
    let future = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    for name in ["", "Dockerfile", "one.txt"] {
        fs::File::open(f.context.join(name))
            .unwrap()
            .set_times(fs::FileTimes::new().set_accessed(future))
            .unwrap();
    }
    let (r, _, _) = f.build(&["-t", "test/config:latest"]);
    success(&r);
    let (r, _, _) = f.build(&["-t", "test/config:latest"]);
    success(&r);
    assert!(String::from_utf8_lossy(&r.stderr).contains("CACHED ("));
    let (r, _, root) = f.build(&[
        "-t",
        "test/config:latest",
        "--build-arg",
        "MODE=600",
        "--build-arg",
        "OWNER=1:2",
    ]);
    success(&r);
    assert!(!String::from_utf8_lossy(&r.stderr).contains("CACHED ("));
    let meta = fs::metadata(root.join("out/one.txt")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    assert_eq!((meta.uid(), meta.gid()), (1, 2));
}

#[test]
fn invalid_references_and_flags_fail_before_output_mutation() {
    for source in [
        "ARG BASE\nFROM $BASE\n",
        "ARG BASE=bad\nFROM ${BASE:-scratch}\n",
        "ARG BASE=next\nFROM $BASE\nFROM scratch AS next\n",
        "FROM scratch\nCOPY --from=$BASE a /a\n",
        "FROM scratch\nCOPY --chmod=888 a /a\n",
        "FROM scratch\nCOPY --chown=a:b:c a /a\n",
        "FROM scratch\nSHELL []\n",
        "FROM scratch\nSHELL [\"\"]\n",
    ] {
        let mut f = Fixture::new(source);
        fs::write(f.context.join("a"), "data").unwrap();
        let (r, out, root) = f.build(&[]);
        assert!(!r.status.success(), "accepted {source}");
        assert!(!out.exists());
        assert!(!root.exists());
    }
}

#[test]
fn reference_resolution_is_bounded_literal_and_cli_override_aware() {
    use rpweld::{
        build::{resolve_plan, selected_stages},
        build_plan::Base,
    };
    use std::collections::BTreeMap;
    let source = "ARG REG=registry.example\nARG TAG=one\nFROM $REG/team/image:${TAG}\n";
    let args = BTreeMap::from([("TAG".into(), "two".into())]);
    assert_eq!(
        resolve_plan(source, &args, 4096).unwrap().stages[0].base,
        Base::Image("registry.example/team/image:two".into())
    );
    for value in [
        "",
        "$(touch /tmp/no)",
        "scratch;false",
        "scratch\nRUN false",
        "../scratch",
        "https://example/a",
    ] {
        let args = BTreeMap::from([("BASE".into(), value.into())]);
        assert!(
            resolve_plan("ARG BASE\nFROM $BASE", &args, 4096).is_err(),
            "accepted {value:?}"
        );
    }
    let plan = resolve_plan(
        "ARG BASE=seed\nFROM scratch AS seed\nFROM unused AS skipped\nFROM $BASE",
        &BTreeMap::new(),
        4096,
    )
    .unwrap();
    assert_eq!(selected_stages(&plan, None).unwrap(), vec![0, 2]);
    assert!(resolve_plan(source, &args, 2).is_err());
}

#[test]
#[ignore = "requires root and RPWELD_TEST_LAYOUT with /bin/sh; offline local fixture only"]
fn custom_shell_run_exec_independence_and_stage_inheritance() {
    let layout = std::env::var("RPWELD_TEST_LAYOUT").expect("set local OCI fixture path");
    let binding = format!("local={layout}");
    let mut f = Fixture::new(
        "FROM local AS base\nSHELL [\"/bin/sh\",\"-eu\",\"-c\"]\nFROM base\nARG VALUE=literal\nRUN printf '%s' \"$VALUE\" > /result\nRUN [\"/bin/sh\",\"-c\",\"false; printf exec > /exec\"]\n",
    );
    let (r, _, root) = f.build(&["--base", &binding]);
    success(&r);
    assert_eq!(fs::read(root.join("result")).unwrap(), b"literal");
    assert_eq!(fs::read(root.join("exec")).unwrap(), b"exec");
    fs::write(
        f.context.join("Dockerfile"),
        "FROM local\nSHELL [\"/bin/sh\",\"-e\",\"-c\"]\nRUN false; printf wrong > /wrong\n",
    )
    .unwrap();
    let (r, out, root) = f.build(&["--base", &binding]);
    assert!(!r.status.success());
    assert!(!out.join("index.json").exists());
    assert!(!root.join("wrong").exists());
}
