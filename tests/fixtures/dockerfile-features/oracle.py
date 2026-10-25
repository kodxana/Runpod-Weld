"""Refresh Docker expectations, never using rpweld. Python stdlib; local daemon only."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
CASES = []


def case(name, dockerfile, *, files=None, args=None, paths=(), absent=(), fail=False):
    CASES.append(dict(name=name, dockerfile=dockerfile, files=files or {},
                      args=args or [], paths=list(paths), absent=list(absent), fail=fail))


case("arg_default", "ARG BASE=scratch\nFROM ${BASE}\nLABEL ok=yes\n")
case("arg_override", "ARG BASE=invalid@@\nFROM $BASE\nARG BASE\nLABEL base=$BASE\n",
     args=["BASE=scratch"])
case("arg_scope", "ARG BASE=scratch\nARG VALUE=global\nFROM $BASE AS parent\nLABEL before=$VALUE\nARG VALUE\nLABEL after=$VALUE\nFROM parent\nLABEL inherited=$VALUE\n")
case("arg_stage_reset", "ARG BASE=scratch\nARG VALUE=global\nFROM $BASE AS first\nARG VALUE=stage\nFROM $BASE\nLABEL before=$VALUE\nARG VALUE\nLABEL after=$VALUE\n")
case("arg_redeclare_override", "ARG BASE=scratch\nARG VALUE=global\nFROM $BASE\nARG VALUE=stage\nLABEL value=$VALUE\n", args=["VALUE=cli"])
case("arg_missing", "ARG BASE\nFROM $BASE\n", fail=True)
case("arg_invalid", "ARG BASE=bad@@\nFROM $BASE\n", fail=True)
case("arg_stage_not_global", "FROM scratch AS first\nARG BASE=scratch\nFROM $BASE\n", fail=True)
case("shell_default", "FROM scratch\nENV X=expanded\nENTRYPOINT echo $X\nCMD echo \"$X\"\n")
case("shell_exec", 'FROM scratch\nENV X=expanded\nSHELL ["/custom", "-c"]\nENTRYPOINT ["echo", "$X"]\nCMD ["echo", "$X"]\n')
case("shell_later", 'FROM scratch\nSHELL ["/first", "-c"]\nENTRYPOINT echo first\nCMD echo earlier\nSHELL ["/later", "-x", "-c"]\n')
case("shell_inherited", 'FROM scratch AS parent\nSHELL ["/custom", "-c"]\nCMD echo parent\nFROM parent\nENTRYPOINT echo child\nCMD echo child-arg\n')
case("entrypoint_resets_cmd", 'FROM scratch AS parent\nCMD ["old"]\nFROM parent\nENTRYPOINT ["new"]\n')
case("label_expansion", 'FROM scratch\nARG X=argument\nLABEL arg="$X" saved="$X" single=\'$X\' literal="\\$X" spaced="two words" equals="a=b"\nENV X=environment\nLABEL env=$X arg="replaced" empty=$UNSET\n')
files = {"a.txt": "A", "b.txt": "B", "nested/c.txt": "C", "nested/deeper/d.txt": "D", "arr[0].txt": "bracket"}
case("wildcard_multiple", "FROM scratch\nCOPY ?.txt /out/\n", files=files,
     paths=["out", "out/a.txt", "out/b.txt"], absent=["out/c.txt", "out/nested"])
case("wildcard_slash", "FROM scratch\nCOPY nested/*.txt /out/\n", files=files,
     paths=["out/c.txt"], absent=["out/a.txt", "out/d.txt", "out/deeper"])
case("wildcard_brackets", "FROM scratch\nCOPY arr[[]0].txt /selected\n", files=files,
     paths=["selected"])
case("wildcard_ignore", "FROM scratch\nCOPY ?.txt /out/\n",
     files={**files, ".dockerignore": "b.txt\n"}, paths=["out/a.txt"], absent=["out/b.txt"])
case("wildcard_missing", "FROM scratch\nCOPY missing* /out/\n", files=files, absent=["out"])
case("wildcard_all_ignored", "FROM scratch\nCOPY ?.txt /out/\n",
     files={**files, ".dockerignore": "*.txt\n"}, absent=["out"])
case("wildcard_multiple_file_dest", "FROM scratch\nCOPY ?.txt /file\n", files=files, paths=["file"])
case("wildcard_one_file_dest", "FROM scratch\nCOPY a.* /renamed\n", files=files, paths=["renamed"])
case("numeric_chown", "FROM scratch\nCOPY --chown=12345:23456 payload /out\nCOPY --chown=34567 payload /single\n",
     files={"payload": "data"}, paths=["out", "single"])
accounts = {"passwd": "root:x:12345:23456::/:/bin/false\n", "group": "root:x:34567:\n", "payload": "data"}
case("named_chown", "FROM scratch\nCOPY passwd /etc/passwd\nCOPY group /etc/group\nCOPY --chown=root:root payload /pair\nCOPY --chown=root payload /single\nCOPY --chown=12345:root payload /mixed\n",
     files=accounts, paths=["pair", "single", "mixed"])
case("named_image_account", "FROM scratch\nCOPY passwd /etc/passwd\nCOPY group /etc/group\nCOPY --chown=nobody:qa payload /pair\nCOPY --chown=nobody payload /single\n",
     files={"passwd": "nobody:x:12345:23456::/:/bin/false\n", "group": "qa:x:34567:\n", "payload": "data"}, paths=["pair", "single"])
case("chown_absent_passwd", "FROM scratch\nCOPY --chown=missing payload /out\n", files={"payload": "data"}, fail=True)
case("chown_absent_passwd_materialized", "FROM scratch\nCOPY payload /seed\nCOPY --chown=missing payload /out\n", files={"payload": "data"}, paths=["out"])
case("chown_absent_group_scratch", "FROM scratch\nCOPY --chown=12345:missing payload /out\n", files={"payload": "data"}, fail=True)
case("literal_missing", "FROM scratch\nCOPY missing /out\n", fail=True)
case("chown_absent_group", "FROM scratch\nCOPY passwd /etc/passwd\nCOPY --chown=root:missing payload /out\n", files=accounts, paths=["out"])
case("chown_unknown_user", "FROM scratch\nCOPY passwd /etc/passwd\nCOPY --chown=missing payload /out\n", files=accounts, paths=["out"])
case("chown_unknown_group", "FROM scratch\nCOPY passwd /etc/passwd\nCOPY group /etc/group\nCOPY --chown=12345:missing payload /out\n", files=accounts, paths=["out"])
case("chmod_octal_arg", "FROM scratch\nARG MODE=0751\nCOPY --chmod=$MODE payload /out\nCOPY --chmod=0640 payload /other\n",
     files={"payload": "data"}, args=["MODE=0705"], paths=["out", "other"])
case("chmod_invalid", "FROM scratch\nCOPY --chmod=0899 payload /out\n", files={"payload": "data"}, fail=True)
case("multistage_owner_default", "FROM scratch AS first\nCOPY --chown=12345:23456 --chmod=0711 payload /owned\nFROM scratch\nCOPY --from=first /owned /copied\nCOPY --from=first --chown=34567:45678 /owned /override\n",
     files={"payload": "data"}, paths=["copied", "override"])
case("directory_metadata", "FROM scratch\nCOPY tree /out/\nCOPY --chmod=0750 --chown=12345:23456 tree /changed/\n",
     files={"tree/nested/file": {"data": "data", "mode": 0o640}, "tree": {"dir": True, "mode": 0o711}, "tree/nested": {"dir": True, "mode": 0o700}},
     paths=["out", "out/nested", "out/nested/file", "changed", "changed/nested", "changed/nested/file"])


def run(*args, check=True, **kw):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=45, env=ENV, **kw)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="rpweld-feature-oracle-") as td:
        temp = Path(td)
        (temp / "docker-config").mkdir()
        ENV = dict(os.environ, DOCKER_CONFIG=str(temp / "docker-config"), DOCKER_BUILDKIT="1")
        version = json.loads(run("docker", "version", "--format", "{{json .}}").stdout)
        report = {"engine": version["Server"]["Version"], "client": version["Client"]["Version"], "cases": []}
        selected = set(sys.argv[1:])
        if selected:
            previous = json.loads((HERE / "docker-oracle.json").read_text())
            assert previous['engine'] == report['engine']
            report['cases'] = [c for c in previous['cases'] if c['name'] not in selected]
        for c in CASES:
            if selected and c['name'] not in selected:
                continue
            context = temp / c["name"]
            context.mkdir()
            for name, spec in c["files"].items():
                p = context / name
                p.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(spec, dict) and spec.get("dir"):
                    p.mkdir(exist_ok=True)
                else:
                    p.write_text(spec["data"] if isinstance(spec, dict) else spec)
            # Apply modes after children have been created, independently of umask.
            for name, spec in c["files"].items():
                p = context / name
                p.chmod(spec.get("mode", 0o644) if isinstance(spec, dict) else 0o644)
            (context / "Dockerfile").write_text(c["dockerfile"])
            tag = "rpweld-feature-oracle:" + uuid.uuid4().hex
            cid = None
            try:
                args = ["docker", "build", "--pull=false", "--network=none", "--no-cache", "-t", tag]
                for arg in c["args"]:
                    args.extend(["--build-arg", arg])
                result = run(*args, str(context), check=False)
                observed = dict(c)
                observed["success"] = result.returncode == 0
                observed["diagnostic"] = result.stderr.decode(errors="replace")[-1600:] if result.returncode else ""
                if result.returncode == 0:
                    config = json.loads(run("docker", "image", "inspect", tag).stdout)[0]["Config"]
                    observed["config"] = {k: config.get(k) for k in ["Cmd", "Entrypoint", "Shell", "Labels"]}
                    cid = run("docker", "create", "--entrypoint", "/never-run", tag).stdout.decode().strip()
                    archive = run("docker", "export", cid).stdout
                    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                        members = {m.name.rstrip("/"): m for m in tar.getmembers()}
                        observed["entries"] = {}
                        for path in c["paths"]:
                            m = members[path]
                            entry = dict(mode=m.mode, uid=m.uid, gid=m.gid, dir=m.isdir())
                            if m.isfile():
                                entry["data"] = tar.extractfile(m).read().decode()
                            observed["entries"][path] = entry
                        for path in c["absent"]:
                            assert path not in members, (c["name"], path)
                report["cases"].append(observed)
                print(c["name"], "OK" if observed["success"] else "FAIL", flush=True)
            finally:
                if cid:
                    run("docker", "rm", cid, check=False)
                run("docker", "image", "rm", tag, check=False)
        (HERE / "docker-oracle.json").write_text(json.dumps(report, indent=2) + "\n")
        surprises = [c["name"] for c in report["cases"] if c["success"] == c["fail"]]
        print("Unexpected status (review before changing tests):", surprises)
