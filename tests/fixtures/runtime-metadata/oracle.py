"""Independent local Docker/BuildKit config oracle. No pulls, RUNs or publication."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
CASES = {
    "scratch": "FROM scratch\nSTOPSIGNAL sigusr1\nHEALTHCHECK --interval=1h2m3.004s --timeout=1.5ms --start-period=5s --start-interval=2s --retries=3 CMD echo $X || exit 1\n",
    "inherit": 'FROM scratch AS base\nUSER missing\nSTOPSIGNAL SIGQUIT\nHEALTHCHECK --timeout=9s CMD ["missing", "$X"]\nFROM base\nLABEL child=yes\n',
    "reset": 'FROM scratch AS base\nSTOPSIGNAL SIGQUIT\nHEALTHCHECK --timeout=9s --retries=9 CMD old\nFROM base\nSTOPSIGNAL +15\nHEALTHCHECK CMD ["new", "$X"]\n',
    "none": "FROM scratch AS base\nHEALTHCHECK --timeout=9s CMD old\nFROM base\nHEALTHCHECK NONE\n",
    "reenable": "FROM scratch\nHEALTHCHECK NONE\nHEALTHCHECK CMD new\n",
    "shell": 'FROM scratch\nSHELL ["/custom", "-c"]\nENV X=value\nHEALTHCHECK CMD echo "$X"\nSHELL ["/later", "-c"]\n',
    "expansion": 'FROM scratch\nARG S=SIGUSR1\nSTOPSIGNAL "$S"\nENV S=SIGUSR2\nSTOPSIGNAL ${S}\n',
    "zero": "FROM scratch\nHEALTHCHECK --interval=0 --timeout=0s --start-period= --start-interval=0 --retries=0 CMD true\n",
    "max": "FROM scratch\nSTOPSIGNAL 9223372036854775807\nHEALTHCHECK --interval=9223372036854775807ns --retries=2147483647 CMD true\n",
    "bad_duration": "FROM scratch\nHEALTHCHECK --interval=9223372036854775808ns CMD true\n",
    "bad_retries": "FROM scratch\nHEALTHCHECK --retries=2147483648 CMD true\n",
    "duplicate_flag": "FROM scratch\nHEALTHCHECK --timeout=1s --timeout=2s CMD true\n",
    "bad_signal": "FROM scratch\nSTOPSIGNAL SIGBOGUS\n",
    "flags_none_divergence": "FROM scratch\nHEALTHCHECK --ignored=anything NONE\n",
}


def main():
    report = {"engine": subprocess.check_output(["docker", "version", "--format", "{{.Server.Version}}"], text=True).strip(), "cases": []}
    with tempfile.TemporaryDirectory(prefix="weld-health-oracle-") as tmp:
        env = dict(os.environ, DOCKER_CONFIG=str(Path(tmp) / "docker-config"), DOCKER_BUILDKIT="1")
        for name, source in CASES.items():
            context = Path(tmp) / name
            context.mkdir()
            (context / "Dockerfile").write_text(source)
            tag = "weld-health-oracle:" + uuid.uuid4().hex
            try:
                result = subprocess.run(["docker", "build", "--pull=false", "--network=none", "-t", tag, str(context)], env=env, capture_output=True, text=True, timeout=120)
                entry = {"name": name, "dockerfile": source, "success": result.returncode == 0}
                if result.returncode == 0:
                    cfg = json.loads(subprocess.check_output(["docker", "image", "inspect", tag], env=env, text=True))[0]["Config"]
                    entry["config"] = {k: cfg[k] for k in ["StopSignal", "Healthcheck", "User", "Shell"] if k in cfg}
                else:
                    entry["error"] = result.stderr[-2000:]
                report["cases"].append(entry)
            finally:
                subprocess.run(["docker", "image", "rm", "-f", tag], env=env, capture_output=True)
    (HERE / "docker-oracle.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Docker {report['engine']}: recorded {len(report['cases'])} cases")


if __name__ == "__main__":
    main()
