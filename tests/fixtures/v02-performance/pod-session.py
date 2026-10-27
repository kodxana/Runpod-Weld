#!/usr/bin/env python3
"""External, bounded controller: run upload/experiment/collection, then delete our Pod.

Never creates resources. Start immediately after the parent's authorized MCP create.
The receipt must be written from that create result, never from a discovered Pod.
Requires an authenticated runpodctl (tested help: 2.9.0-c094cac) outside the Pod.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def call(cli, arguments):
    # Do not persist pod-get/list bodies: they can contain environment secrets.
    try:
        result = subprocess.run([cli, *arguments], capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "code": "timeout"}, None
    try:
        data = json.loads(result.stdout if result.returncode == 0 else result.stderr)
    except json.JSONDecodeError:
        data = None
    record = {"returncode": result.returncode, "code": data.get("code") if isinstance(data, dict) else None}
    return record, data


def cleanup(cli, pod_id, evidence):
    attempts = []
    for attempt in range(3):
        deleted, _ = call(cli, ["pod", "delete", pod_id])
        fetched, _ = call(cli, ["pod", "get", pod_id])
        listed, data = call(cli, ["pod", "list", "--all"])
        pods = data if isinstance(data, list) else data.get("pods") if isinstance(data, dict) else None
        absent = isinstance(pods, list) and all(p.get("id") != pod_id for p in pods)
        verified = fetched["returncode"] != 0 and fetched["code"] == "not_found" and listed["returncode"] == 0 and absent
        attempts.append({"delete": deleted, "get": fetched, "list": listed, "absent": verified})
        (evidence / "teardown.json").write_text(json.dumps({"pod_id": pod_id, "attempts": attempts,
            "verified_absent": verified, "at": datetime.now(timezone.utc).isoformat()}, indent=2) + "\n")
        if verified:
            return
        if any(r["code"] in ("unauthorized", "forbidden", "no_credentials", "usage_error") for r in (deleted, fetched, listed)):
            break
        if attempt < 2:
            time.sleep(3 * (attempt+1))
    raise RuntimeError(f"Pod {pod_id} deletion NOT verified; parent must use MCP delete/get/list immediately")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--deadline-utc", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--cli", default="runpodctl")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text())
    assert receipt["created_by_this_task"] is True and receipt["source"] == "create-pod"
    pod_id = receipt["id"]
    assert pod_id and pod_id.isascii() and pod_id.isalnum()
    created = datetime.fromisoformat(receipt["created_at"].replace("Z", "+00:00"))
    deadline = datetime.fromisoformat(args.deadline_utc.replace("Z", "+00:00"))
    assert 0 < (deadline-created).total_seconds() <= 5400, "maximum lease: 90 minutes from creation"
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    assert command
    args.evidence.mkdir(parents=True, exist_ok=True)
    process = None
    def interrupted(*_):
        raise InterruptedError("controller interrupted; deleting temporary Pod")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        # 3 attempts x 3 API calls x 45 seconds + backoff fit in this reserve.
        remaining = (deadline-datetime.now(timezone.utc)).total_seconds() - 480
        assert remaining > 0, "lease cleanup reserve reached; deleting Pod"
        process = subprocess.Popen(command, start_new_session=True)
        code = process.wait(timeout=remaining)
        if code:
            raise RuntimeError(f"experiment/collection command exited {code}")
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        cleanup(args.cli, pod_id, args.evidence)


if __name__ == "__main__":
    main()
