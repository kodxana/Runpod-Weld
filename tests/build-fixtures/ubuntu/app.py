import json
import os
import pathlib
import subprocess
import sys

result = {
    "marker": os.environ["WELD_TEST"],
    "cwd": os.getcwd(),
    "venv": sys.prefix,
    "python": sys.version.split()[0],
    "hello": subprocess.check_output(["/usr/bin/hello"], text=True).strip(),
    "payload": pathlib.Path(__file__).name,
}
assert result["marker"] == "ubuntu24-fd1024"
assert result["cwd"] == "/app"
assert result["venv"] == "/opt/venv"
assert result["hello"] == "Hello, world!"
print(json.dumps(result, sort_keys=True), flush=True)
