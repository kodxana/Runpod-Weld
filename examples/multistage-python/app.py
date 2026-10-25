import json
import os
import subprocess
import sys

print(json.dumps({
    "cwd": os.getcwd(),
    "hello": subprocess.check_output(["hello"], text=True).strip(),
    "marker": os.getenv("WELD_TEST"),
    "python": sys.version.split()[0],
    "venv": sys.prefix,
}))
