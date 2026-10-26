#!/usr/bin/env python3
"""List distribution packages whose current files enter the release (build host only)."""
from pathlib import Path
import runpy

helpers = runpy.run_path(str(Path(__file__).with_name('package-linux.py')))
paths = helpers['dependencies'](Path('/usr/bin/skopeo'))
paths += [Path('/usr/lib/x86_64-linux-gnu/libc.a'), Path(helpers['run']('cc', '-print-libgcc-file-name'))]
print(' '.join(sorted({'ca-certificates', *(helpers['package_owner'](path) for path in paths)})))
