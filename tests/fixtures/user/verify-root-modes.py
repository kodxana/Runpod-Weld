#!/usr/bin/env python3
"""Independent OCI root header inspection; Python stdlib only."""
import json
from pathlib import Path
import sys
import tarfile


def root_modes(layout):
    def blob(digest):
        return layout / 'blobs' / digest.replace(':', '/')
    index = json.loads((layout / 'index.json').read_text())
    manifest = json.loads(blob(index['manifests'][0]['digest']).read_text())
    modes = []
    for layer in manifest['layers']:
        with tarfile.open(blob(layer['digest']), 'r:*') as archive:
            for entry in archive:
                if entry.isdir() and entry.name.strip('/') in ('', '.'):
                    modes.append(entry.mode & 0o7777)
    return modes


if __name__ == '__main__':
    base, destination = map(Path, sys.argv[1:])
    assert root_modes(base) == [], 'regression base must omit the root directory header'
    layouts = sorted(destination.glob('mask-*/output-*'))
    checkpoints = [p for p in destination.glob('mask-*/store/cache-v2/entries/*') if (p / 'index.json').is_file()]
    assert checkpoints, 'managed builds must publish real OCI cache checkpoints'
    layouts += sorted(checkpoints)
    checked = 0
    for layout in layouts:
        if (layout / 'index.json').is_file():
            modes = root_modes(layout)
            assert modes and modes[-1] == 0o755, (str(layout), modes)
            checked += 1
    assert checked >= 6, checked
    print(json.dumps({'checked_export_and_cache_layouts': checked, 'cache_checkpoints': len(checkpoints), 'root_mode': '0755', 'base_root_header': 'absent'}))
