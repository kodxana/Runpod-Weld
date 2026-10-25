"""Bounded local scratch builds; compare payload bytes and types, no RUN/pulls."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=60, **kwargs)


for args in [['docker', 'version'], ['docker', 'buildx', 'version'],
             ['docker', 'buildx', 'inspect']]:
    result = command(args)
    result.check_returncode()
    print(result.stdout, flush=True)
cases = json.loads(Path(__file__).with_name('patterns.json').read_text())
checks = []


def build(label, policy, paths, recipe='Dockerfile', specific=None, expected_dirs=None,
          source='FROM scratch\nCOPY . /out/\n', fifo=False, failure=False):
    with tempfile.TemporaryDirectory(prefix='dockerignore-oracle-') as temp:
        base = Path(temp)
        context = base / 'context'
        context.mkdir()
        output = base / 'output'
        dockerfile = context / recipe
        dockerfile.parent.mkdir(parents=True, exist_ok=True)
        dockerfile.write_text(source)
        (context / '.dockerignore').write_text(policy)
        if specific is not None:
            Path(str(dockerfile) + '.dockerignore').write_text(specific)
        for name, _ in paths:
            path = context / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        if fifo:
            os.mkfifo(context / 'blocked')
        result = command([
            'docker', 'build', '--network=none', '--progress=plain',
            '-f', os.path.relpath(dockerfile, base),
            '--output', f'type=local,dest={output}', 'context',
        ], cwd=base)
        if failure:
            assert result.returncode != 0, label
            assert not output.exists(), label
            assert 'not found' in result.stderr, result.stderr
            print(f'PASS {label}: missing source rejected; no exported filesystem', flush=True)
            checks.append(label)
            return
        assert result.returncode == 0, result.stderr
        root = output / 'out'
        controls = {'Dockerfile', '.dockerignore', recipe, recipe + '.dockerignore'}
        actual = {}
        directories = []
        for path in sorted(root.rglob('*')):
            name = path.relative_to(root).as_posix()
            if path.is_dir():
                directories.append(name)
            elif name not in controls:
                assert path.is_file() and not path.is_symlink(), name
                actual[name] = path.read_bytes()
        expected = {name: name.encode() for name, excluded in paths if not excluded}
        assert actual == expected, (label, actual, expected)
        if expected_dirs is not None:
            assert directories == expected_dirs, (label, directories, expected_dirs)
        if label == 'excluded-controls':
            assert not (root / 'Dockerfile').exists()
            assert not (root / '.dockerignore').exists()
        print(f'PASS {label}: bytes={sorted(actual)} directories={directories}', flush=True)
        checks.append(label)


for index, case in enumerate(cases):
    build(f'patterns-{index + 1}', case['policy'], case['paths'], expected_dirs=case['directories'])
for recipe in ['Dockerfile', 'recipes/custom.Dockerfile', '../recipes/custom.Dockerfile']:
    for specific in ['', 'target\n']:
        build(f'override:{recipe}:{specific!r}', 'root-only\n',
              [('root-only', False), ('target', bool(specific)),
               ('recipes/target', False)], recipe=recipe, specific=specific)
build('excluded-controls', 'Dockerfile\n.dockerignore\nsecret\n',
      [('good', False), ('secret', True)])
build('ignored-fifo', 'blocked\n', [('good', False)], fifo=True)
for name in ['secret', 'excluded/child']:
    build(f'explicit:{name}', 'secret\nexcluded\n',
          [('good', False), (name, True)],
          source=f'FROM scratch\nCOPY good /first\nCOPY {name} /second\n', failure=True)
print(f'Docker/BuildKit: {len(checks)} scratch filesystem checks passed')
