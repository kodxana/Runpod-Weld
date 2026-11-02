# Real Nemotron image acceptance

`oracle.py` is the read-only, bounded validator used by the sealed real-workload
runner. It streams layer contents without extracting them, checks blob hashes
and diff IDs, compares the pinned model/application contents and configuration,
and checks cache retention and public-output inode isolation across phases.

The three reference inputs named and SHA-256-pinned in `REFERENCE_HASHES` must be
supplied under `reference/` by the separately sealed runner. They are the original
Nemotron source archive, asset lock and historical independent image receipt.
This program has no reference override or skip-verification mode.

The October 28 trial completed its build but stopped at the validator's blanket
backslash rejection. Linux image layer names use `/` as their separator; a
literal backslash in a systemd filename is ordinary filename data. The layer
scanner now selects POSIX string validation. Source archive paths retain the
portable backslash restriction because they are also used as host paths.
Absolute names, NUL, `/..` traversal and existing byte limits remain rejected.

Run the small raw/gzip regression fixtures without reference files:

```sh
python3 -B -m unittest discover -s tests/fixtures/nemotron -p test_paths.py
```

These fixtures are not a substitute for full-image cold/warm/edit acceptance.
Historical bundles and results remain unchanged.
