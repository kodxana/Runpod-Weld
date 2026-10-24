# Ubuntu build smoke fixture

Opt-in Linux amd64/root network test for apt with its normal sandbox, Python
venv creation, local COPY, RUN and exported configuration. Apt repositories are
mutable; this is not a reproducible package baseline. Use a trusted local OCI
Ubuntu 24.04 layout and record its manifest digest with the test results.

From the repository root, with new output/work paths outside the context:

```sh
ulimit -Sn 1024
rpweld build -f tests/build-fixtures/ubuntu/Dockerfile \
  --base ubuntu:24.04=/absolute/path/to/ubuntu-layout \
  --output /absolute/path/to/new-output \
  --work-dir /absolute/path/to/new-work \
  --max-rootfs-bytes 2147483648 --max-layer-bytes 2147483648 \
  --metadata-budget 67108864 --run-timeout-seconds 600 --host-dns \
  tests/build-fixtures/ubuntu
```

The base layout must select one unambiguous image; otherwise add
`--base-ref ubuntu:24.04=REFERENCE`. The existing hard descriptor limit must
permit replay's computed budget. Weld may raise the soft limit automatically.
These budgets do not enforce RUN memory or disk quotas.

Success requires a published OCI index and JSON reporting `Hello, world!`,
`/opt/venv`, and `/app`. Independently unpack and execute the exported CMD with
its configured working directory and environment; verify host resolver data was
not exported. Keep the source SHA, base digest, logs and independent result.
Failure retains partial directories; never reuse them as a successful image.
