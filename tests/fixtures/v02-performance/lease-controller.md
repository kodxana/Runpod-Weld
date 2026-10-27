# Sealed xattr comparison: independent local supervision

`lease-controller.py` runs one fresh, authorized experiment using the existing
sealed `d6fe610` / `e41a8ea` payload. It starts the sealed remote supervisor once,
then observes status and requests one sealed `pulse.py` invocation every 20
seconds. It runs as a local Python process, independently of LLM/tool-call
cadence. It does not create or delete cloud resources, collect evidence, retry a
failed experiment, or modify/reseal the payload. It replaces the manual pulse/run
steps in that payload's `HANDOFF.md`; the other preflight/acceptance/collection
steps still apply. The older general-purpose `pod-session.py` is not this helper.

The previous partial trial remains immutable. A new trial needs a separate local
directory, newly created Pod, exact fresh receipt, reviewed GO with a new public
nonce, and a new remote `/var/tmp/weld-xattr-*` session. Do not resume the old trial
or combine its samples with the new four-build comparison.

## Parent handoff and launch

1. Run the local control tests before creation. No builder is executed:

   ```powershell
   python -B -m unittest discover -s tests/fixtures/v02-performance -p test_lease_controller.py -v
   ```

2. Parent owns create/read-back/delete through the same Runpod MCP and keeps an
   independent deadline reminder. Use the sealed receipt/GO schema unchanged:
   8 vCPU, 32 GiB, 80 GB ephemeral disk, verified local backing, same CPU class;
   start within 20 minutes of creation; deletion verified by T0+60 minutes.
   Begin deletion no later than T0+55 minutes even if evidence collection fails.
   `independent_cleanup_armed` means the parent actually armed its backup, not
   that this Python helper guarantees cloud deletion.

3. Verify/upload the byte-identical original archive and extract/preflight using
   the existing preparation recipe. Keep `SEALED-READY.json` locally. Upload the
   exact bytes of the **new** `created-pod.json` and `GO.json` into the new remote
   session. Keep their local originals. Remote Python >=3.11, GNU `timeout`, and
   the original harness prerequisites must already be available. No installs.
   Pin the new host's SSH host key through the parent's verified connection
   evidence in a dedicated `known_hosts` file. The helper refuses unknown keys.
   Do not run `pulse.py` or `run.py` yourself.

4. Start the helper on Windows with Python >=3.11 and OpenSSH on PATH. Its only
   connection inputs are the public host, port, session, known-hosts path and
   private-key **path**. It never opens the private key or reads auth environment
   variables. OpenSSH reads the named key normally; this unattended path needs a
   usable noninteractive key. Agent authentication and SSH configuration files
   are disabled. `--host` is DNS/IPv4 without `root@`; the SSH user is `root`.

   Foreground invocation (the process must remain alive while the parent works):

   ```powershell
   python -B tests/fixtures/v02-performance/lease-controller.py `
     --host $sshHost --port $sshPort --identity $keyPath --known-hosts $knownHosts `
     --session $remoteSession --receipt "$trial/created-pod.json" `
     --go "$trial/GO.json" --ready "$trial/SEALED-READY.json" `
     --evidence "$trial/controller-evidence"
   ```

   For a hidden independent process, with those variables set to the exact new
   public connection/session values and absolute local paths:

   ```powershell
   $helper = (Resolve-Path 'tests/fixtures/v02-performance/lease-controller.py').Path
   $python = (Get-Command python).Source
   $controllerArgs = @(
     '-B', ('"{0}"' -f $helper), '--host', $sshHost, '--port', $sshPort,
     '--identity', ('"{0}"' -f $keyPath), '--known-hosts', ('"{0}"' -f $knownHosts),
     '--session', $remoteSession, '--receipt', ('"{0}/created-pod.json"' -f $trial),
     '--go', ('"{0}/GO.json"' -f $trial), '--ready', ('"{0}/SEALED-READY.json"' -f $trial),
     '--evidence', ('"{0}/controller-evidence"' -f $trial)
   )
   $controller = Start-Process -FilePath $python -ArgumentList $controllerArgs `
     -WindowStyle Hidden -PassThru -RedirectStandardOutput "$trial/controller.stdout.log" `
     -RedirectStandardError "$trial/controller.stderr.log"
   $controller.Id | Set-Content "$trial/controller.pid"
   ```

   `controller-evidence` must not exist. Check that `observations.jsonl` has a
   valid RUNNING record and continues to grow, then let the controller run while
   doing other work. The PID identifies this exact local controller for an
   intentional stop; never launch another controller to repair a failed start.

5. Read `controller-evidence/controller-status.json` when the process exits.
   Exit zero/PASS means the sealed supervisor reported PASS, four accepted cold
   ABBA results and both completed pair/mutation/parity markers were present.
   It is not a speedup claim or a cloud teardown receipt. The parent must still
   inspect/verify the collected evidence independently. Failure status includes
   the error and up to 8 KiB of SSH/probe stderr; startup errors before the local
   evidence directory exists go to the redirected stderr log. An ambiguous
   launch/transport failure is final, even if remote work started successfully.

6. On every outcome, preserve partial evidence with the unchanged remote
   `payload/harness/collect.py --session ...`, download its archive/checksum,
   verify locally, and delete the exact Pod through the original MCP. If the
   controller stopped early, allow the last 90-second remote lease to expire
   and confirm the remote supervisor has stopped before collecting; the parent
   may instead proceed with its already authorized shutdown/deletion. A hard
   Pod deadline always takes precedence over collection. Record deletion via
   get=not-found and absence from a complete fresh list.

## Bounds and failure behavior

- The sealed harness is unchanged: a 90-second lease, 35-minute experiment,
  300 seconds per build, exactly baseline/candidate/candidate/baseline, zero
  retries, and all independent OCI/replay/parity/mutation checks. The controller
  also stops on its own monotonic or absolute 35-minute deadline. It reserves a
  full SSH timeout rather than starting a call across that cutoff.
- Every observation validates receipt/GO/manifest bytes, sealed control-code
  hashes, Pod/nonce identity, a fresh response challenge, supervisor PID/start
  tick, worker deadline and status, and attempted ABBA order before renewal.
  An expired lease is never revived. Hashing the entire payload/binaries remains
  in the sealed runner's original preflight/build/final checks; pulses only hash
  small control files and do not walk the benchmark tree during timing.
- Unknown/malformed status, identity/hash changes, a lost supervisor, terminal
  failure, or the **first** SSH failure stops this controller. No SSH operation
  is retried. One local SSH child is allowed at a time, bounded to 15 seconds;
  each remote probe is bounded to 12 seconds and can pulse at most once. The
  remote supervisor starts at most 15 seconds after the local cutoff was set;
  its unchanged 35-minute cap remains independently enforced.
- Normal exit/signals kill and reap the local SSH child. On Windows, a
  kill-on-close Job also kills it if Python is forcibly terminated. There is no
  heartbeat thread, child daemon, or remote renewal loop. A request already
  received remotely may finish its single pulse within its 12-second bound;
  the last issued lease then expires within 90 seconds. The sealed remote
  supervisor may survive the local process until lease/deadline cleanup. This
  stops benchmark work, **not Pod billing**.
- Public protocol logs and controller configuration are retained under the new
  trial; no cloud API, credential discovery, private-key reads, local benchmark,
  `/source` access, or production Rust change is involved.
