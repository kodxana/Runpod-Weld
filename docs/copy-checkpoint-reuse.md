# Managed COPY checkpoint reuse

The managed Linux build path can avoid rereading unchanged payloads after a
single COPY. This targets the repeated root hashing and inherited-layer
verification observed in the [real Nemotron run](real-nemotron-5860971.md).
It does not eliminate full directory walks, final output verification, or the
first verification of newly created physical objects. Pod timing remains a
separate acceptance gate.

## Working-root inventory

Each baseline may retain one read-only root-directory handle within the existing
soft descriptor budget. The managed COPY records the device/inode of every
regular output it creates, before writing payload bytes. COPY replaces regular
leaves rather than modifying existing regular inodes. The record is returned
only on success, borrows the exact baseline, and is consumed by the immediately
following checkpoint. It is not a list of destination paths.

The checkpoint still walks every entry and observes metadata, xattrs, mounts,
symlinks and hardlink topology. It opens regular files and checks their identity
as before. A previous hash is reusable only at the same path with matching
regular-file identity, size, mtime and ctime, outside the COPY write set. Those
stamps reject unexpected changes; they do not establish the no-write interval.
That interval comes from the closed managed execution path and COPY's actual
write behavior.

Logical byte, entry and metadata charges remain unchanged. Missing root pins
disable reuse. A stale baseline/root or cancellation remains an error. RUN,
WORKDIR and cache replay do not receive a COPY proof; their checkpoint inventory
hashes payloads completely and establishes a new baseline. Arbitrary-callback
library entrypoints remain conservative.

## Inherited checkpoint layers

The existing publication session tracks a committed generation only after a
publication succeeds, including its durability checks. Checkpoint inheritance
and loading may consult source-side evidence from that committed generation.
They neither admit new objects nor advance publication generations.

Every pathname is bound to the retained physical object and the exporter's
pinned checkpoint directories. Independently copied cache objects cannot vouch
for a source checkpoint. Unknown or replaced objects are fully verified.
Metadata/configuration, descriptor order and multiplicity, limits and diff IDs
remain checked; the new delta is fully verified and decoded. Inheritance keeps
private checkpoint hardlinks, while public outputs receive independent copies.

Errors invalidate the session. First-admission verification, existing-winner
verification, restart behavior and final conservative publication remain intact.
This uses the existing cooperative-store/trusted-RUN contract; retained handles
are not kernel-enforced immutability against unrelated writers.

## Validation scope

Focused tests cover changed leaves, hardlink survivors, destination symlinks,
implicit parents, raw names, repeated overwrites, stale baseline/root refusal,
descriptor fallback, cancellation, exact logical charges and payload-read
counts. Existing raw/gzip CLI coverage includes consecutive COPY checkpoints,
warm cache reuse, no-cache output, independent replay and public inode isolation.
Publication tests cover committed-generation gating, source replacement,
corruption, cancellation, alias binding and conservative fallback.

These correctness checks do not establish a large-image speedup. The real cold,
warm and edited Nemotron outputs still need independent acceptance, as listed
in [implementation gaps](implementation-gaps.md).
