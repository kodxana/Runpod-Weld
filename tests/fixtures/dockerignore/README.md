# Independent dockerignore regressions

`cargo test --test dockerignore_cli` uses scratch builds, no RUN or network,
and verifies emitted OCI layers through the public loader, verifier and replay
APIs. Run as Linux x86_64 root for faithful ownership/metadata replay. Every
fixture has an isolated store; successive builds share it for cache checks.
Output and work directories are unique per build and outside its context.

`patterns.json` is shared with an optional Go matcher oracle pinned to
`github.com/moby/patternmatcher v0.6.0`. From this directory, `go run -mod=mod .`
checks the expected exclusion booleans with upstream `ignorefile.ReadAll` and
`MatchesOrParentMatches`. This checks matcher semantics, not Docker COPY,
BuildKit directory traversal, control-file precedence or Weld itself.

Primary references:
- https://github.com/moby/patternmatcher/blob/v0.6.0/patternmatcher_test.go
- https://github.com/moby/patternmatcher/blob/v0.6.0/ignorefile/ignorefile.go

The cache tests pin emitted metadata, including future atime to avoid relatime
read effects. They edit existing ignored files, not directory entries: adding
an ignored file may correctly invalidate a preserved parent directory mtime.
Excluded control-file comments must not alter semantic cache identity.

## Docker filesystem comparison

Run `python3 tests/fixtures/dockerignore/docker_oracle.py` from the repository
root against an existing Docker daemon. The script records versions and runs
17 scratch-build checks without RUN or base pulls, using network=none and a
60-second command timeout. It compares files, contents, directory structure,
policy precedence, and explicit-source failures. It does not provision a daemon.

The Rust CLI suite separately checks pre-mutation failures, confinement, cache
reuse and invalidation, and preserved directory timestamps. Passing the reference
oracles alone does not establish Weld compatibility; run the Rust suite too.