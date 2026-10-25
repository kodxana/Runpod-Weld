# Runtime metadata oracle

`docker-oracle.json` was generated with local Docker 29.7.2 by `python3 oracle.py`.
The script never invokes Weld. It builds scratch-only metadata examples, records
Docker's inspected config and failures, then removes its uniquely tagged images.
It does not pull images, execute RUN, start containers or publish to a registry.
The integration test compares Weld's exported config against these observations.

Cases cover shell/JSON encoding, all options, zero/default omission, numeric
limits, repeated declarations, stage inheritance, reset/NONE/re-enable, ARG/ENV
signal expansion, SHELL changes, USER preservation and invalid flags/values.
Weld explicitly rejects flags on NONE even though Docker ignores them. Malformed
JSON, negative durations (including negative zero), and the existing parser's
unsupported directives/heredocs are also rejected rather than guessed.

Primary semantics reviewed:

- [Dockerfile reference](https://docs.docker.com/reference/dockerfile/#healthcheck)
- [BuildKit instruction parser](https://github.com/moby/buildkit/blob/master/frontend/dockerfile/instructions/parse.go): `parseHealthcheck`, `parseOptInterval`, `parseStopSignal`
- [BuildKit flags](https://github.com/moby/buildkit/blob/master/frontend/dockerfile/instructions/bflag.go): duplicate flags and `--name=value`
- [BuildKit evaluator](https://github.com/moby/buildkit/blob/master/frontend/dockerfile/dockerfile2llb/convert.go): healthcheck replacement and stop-signal validation
- [Expansion interfaces](https://github.com/moby/buildkit/blob/master/frontend/dockerfile/instructions/commands.go): StopSignal supports expansion, HealthCheck does not
- [Moby signal parser](https://github.com/moby/sys/blob/main/signal/signal.go) and [Linux names](https://github.com/moby/sys/blob/main/signal/signal_linux.go)
- [Docker image config](https://github.com/moby/docker-image-spec/blob/main/specs-go/v1/image.go): integer nanoseconds and omitted zero fields

No runtime health monitoring is tested or implemented. Existing cache keys include
the evaluated config at filesystem checkpoints, and final metadata is exported
even when there are no filesystem instructions. Separate integration tests cover
local OCI base inheritance and cache hits/invalidation.
