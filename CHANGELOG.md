# Changelog

## Unreleased

### Added

- `lattice-probe`, a long-lived daemon embedding sing-box `v1.13.19` (tags `with_quic,with_utls`) that creates pasted outbounds in one running instance, measures them and removes them on every exit path.
- Socket API: `GET /v1/health`, `GET /v1/targets`, `POST /v1/probe`, HTTP/1.1 on a 0660 unix socket, 64 KiB bodies, at most 32 probes in flight.
- Measures: validity, a plain server check (TCP connect, or a QUIC handshake attempt with salamander and xplus obfuscation), cold and warm delay per target with min/p50/p90 over 1 to 10 samples, exit IP and location, UDP through a DNS query, and an opt-in throughput download capped at 25 MB.
- Policy: allowed outbound types, request-local detours without cycles, configured targets only, no `*_path` fields, and global unicast server addresses, enforced again at dial time by a guard outbound every probed outbound detours to.
- Credentials never reach a log; error text has request credentials redacted.
- `probectl` to test one outbound file in-process or against the socket; `lattice-probe -health` for the container health check.
- Distroless image for linux/amd64 and linux/arm64, uid 65532, read-only root, built from `v*` tags.
- `bench/engine-choice`, the sing-box versus mihomo benchmark behind design 27, and `bench/probebench` for the engine's own numbers.
