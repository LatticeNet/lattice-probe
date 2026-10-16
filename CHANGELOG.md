# Changelog

## Unreleased

### Added

- `custom_targets` on `POST /v1/probe`: definitions of targets the operator saved in lattice-server (id, url, method GET or HEAD, `expect_status` as statuses and ranges, optional `body_contains`), measured where `targets` names their ids. The probe checks every definition before use: https only, the scheme's port or one from 1024 to 65535, no credentials or fragments, address literals through the same address policy as servers (deny prefixes, mapped and NAT64 forms included), fully qualified host names that are not local-only or numeric, a 2 KiB URL cap, and a resolution hint on the probe that refuses names resolving to refused addresses. Requests that carry ids only behave as before.
- `body_match` on a target result with a `body_contains` needle: whether any sample's body held it in its first 64 KiB. The body itself is never returned.
- `capabilities` in `GET /v1/health`, listing `custom_targets`, so a server knows before it sends any.
- `LATTICE_PROBE_ALLOW_HTTP_TARGETS` permits http:// custom targets for a lab; off by default.

### Changed

- Target ids in `LATTICE_PROBE_TARGETS_FILE` may no longer start with `custom-`, which is reserved for custom targets so the two lists can never share an id.
- A request measures at most 16 targets, built-in and custom together.

## 0.1.0-alpha.2 (2026-10-08)

### Added

- `LATTICE_PROBE_DENY_PREFIXES`: comma-separated prefixes the probe always refuses, checked before `LATTICE_PROBE_ALLOW_PREFIXES` so deny wins, and matched against the IPv4 address inside a mapped, NAT64 or 6to4 form. Deployments set it to the probe host's own public addresses, which are global unicast and so were not refused before, and which reach services the host's firewall hides from the internet when dialled from the probe's bridge network.

## 0.1.0-alpha.1 (2026-10-08)

### Added

- `lattice-probe`, a long-lived daemon embedding sing-box `v1.13.19` (tags `with_quic,with_utls`) that creates pasted outbounds in one running instance, measures them and removes them on every exit path.
- Socket API: `GET /v1/health`, `GET /v1/targets`, `POST /v1/probe`, HTTP/1.1 on a 0660 unix socket, 64 KiB bodies, at most 32 probes in flight.
- Measures: validity, a plain server check (TCP connect, or a QUIC handshake attempt with salamander and xplus obfuscation), cold and warm delay per target with min/p50/p90 over 1 to 10 samples, exit IP and location, UDP through a DNS query, and an opt-in throughput download capped at 25 MB.
- Policy: allowed outbound types, request-local detours without cycles, configured targets only, no `*_path` fields in any letter case, field names sing-box cannot fold onto another field, and global unicast server addresses, enforced again at dial time by a guard outbound every probed outbound detours to.
- Credentials never reach a log; error text has request credentials redacted.
- `probectl` to test one outbound file in-process or against the socket; `lattice-probe -health` for the container health check.
- Distroless image for linux/amd64 and linux/arm64, uid 65532, read-only root, built from `v*` tags.
- `bench/engine-choice`, the sing-box versus mihomo benchmark behind design 27, and `bench/probebench` for the engine's own numbers.
