# lattice-probe

lattice-probe answers one question for a pasted proxy outbound: does it work, and how fast is it. It is a long-lived daemon that embeds [sing-box](https://github.com/SagerNet/sing-box) as a Go library and runs one sing-box instance with no inbounds. Each request's outbounds are decoded with the sing-box option registry (the same path `sing-box check` uses), created inside that running instance under fresh tags, measured, and removed again on every exit path. Nothing is written to disk, nothing reloads, and the sing-box that serves users is never involved.

lattice-server talks to the probe over a unix socket and exposes it to operators as a vpn-core host service. The design, the alternatives that were rejected, and the engine benchmark are in `lattice/docs/designs/design-27-outbound-probe.md`; the benchmark programs are under [`bench/`](bench/).

The sing-box version is pinned in `go.mod` to the tag the fleet runs (`v1.13.19` today), so a probe result describes the core the fleet runs.

## What a probe measures

| Measure | How |
|---|---|
| valid | option decode, then outbound create in the running instance; a config sing-box refuses never reaches the network |
| server | plain TCP connect to the first hop's `server:server_port`, outside the proxy protocol; for hysteria, hysteria2 and tuic a QUIC handshake attempt, where any answer counts (salamander and xplus obfuscation are applied) |
| cold delay | GET through a new proxied connection, timed with `httptrace` from the start of the dial to the first response byte, so it includes the proxy handshake |
| warm delay | a second GET on the same connection |
| samples | 1 to 10 cold and warm pairs per target (default 5), reported as min, p50 and p90 with ok/of |
| exit | GET `https://www.cloudflare.com/cdn-cgi/trace` through the outbound: exit IP, `loc`, `colo` |
| UDP | a DNS query to `1.1.1.1:53` through the outbound's `ListenPacket`, only when asked and only when the outbound relays UDP |
| throughput | off by default; downloads up to 25 MB (default 10 MB) from `speed.cloudflare.com` and times the body from the first byte |

sing-box's `urltest.URLTest` is not used for timing: it sends HEAD, rounds to whole milliseconds and leaves the dial out for vmess and vless. All delays are milliseconds with one decimal.

For QUIC protocols the outbound keeps one QUIC connection and opens a stream per request, so only the first sample of a probe pays the QUIC handshake. That is what a client feels after its first request too.

## API

HTTP/1.1 on a unix socket, path from `LATTICE_PROBE_SOCKET` (default `/run/lattice-probe/probe.sock`), mode 0660.

`GET /v1/health`

```json
{"probe_version":"0.1.0","engine":"sing-box","core_version":"1.13.19","uptime_s":42,"inflight":0,"max_inflight":32,"targets":3}
```

`GET /v1/targets`

```json
{"targets":[{"id":"gstatic-204","url":"https://www.gstatic.com/generate_204","expect":204},
            {"id":"cloudflare-204","url":"https://cp.cloudflare.com/generate_204","expect":204},
            {"id":"apple-success","url":"https://www.apple.com/library/test/success.html","expect":200}]}
```

`POST /v1/probe`, body at most 64 KiB:

```json
{"outbounds":[{"type":"vless","tag":"exit","server":"example.net","server_port":443,"uuid":"...","tls":{"enabled":true}}],
 "test":"exit","targets":["gstatic-204"],"samples":5,"udp":true,"throughput":false,"throughput_bytes":0,"timeout_ms":15000}
```

`outbounds` holds one outbound, or up to eight for a chain, where `detour` names another outbound of the same request. `test` names the one to measure and may be left out when there is only one. Missing `targets` means the first configured target; zero values mean the defaults above.

Every completed probe answers 200, including one whose outbound fails:

```json
{"valid":true,"stage":"ok","error":"",
 "server":{"address":"example.net:443","reachable":true,"rtt_ms":41.3,"network":"tcp"},
 "targets":[{"id":"gstatic-204","ok":5,"of":5,"cold_ms":{"min":212.4,"p50":230.1,"p90":268.0},
             "warm_ms":{"min":74.2,"p50":78.0,"p90":90.6},"status":204,"error":""}],
 "exit":{"ip":"203.0.113.7","loc":"US","colo":"LAX"},
 "udp":{"ok":true,"rtt_ms":80.2,"error":""},
 "throughput":null,
 "engine":{"name":"sing-box","version":"1.13.19"},"took_ms":1840.5}
```

`stage` is where the probe stopped:

| stage | meaning |
|---|---|
| `ok` | every target answered as expected at least once |
| `decode` | sing-box could not decode an outbound (`valid` is false) |
| `create` | sing-box refused to create an outbound (`valid` is false) |
| `server` | the first hop refused or ignored a plain connect, or its name does not resolve |
| `handshake` | no sample got an HTTP answer: wrong credentials, a wrong transport, or a server that reaches no target. Most protocols cannot tell these apart; the server just closes the connection |
| `target` | the proxy works, but a target never answered with its expected status |
| `timeout` | samples ran out of time without an answer |

`exit`, `udp` and `throughput` are `null` when they were not measured. A malformed body or a policy refusal answers 400 with `{"error":{"stage":"request"|"policy","message":"..."}}`; a probe beyond 32 in flight answers 429 with `Retry-After`.

## Policy

Checked before anything connects:

- allowed types: shadowsocks, vmess, vless, trojan, hysteria, hysteria2, tuic, shadowtls, anytls, socks, http, ssh. direct, block, dns, selector, urltest and everything else are refused;
- at most 8 outbounds, unique tags, `detour` only to a tag of the same request and without cycles;
- target ids only from the configured list; a request can never supply a URL;
- samples 1 to 10, `timeout_ms` 1000 to 30000, `throughput_bytes` at most 25,000,000;
- no field ending in `_path` (`certificate_path`, `private_key_path`, ...): the probe never reads a file named by a request;
- field names are what sing-box reads: top-level names exactly lowercase ASCII and no non-ASCII name at any depth. The sing-box decoder matches names case-insensitively with Unicode folding (`ſerver` decodes as `server`), so a folded name would let the policy, the response and the audit name one server while sing-box dials another;
- every server address, and every address its name resolves to, must be global unicast. Loopback, RFC 1918, unique local (fc00::/7), link-local, CGNAT (100.64.0.0/10), multicast, unspecified, 0.0.0.0/8 and the other special-purpose ranges are refused, including IPv4-mapped, NAT64 and 6to4 forms of them.

The address check is not only a parse-time check. Every outbound a request creates has its `detour` rewritten to an internal guard outbound, so all of its traffic (TCP, connected UDP for QUIC, and unconnected UDP) leaves through one dialer. The guard resolves names itself, refuses any address the policy refuses, and checks again in the socket's `Control` hook with the exact address the kernel is about to connect to. The address dialled is therefore always one that passed the check, even when a name rebinds between the parse-time check and the dial; `TestRebindingRefusedAtDialTime` proves it. `domain_resolver` is dropped from pasted outbounds for the same reason: the guard resolves server names.

`LATTICE_PROBE_ALLOW_PREFIXES` (comma-separated CIDRs, empty by default) exempts prefixes from the address classes, for a lab network. It never opens unspecified or multicast addresses.

## Credentials and logs

A pasted outbound carries passwords and UUIDs. The probe never logs an outbound or any part of one. Each probe leaves exactly one log line with a request id, the outbound types, the stage and the duration; error text is not logged, and sing-box's own logger is disabled. Error text returned to the caller has every credential-like value of the request (passwords, UUIDs, keys, short ids, tokens) replaced with `[redacted]`. Results live only in the answer; the probe keeps no history.

## Running

```sh
docker run -d --name lattice-probe \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 128m --cpus 0.5 --pids-limit 256 \
  -v lattice-probe-sock:/run/lattice-probe \
  ghcr.io/latticenet/lattice-probe:<tag>
```

The image is distroless, runs as uid and gid 65532 and works with a read-only root. lattice-server mounts the same volume and needs gid 65532 as a supplementary group to use the 0660 socket. Keep the probe off the network that reaches lattice-server's port, so a check that is wrong still cannot aim a pasted outbound at the control plane. The image holds only the daemon; its health check runs `lattice-probe -health`.

Environment:

| variable | default | meaning |
|---|---|---|
| `LATTICE_PROBE_SOCKET` | `/run/lattice-probe/probe.sock` | socket path |
| `LATTICE_PROBE_TARGETS_FILE` | none | JSON `{"targets":[...]}` that replaces the built-in list; ids match `^[a-z0-9-]{1,40}$`, URLs are https |
| `LATTICE_PROBE_ALLOW_PREFIXES` | none | CIDRs exempt from the address policy |

`probectl`, built from `./cmd/probectl`, tests one outbound file in-process or against a running daemon:

```sh
probectl outbound.json                    # in-process
probectl -socket /run/lattice-probe/probe.sock -udp outbound.json
probectl -json -targets gstatic-204,cloudflare-204 chain.json
probectl -health
```

## Development

sing-box needs build tags for QUIC (hysteria, hysteria2, tuic) and uTLS (Reality). Without them the engine package does not compile, on purpose:

```sh
go build -tags with_quic,with_utls ./...
go vet -tags with_quic,with_utls ./...
go test -race -gcflags=all=-d=checkptr=0 -tags with_quic,with_utls ./...
```

The tests start an in-process sing-box server with shadowsocks 2022, vmess over websocket, vless with Reality (against a local TLS 1.3 site), trojan with TLS, hysteria2 and TUIC v5 inbounds, plus local targets, so they need no network. checkptr is off under `-race` because sing-vmess's Vision reads `crypto/tls` internals with pointer arithmetic that checkptr rejects; the race detector itself stays on.

Release images are built by `.github/workflows/container.yml` from `v*` tags for linux/amd64 and linux/arm64. During the alpha phase tags are prereleases (`v0.1.0-alpha.1`).

## License

GPL-3.0-or-later, the licence of sing-box, which this program links. That is why the probe is its own repository and process: lattice-server, lattice-node-agent and the vpn-core plugin are MIT and talk to it only over the socket.
