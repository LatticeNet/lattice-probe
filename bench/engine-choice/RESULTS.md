# Outbound probe engine benchmark: sing-box vs mihomo

Run on 2026-10-08 for design 27 (`lattice/docs/designs/design-27-outbound-probe.md`). Everything was local and throwaway: one container, loopback only, generated credentials, no Lattice server and no fleet node.

## Verdict in one paragraph

Both engines pass every valid config and fail fast on every wrong credential, with the same root error text in each case (the server decides most of it). Latency is a tie on five of six protocols (cold p50 within about 0.1 ms on loopback). sing-box used slightly less CPU per test on vmess, vless/reality and trojan in all three sequential runs (by 0.01 to 0.12 ms, most on reality), and concurrency throughput overlapped across seven runs per engine. mihomo leaks resources on TUIC: `Close()` on a TUIC adapter is a no-op, so each test strands one QUIC connection (1 UDP fd, 5 goroutines, about 82 KiB heap), and 45 s of lingering with GC does not reclaim it. A long-lived probe that creates an outbound per test would grow without bound on TUIC lines. sing-box is also smaller (26.1 vs 43.3 MB) and peaks lower under concurrency (34 vs 45 MiB without TUIC, 34 vs 85 MiB with it). mihomo's engine init is faster (0.5 ms vs 7.6 ms from main), but its heavier package init makes process start to ready slower (median 55 ms vs 47 ms); neither matters for a long-lived daemon.

## Environment

| item | value |
|---|---|
| host | Apple M3, macOS (Darwin 25.5.0), Colima VM aarch64 with 4 vCPU and 4 GiB (3.8 GiB usable), kernel 6.8.0-100-generic |
| container | `golang:1.26.4-bookworm`, `--cpus 2 --memory 4g` (cgroup `cpu.max` 200000/100000, `memory.max` 4 GiB; the VM has less than 4 GiB, so the memory cap never binds) |
| architecture | **arm64** (linux/arm64). The control-plane host may be amd64; absolute numbers will differ there. |
| Go | go1.26.4, `CGO_ENABLED=0`, `-trimpath -ldflags "-s -w"`, GOMAXPROCS 2 in every probe process |
| engine A | `github.com/sagernet/sing-box v1.13.19`, build tags `with_quic,with_utls,with_wireguard` |
| engine B | `github.com/metacubex/mihomo v1.19.32`: the latest release tag (published 2026-09-30), not the branch head. No build tags. |
| upstream server | sing-box v1.13.19, same tags, `go install .../cmd/sing-box@v1.13.19`, one process in the same container |
| target | Go `net/http` server answering 204 at `http://127.0.0.1:18204/generate_204` |
| reality handshake | performance runs used a local Go TLS 1.3 server at `127.0.0.1:18443` (self-signed), so public-internet RTT does not dominate the numbers. A second reality inbound with handshake server `www.apple.com:443` was used for the correctness check only. |

Trap worth knowing: with `go 1.24` in the probe's `go.mod`, Go keeps the pre-1.25 GODEBUG default and ignores the cgroup CPU limit (GOMAXPROCS came out as 4 under `--cpus 2`). Both probe modules declare `go 1.26`, so the runtime sees the limit. The real probe repository needs the same.

## How each engine was driven

| | sing-box | mihomo |
|---|---|---|
| engine start | `include.Context(ctx)`, `box.New` with log disabled and one `direct` outbound, `Start()` | `log.SetLevel(log.SILENT)`, nothing else |
| create | `sing/common/json.UnmarshalExtendedContext[option.Outbound](ctx, text)` (the option registry path `sing-box check` uses), then `Outbound().Create(ctx, Router(), logger, tag, type, options)` | `encoding/json` text to `map[string]any`, then `adapter.ParseProxy(map)` |
| dial | `Outbound().Outbound(tag)` as `N.Dialer`, `DialContext(ctx, "tcp", socksaddr)` | `C.Proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP, DstPort})` |
| release | `Outbound().Remove(tag)`, which closes the outbound because the manager is started | `C.Proxy.Close()`. `ParseProxy` wraps every adapter in `autoCloseProxyAdapter`, whose `Close` calls the adapter's `Close` once and clears the finalizer. |
| URL test | `common/urltest.URLTest(ctx, url, outbound)` | `C.Proxy.URLTest(ctx, url, nil)`, `UnifiedDelay` at its default (false) |

Both programs share one harness (`harness/harness.go`, stdlib only). For each test it builds a fresh `http.Transport` whose `DialContext` goes through the engine, and it times with `httptrace`. **create** runs from text to a ready outbound. **cold** runs from the moment the transport calls the engine's dial to the first response byte of a GET on that new proxied connection. **warm** runs from the start of the second GET to its first byte; all 29,600 recorded warm GETs (sequential and concurrent runs) confirmed `GotConnInfo.Reused`. **remove** is the engine's release call after the connection is closed. CPU is `getrusage(RUSAGE_SELF)` user+sys of the probe process only (the server is not included); RSS and HWM come from `/proc/self/status`. Config text was generated once per case outside the timed region.

Client configs were made equivalent per protocol:

| protocol | server inbound | client settings (both engines) |
|---|---|---|
| ss | shadowsocks `2022-blake3-aes-128-gcm` | same method, 16-byte base64 key |
| vmess_ws | vmess, ws path `/vm` | cipher/security pinned to `aes-128-gcm`, alterId 0, ws path `/vm` |
| vless_reality | vless, flow `xtls-rprx-vision`, reality | same flow, uTLS fingerprint `chrome`, public key, short_id, SNI `reality.test` |
| trojan_tls | trojan, TLS self-signed | SNI `bench.test`, certificate verification off |
| hysteria2 | hysteria2, TLS self-signed, ALPN h3 | ALPN h3, verification off, no bandwidth hints (BBR in both) |
| tuic | tuic v5, BBR, ALPN h3 | uuid+password, BBR, `udp_relay_mode native`, ALPN h3, verification off, no 0-RTT |

## Results

Main run (`out/full/`); follow-ups and repeats at the end (`out/followup/`, `out/repeat/`). All latencies are in milliseconds over loopback, so they measure engine and handshake cost, not network.

### Binary size and start

| engine | stripped binary | exec to main (median) | main to ready (median) | exec to ready (median) | RSS idle 2 s after ready (median) | goroutines idle |
|---|---|---|---|---|---|---|
| sing-box | 26.1 MB (26149026 B) | 39.1 ms | 7.56 ms | 47.0 ms | 18.7 MiB | 8 |
| mihomo | 43.3 MB (43253922 B) | 54.7 ms | 0.46 ms | 55.2 ms | 20.3 MiB | 3 |

sing-box start runs (exec to ready ms): 124.9, 90.8, 41.8, 47.3, 45.1, 46.7, 50.7, 80.9, 39.2, 40.3
mihomo start runs (exec to ready ms): 78.7, 42.7, 70.6, 60.1, 51.7, 68.6, 33.6, 58.8, 27.3, 49.9

### Sequential, 200 iterations per protocol (ms)

| protocol | engine | ok | create p50/p90/p99 | dial p50 | cold p50/p90/p99 | warm p50/p90/p99 | remove p50/p90/p99 | CPU ms/test |
|---|---|---|---|---|---|---|---|---|
| ss | sing-box | 200/200 | 0.017 / 0.027 / 0.133 | 0.021 | 0.180 / 0.267 / 0.619 | 0.084 / 0.099 / 0.168 | 0.000 / 0.000 / 0.001 | 0.194 |
| ss | mihomo | 200/200 | 0.019 / 0.042 / 0.087 | 0.057 | 0.216 / 0.479 / 0.909 | 0.090 / 0.119 / 0.196 | 0.001 / 0.001 / 0.005 | 0.312 |
| vmess_ws | sing-box | 200/200 | 0.025 / 0.033 / 0.040 | 0.067 | 0.267 / 0.317 / 0.870 | 0.092 / 0.107 / 0.148 | 0.000 / 0.001 / 0.001 | 0.291 |
| vmess_ws | mihomo | 200/200 | 0.030 / 0.041 / 0.072 | 0.125 | 0.288 / 0.372 / 0.602 | 0.085 / 0.108 / 0.150 | 0.001 / 0.001 / 0.002 | 0.333 |
| vless_reality | sing-box | 200/200 | 0.034 / 0.042 / 0.142 | 0.676 | 0.821 / 0.887 / 1.091 | 0.091 / 0.103 / 0.123 | 0.000 / 0.001 / 0.001 | 0.617 |
| vless_reality | mihomo | 200/200 | 0.030 / 0.038 / 0.056 | 0.711 | 0.864 / 0.924 / 1.240 | 0.096 / 0.109 / 0.126 | 0.001 / 0.001 / 0.008 | 0.718 |
| trojan_tls | sing-box | 200/200 | 0.021 / 0.029 / 0.036 | 0.448 | 0.558 / 0.601 / 0.921 | 0.086 / 0.098 / 0.108 | 0.000 / 0.001 / 0.001 | 0.461 |
| trojan_tls | mihomo | 200/200 | 0.018 / 0.024 / 0.049 | 0.474 | 0.586 / 0.630 / 1.238 | 0.085 / 0.103 / 0.152 | 0.001 / 0.001 / 0.005 | 0.492 |
| hysteria2 | sing-box | 200/200 | 0.023 / 0.030 / 0.108 | 0.741 | 0.933 / 1.139 / 1.326 | 0.110 / 0.129 / 0.155 | 0.023 / 0.030 / 0.056 | 0.809 |
| hysteria2 | mihomo | 200/200 | 0.025 / 0.037 / 0.115 | 0.760 | 0.951 / 1.431 / 3.393 | 0.096 / 0.131 / 0.671 | 0.023 / 0.034 / 0.069 | 0.797 |
| tuic | sing-box | 200/200 | 0.027 / 0.034 / 0.140 | 0.561 | 0.762 / 0.952 / 1.130 | 0.106 / 0.123 / 0.173 | 0.020 / 0.028 / 0.036 | 0.661 |
| tuic | mihomo | 200/200 | 0.038 / 0.064 / 0.096 | 0.696 | 0.943 / 1.698 / 3.852 | 0.100 / 0.135 / 0.709 | 0.001 / 0.001 / 0.005 | 0.865 |

sing-box: warm GET not on the reused connection: 0; errors: none
mihomo: warm GET not on the reused connection: 0; errors: none

### Concurrency, 32 workers x 50 iterations, mixed protocols

| engine | ok | wall | tests/s | CPU user+sys | CPU ms/test | avg cores | peak RSS (VmHWM) | goroutines before / right after / after GC+2 s | cold p50/p90/p99 under load |
|---|---|---|---|---|---|---|---|---|---|
| sing-box | 1600/1600 | 0.73 s | 2206 | 0.75 s | 0.47 | 1.04 | 34.6 MiB | 8 / 10 / 8 | 5.637 / 21.971 / 51.971 |
| mihomo | 1600/1600 | 0.84 s | 1913 | 0.79 s | 0.50 | 0.95 | 84.6 MiB | 3 / 1333 / 1333 | 7.555 / 22.484 / 35.880 |

sing-box conc errors: none; per protocol cold p50: ss 3.55, vmess_ws 4.74, vless_reality 6.97, trojan_tls 5.25, hysteria2 8.21, tuic 5.97
mihomo conc errors: none; per protocol cold p50: ss 4.22, vmess_ws 5.61, vless_reality 13.98, trojan_tls 5.31, hysteria2 10.82, tuic 8.39

### Leaks: 2000 bare create/remove cycles, then 2000 full tests (each snapshot after runtime.GC() and 2 s settle)

| engine | snapshot | RSS MiB | heap alloc KiB | heap objects | goroutines | fds |
|---|---|---|---|---|---|---|
| sing-box | after_start | 18.8 | 527 | 1779 | 8 | 10 |
| sing-box | after_warmup60 | 26.1 | 703 | 3326 | 8 | 10 |
| sing-box | after_bare_create_remove | 28.0 | 704 | 3338 | 8 | 10 |
| sing-box | after_full_tests | 28.6 | 725 | 3493 | 8 | 10 |
| sing-box | after_free_os_memory | 27.3 | 733 | 3498 | 8 | 10 |
| mihomo | after_start | 21.1 | 1073 | 2402 | 3 | 7 |
| mihomo | after_warmup60 | 32.6 | 2294 | 6841 | 53 | 17 |
| mihomo | after_bare_create_remove | 34.7 | 2211 | 6803 | 53 | 17 |
| mihomo | after_full_tests | 87.3 | 29415 | 110998 | 1718 | 350 |
| mihomo | after_free_os_memory | 77.5 | 29332 | 110938 | 1718 | 350 |

sing-box: bare cycles 2000 in 75 ms (fail 0 ); full tests in 1837 ms (fail 0)
mihomo: bare cycles 2000 in 85 ms (fail 0 ); full tests in 2037 ms (fail 0)

### Correctness: wrong credentials (3 trials each, 5 s timeout)

| case | engine | result | ms to error (min / p50 / max) | timeouts | stage | error text |
|---|---|---|---|---|---|---|
| ss wrong_password | sing-box | 0/3 ok | 0.8 / 1.2 / 9.4 | 0 | cold | read tcp 127.0.0.1:<port>->127.0.0.1:20001: read: connection reset by peer |
| ss wrong_password | mihomo | 0/3 ok | 0.3 / 0.7 / 4.3 | 0 | cold | read tcp 127.0.0.1:<port>->127.0.0.1:20001: read: connection reset by peer |
| vmess_ws wrong_uuid | sing-box | 0/3 ok | 0.4 / 0.4 / 3.7 | 0 | cold | write tcp 127.0.0.1:<port>->127.0.0.1:20002: write: connection reset by peer |
| vmess_ws wrong_uuid | mihomo | 0/3 ok | 0.4 / 0.4 / 5.9 | 0 | cold | write tcp 127.0.0.1:<port>->127.0.0.1:20002: write: connection reset by peer |
| vless_reality wrong_uuid | sing-box | 0/3 ok | 1.3 / 1.4 / 5.4 | 0 | cold | EOF |
| vless_reality wrong_uuid | mihomo | 0/3 ok | 1.4 / 2.1 / 22.3 | 0 | cold | EOF |
| vless_reality wrong_short_id | sing-box | 0/3 ok | 0.8 / 1.0 / 18.1 | 0 | dial | x509: certificate signed by unknown authority |
| vless_reality wrong_short_id | mihomo | 0/3 ok | 0.7 / 0.8 / 0.8 | 0 | dial | 127.0.0.1:20003 connect error: x509: certificate signed by unknown authority |
| vless_reality public_wrong_short_id | sing-box | 0/3 ok | 679.1 / 1634.5 / 3487.6 | 0 | dial | reality verification failed |
| vless_reality public_wrong_short_id | mihomo | 0/3 ok | 4837.7 / 5003.7 / 5004.2 | 2 | cold, dial | 127.0.0.1:20013 connect error: REALITY authentication failed / context deadline exceeded |
| trojan_tls wrong_password | sing-box | 0/3 ok | 1.5 / 1.6 / 7.1 | 0 | cold | EOF |
| trojan_tls wrong_password | mihomo | 0/3 ok | 3.2 / 11.2 / 13.1 | 0 | cold | EOF |
| hysteria2 wrong_password | sing-box | 0/3 ok | 1.4 / 5.3 / 31.3 | 0 | dial | authentication failed, status code: 404 |
| hysteria2 wrong_password | mihomo | 0/3 ok | 2.9 / 4.4 / 14.4 | 0 | dial | authentication failed, status code: 404 |
| tuic wrong_password | sing-box | 0/3 ok | 1.3 / 1.5 / 3.2 | 0 | cold | EOF |
| tuic wrong_password | mihomo | 0/3 ok | 2.5 / 4.5 / 17.4 | 0 | cold | EOF |
| tuic wrong_uuid | sing-box | 0/3 ok | 1.0 / 1.9 / 3.0 | 0 | cold | EOF |
| tuic wrong_uuid | mihomo | 0/3 ok | 2.5 / 5.1 / 7.4 | 0 | cold | EOF |
| ss valid | sing-box | 3/3 ok | 0.9 / 2.6 / 4.2 | 0 | - | - |
| ss valid | mihomo | 3/3 ok | 0.7 / 1.0 / 5.0 | 0 | - | - |
| vmess_ws valid | sing-box | 3/3 ok | 0.9 / 1.2 / 6.1 | 0 | - | - |
| vmess_ws valid | mihomo | 3/3 ok | 0.7 / 0.9 / 1.3 | 0 | - | - |
| vless_reality valid | sing-box | 3/3 ok | 1.1 / 1.5 / 3.0 | 0 | - | - |
| vless_reality valid | mihomo | 3/3 ok | 1.5 / 3.7 / 4.0 | 0 | - | - |
| trojan_tls valid | sing-box | 3/3 ok | 0.6 / 0.9 / 1.0 | 0 | - | - |
| trojan_tls valid | mihomo | 3/3 ok | 1.6 / 1.7 / 2.7 | 0 | - | - |
| hysteria2 valid | sing-box | 3/3 ok | 1.0 / 1.3 / 1.3 | 0 | - | - |
| hysteria2 valid | mihomo | 3/3 ok | 1.6 / 1.9 / 5.3 | 0 | - | - |
| tuic valid | sing-box | 3/3 ok | 0.9 / 1.2 / 1.6 | 0 | - | - |
| tuic valid | mihomo | 3/3 ok | 1.2 / 1.3 / 2.4 | 0 | - | - |
| vless_reality public_valid | sing-box | 2/3 ok | 687.4 / 799.6 / 5010.1 | 1 | cold | context deadline exceeded |
| vless_reality public_valid | mihomo | 2/3 ok | 623.5 / 629.8 / 5005.6 | 1 | cold | context deadline exceeded |

### URLTest helper, 5 runs per protocol (fresh outbound each run)

| protocol | engine | reported ms | wall ms | errors |
|---|---|---|---|---|
| ss | sing-box | 3, 1, 0, 0, 0 | 4.5, 1.9, 0.4, 0.3, 0.3 | - |
| ss | mihomo | 24, 0, 0, 2, 0 | 24.4, 0.8, 0.5, 2.2, 0.8 | - |
| vmess_ws | sing-box | 0, 1, 0, 0, 0 | 1.1, 1.4, 0.3, 0.4, 0.4 | - |
| vmess_ws | mihomo | 2, 0, 0, 0, 0 | 2.8, 0.6, 0.4, 0.3, 0.3 | - |
| vless_reality | sing-box | 0, 0, 0, 0, 0 | 2.2, 1.2, 0.9, 1.3, 1.0 | - |
| vless_reality | mihomo | 4, 1, 0, 0, 1 | 4.1, 1.1, 1.0, 0.9, 1.4 | - |
| trojan_tls | sing-box | 0, 0, 0, 0, 0 | 1.4, 0.6, 0.7, 0.6, 0.7 | - |
| trojan_tls | mihomo | 1, 0, 0, 0, 0 | 1.7, 0.7, 0.7, 0.7, 0.7 | - |
| hysteria2 | sing-box | 0, 0, 0, 0, 0 | 5.6, 1.6, 2.5, 1.1, 1.4 | - |
| hysteria2 | mihomo | 5, 1, 2, 1, 1 | 5.5, 1.3, 2.0, 1.4, 1.3 | - |
| tuic | sing-box | 0, 0, 0, 0, 0 | 0.8, 0.8, 0.8, 0.8, 0.8 | - |
| tuic | mihomo | 2, 1, 1, 1, 1 | 2.5, 1.2, 1.2, 1.5, 1.1 | - |

### Follow-up: leak attribution, 300 full tests per protocol, then 45 s linger with GC every 5 s

| engine | protocol | goroutines (after warmup / after 300 / after linger) | fds | heap alloc KiB | RSS MiB |
|---|---|---|---|---|---|
| sing-box | ss | 8 / 8 / 8 | 10 / 10 / 10 | 569 / 579 / 580 | 23.1 / 21.8 / 21.6 |
| sing-box | vmess_ws | 8 / 8 / 8 | 10 / 10 / 10 | 581 / 598 / 599 | 23.3 / 22.7 / 22.5 |
| sing-box | vless_reality | 8 / 8 / 8 | 10 / 10 / 10 | 585 / 593 / 595 | 24.3 / 23.6 / 23.1 |
| sing-box | trojan_tls | 8 / 8 / 8 | 10 / 10 / 10 | 582 / 602 / 603 | 22.2 / 23.2 / 23.2 |
| sing-box | hysteria2 | 8 / 8 / 8 | 10 / 10 / 10 | 644 / 653 / 653 | 25.1 / 26.1 / 25.1 |
| sing-box | tuic | 8 / 8 / 8 | 10 / 10 / 10 | 596 / 608 / 609 | 24.2 / 25.4 / 24.5 |
| mihomo | ss | 3 / 3 / 3 | 7 / 7 / 7 | 1098 / 1104 / 1105 | 27.1 / 28.7 / 25.0 |
| mihomo | vmess_ws | 3 / 3 / 3 | 7 / 7 / 7 | 1106 / 1134 / 1136 | 25.1 / 28.4 / 25.6 |
| mihomo | vless_reality | 3 / 3 / 3 | 7 / 7 / 7 | 1362 / 1374 / 1375 | 27.1 / 30.7 / 27.1 |
| mihomo | trojan_tls | 3 / 3 / 3 | 7 / 7 / 7 | 1352 / 1370 / 1371 | 29.7 / 26.4 / 26.1 |
| mihomo | hysteria2 | 3 / 3 / 3 | 7 / 7 / 7 | 1413 / 1437 / 1438 | 28.8 / 31.8 / 28.3 |
| mihomo | tuic | 303 / 1803 / 1803 | 67 / 367 / 367 | 6332 / 30827 / 30771 | 35.4 / 72.8 / 71.7 |

### Follow-up: public reality destination (www.apple.com:443), 2 rounds x 5 trials, engines alternated

| engine | case | ok | timeouts | ms to result min / p50 / max | error text |
|---|---|---|---|---|---|
| sing-box | public_valid | 10/10 | 0 | 68.0 / 71.7 / 86.2 | - |
| sing-box | public_wrong_short_id | 0/10 | 0 | 63.9 / 77.7 / 95.7 | reality verification failed |
| mihomo | public_valid | 10/10 | 0 | 64.4 / 73.7 / 105.3 | - |
| mihomo | public_wrong_short_id | 0/10 | 0 | 65.4 / 71.7 / 82.4 | 127.0.0.1:20013 connect error: REALITY authentication failed |

### Repeats: concurrency 3 runs each (32 x 50), all six protocols and the five without tuic

| mix | engine | tests/s (3 runs) | CPU ms/test | peak RSS VmHWM MiB | goroutines after GC+2 s | ok | cold p50 / p99 ms |
|---|---|---|---|---|---|---|---|
| all | sing-box | 2003, 1689, 1980 | 0.48, 0.56, 0.50 | 34.6, 34.9, 34.1 | 8, 8, 8 | 1600, 1600, 1600 | 6.5/49, 6.4/74, 6.3/52 |
| all | mihomo | 2091, 1828, 1941 | 0.47, 0.53, 0.49 | 85.8, 86.1, 83.7 | 1333, 1333, 1333 | 1600, 1600, 1600 | 7.8/38, 8.7/37, 7.8/39 |
| notuic | sing-box | 2520, 2294, 1765 | 0.41, 0.42, 0.49 | 33.7, 34.1, 33.9 | 8, 8, 8 | 1600, 1600, 1600 | 5.6/49, 5.8/52, 6.2/61 |
| notuic | mihomo | 2017, 2188, 1927 | 0.47, 0.44, 0.49 | 47.1, 44.9, 45.1 | 3, 3, 3 | 1600, 1600, 1600 | 6.9/54, 7.0/37, 7.7/92 |

### Repeats: sequential, 2 more runs each (cold p50 ms / cold p99 ms / CPU ms per test)

| engine | run | ss | vmess_ws | vless_reality | trojan_tls | hysteria2 | tuic |
|---|---|---|---|---|---|---|---|
| sing-box | 1 | 0.242 / 3.70 / 0.32 | 0.314 / 0.59 / 0.31 | 0.864 / 3.63 / 0.67 | 0.578 / 1.00 / 0.46 | 1.013 / 1.46 / 0.82 | 0.785 / 1.12 / 0.65 |
| sing-box | 2 | 0.231 / 1.33 / 0.23 | 0.292 / 0.59 / 0.29 | 0.845 / 1.14 / 0.62 | 0.578 / 1.06 / 0.46 | 0.999 / 3.64 / 0.91 | 0.826 / 1.85 / 0.71 |
| mihomo | 1 | 0.223 / 1.98 / 0.25 | 0.305 / 0.61 / 0.33 | 0.874 / 1.24 / 0.73 | 0.589 / 0.90 / 0.48 | 0.963 / 2.54 / 0.75 | 0.880 / 3.37 / 0.81 |
| mihomo | 2 | 0.213 / 0.62 / 0.26 | 0.303 / 0.98 / 0.32 | 0.869 / 1.21 / 0.74 | 0.586 / 0.71 / 0.47 | 1.076 / 2.89 / 0.86 | 1.120 / 5.94 / 1.09 |

## Findings

**Correctness.** Each engine passed every valid config: 1,200 of 1,200 tests in each of 3 sequential runs, 1,600 of 1,600 in each of 7 concurrency runs, 2,000 of 2,000 full leak cycles, and every valid control in the error suite. Every wrong credential failed fast in both engines, well under the 5 s timeout. Most of the failure shape is decided by the server. Shadowsocks 2022 and vmess get a TCP reset, so the error is `connection reset by peer` (on read for ss, on write for vmess). Trojan, vless with a wrong UUID, and TUIC (wrong password or wrong UUID) get a plain `EOF` after the server logs the auth failure. Neither engine can tell "wrong credential" from "server closed" for these, so the probe has to report "handshake failed" there, not "wrong password". Hysteria2 is the only protocol that names the cause (`authentication failed, status code: 404`), and it does so at the dial stage in both engines. A wrong reality short_id fails at the dial stage in both: with a public handshake site the error is `reality verification failed` (sing-box) or `REALITY authentication failed` (mihomo) at 64 to 96 ms; with the local self-signed handshake site it surfaces as an x509 error because the fallback certificate is not trusted. mihomo prefixes dial errors with `<server>:<port> connect error:`; sing-box returns the bare cause. In the main run, mihomo timed out on 2 of 3 public wrong-short_id trials, but the public valid control also timed out once in each engine in the same minute, and 20 follow-up trials (10 per engine, alternated) showed no timeouts. That was internet noise, not engine behavior. Both engines run the reality fallback request in a background goroutine (`go realityClientFallback` in both sources), so neither blocks the error on it.

**TUIC leak in mihomo (confirmed, mechanism read in source).** `adapter/outbound/tuic.go` in v1.19.32 defines no `Close`, so `C.Proxy.Close()` reaches `Base.Close`, which returns nil and leaves the QUIC connection open. The transport only frees its client through `runtime.SetFinalizer`, and the 10 s default heartbeat keeps the connection alive, so the finalizer path did not reclaim anything within 45 s. Measured: after 300 TUIC tests, goroutines went 303 to 1803, fds 67 to 367 and heap 6.2 to 30.1 MiB, with no change after the linger. Every other protocol, in both engines, stayed flat (goroutines and fds identical before and after). The same leak explains mihomo's concurrency numbers: 1333 goroutines left after the mixed run (about 266 TUIC tests x 5) and a peak of 84 to 86 MiB. It also explains the worse TUIC tails in sequential runs (cold p99 3.4 to 5.9 ms vs 1.1 to 1.9 ms), since leaked connections keep heartbeating while later tests run. mihomo's TUIC `remove` time (0.001 ms vs 0.020 ms for sing-box) is the no-op close showing. A mihomo-based probe would have to work around this, for example by keeping one adapter per TUIC line or by reaching into the transport to close it; neither is available through the public `C.Proxy` interface.

**Speed and CPU.** On loopback the engines tie on latency for ss, vmess_ws, vless_reality, trojan_tls and hysteria2: cold p50 within about 0.1 ms and warm p50 within about 0.015 ms across three sequential runs, with no consistent winner. CPU per test is close but not random: sing-box was lower on vmess_ws (by about 0.03 ms), vless_reality (0.06 to 0.12 ms) and trojan_tls (0.01 to 0.03 ms) in all three runs, while ss and hysteria2 flipped between runs. Concurrency throughput overlapped across repeats (sing-box 1689 to 2520 tests/s, mihomo 1828 to 2188). Under load, cold p50 was slightly lower for sing-box (5.6 to 6.5 ms vs 6.9 to 8.7 ms), and cold p99 jumped around in both. Create and remove both cost tens of microseconds in each engine, so per-test outbound creation is free in either.

**Memory.** Idle RSS after start: 18.7 MiB (sing-box) vs 20.3 MiB (mihomo). Peak RSS under 32-way concurrency without TUIC: about 34 MiB vs 45 MiB. With TUIC: 34 MiB vs 84 to 86 MiB because of the leak. Heap in use after GC stays under 1 MiB for sing-box and about 1.1 to 1.4 MiB for mihomo when nothing leaks. Go keeps RSS after GC (the scavenger returns pages slowly), so RSS growth from about 19 to 28 MiB in sing-box's leak run is runtime retention, not a leak: heap, goroutines and fds stayed flat.

**URLTest helpers are not a substitute for the harness.** Both send HEAD and return whole milliseconds as `uint16`, so on loopback most results are 0 or 1. They also time different spans. sing-box restarts the clock after dial when the connection still needs its handshake on first write (`N.NeedHandshakeForWrite`, true for vmess and vless), so it excludes the dial for exactly the protocols where the dial is lazy. mihomo includes the dial unless `UnifiedDelay` is on, in which case it times a second request. The design's own cold and warm timing is the comparable measure in both engines.

## What was not measured

UDP relay (`ListenPacket` DNS query), the throughput test, the plain TCP or QUIC server-reachable check, and real network RTT were all out of scope for this run; everything ran over loopback. The 0.5 CPU and 256 MiB limits from the design's deployment section were not applied; the run used the 2 vCPU shape requested. Only arm64 was measured. Start time was taken over 10 runs per engine; the `exec to main` column includes the Go runtime, package init (heavier in mihomo) and a few milliseconds of `date` fork overhead from the launcher, which is the same for both. Engine-level jitter at the 0.01 ms scale is below what one loopback run can resolve; differences smaller than about 0.1 ms in p50 should be read as ties. The vless/reality uTLS ClientHello may differ between engines (mihomo's `support-x25519mlkem768` defaults to false; whether sing-box's `chrome` fingerprint sends an ML-KEM key share was not checked), which would change handshake size slightly.

## Files

- `harness/`: shared measurement code (`harness.go`, `params.go`) and `cmd/benchaux` (setup of throwaway keys, cert and server config; 204 target; local TLS 1.3 reality destination).
- `sbprobe/main.go`, `mhprobe/main.go`: the two engine adapters. `build.sh` builds everything; `run.sh full` is the main run; `followup.sh` and `followup2.sh` are the leak attribution, public reality retries and repeats.
- `out/full/`, `out/followup/`, `out/repeat/`: raw JSON per mode and engine (sequential runs include every sample), `run.log` with server CPU ticks per run, and `server.log`. `out/smoke/` is the first sanity pass. `out/tables.md` is the generated table set embedded above (`summarize.py`).
- `bin/`: the stripped binaries measured. `server/` holds the generated throwaway params, certificate and server config.

To rerun: `docker volume create lpb-gomod; docker volume create lpb-gocache`, build with `docker run --rm -v $PWD:/bench -v lpb-gomod:/go/pkg/mod -v lpb-gocache:/root/.cache/go-build golang:1.26.4-bookworm /bench/build.sh` (it uses `GOPROXY=https://goproxy.cn,direct` because proxy.golang.org stalled from this network), then `docker run -d --name lpb-bench --cpus 2 --memory 4g -v $PWD:/bench golang:1.26.4-bookworm sleep infinity` and `docker exec lpb-bench /bench/run.sh full`. Keep the module cache in a Docker volume: on Colima a bind-mounted cache made the first build stall for over 15 minutes.
