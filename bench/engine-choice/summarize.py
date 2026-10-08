"""Turn out/<run>/*.json into markdown tables (stdout). Stdlib only."""

import json
import os
import re
import statistics
import sys

RUN = sys.argv[1] if len(sys.argv) > 1 else "out/full"
ENG = [("sbprobe", "sing-box"), ("mhprobe", "mihomo")]
PROTOS = ["ss", "vmess_ws", "vless_reality", "trojan_tls", "hysteria2", "tuic"]


def load(name):
    with open(os.path.join(RUN, name)) as f:
        return json.load(f)


def mb(kb):
    return f"{kb / 1024:.1f}"


def out(s=""):
    print(s)


# binary size
out("### Binary size and start\n")
out("| engine | stripped binary | exec to main (median) | main to ready (median) | exec to ready (median) | RSS idle 2 s after ready (median) | goroutines idle |")
out("|---|---|---|---|---|---|---|")
for key, name in ENG:
    size = os.path.getsize(os.path.join("bin", key))
    rows = [load(f"{key}-start-{i}.json") for i in range(1, 11)]
    med = lambda k: statistics.median(r[k] for r in rows)
    rss = statistics.median(r["idle_2s"]["rss_kb"] for r in rows)
    gor = statistics.median(r["idle_2s"]["goroutines"] for r in rows)
    out(f"| {name} | {size / 1e6:.1f} MB ({size} B) | {med('exec_to_main_ms'):.1f} ms | {med('main_to_ready_ms'):.2f} ms | {med('exec_to_ready_ms'):.1f} ms | {mb(rss)} MiB | {gor:.0f} |")
out()
for key, name in ENG:
    rows = [load(f"{key}-start-{i}.json") for i in range(1, 11)]
    out(f"{name} start runs (exec to ready ms): " + ", ".join(f"{r['exec_to_ready_ms']:.1f}" for r in rows))
out()

# sequential
out("### Sequential, 200 iterations per protocol (ms)\n")
out("| protocol | engine | ok | create p50/p90/p99 | dial p50 | cold p50/p90/p99 | warm p50/p90/p99 | remove p50/p90/p99 | CPU ms/test |")
out("|---|---|---|---|---|---|---|---|---|")
seq = {k: load(f"{k}-seq.json") for k, _ in ENG}
f3 = lambda d: f"{d['p50']:.3f} / {d['p90']:.3f} / {d['p99']:.3f}"
for p in PROTOS:
    for key, name in ENG:
        s = seq[key]["per_proto"][p]
        out(f"| {p} | {name} | {s['ok']}/{s['n']} | {f3(s['create_ms'])} | {s['dial_ms']['p50']:.3f} | {f3(s['cold_ms'])} | {f3(s['warm_ms'])} | {f3(s['remove_ms'])} | {s['cpu_ms_per_test']:.3f} |")
out()
for key, name in ENG:
    s = seq[key]["per_proto"]
    nr = sum(v["warm_not_reused"] for v in s.values())
    errs = {p: v["errors"] for p, v in s.items() if v["errors"]}
    out(f"{name}: warm GET not on the reused connection: {nr}; errors: {errs or 'none'}")
out()

# concurrency
out("### Concurrency, 32 workers x 50 iterations, mixed protocols\n")
out("| engine | ok | wall | tests/s | CPU user+sys | CPU ms/test | avg cores | peak RSS (VmHWM) | goroutines before / right after / after GC+2 s | cold p50/p90/p99 under load |")
out("|---|---|---|---|---|---|---|---|---|---|")
for key, name in ENG:
    c = load(f"{key}-conc.json")
    o = c["overall"]
    out(f"| {name} | {o['ok']}/{o['n']} | {c['wall_ms'] / 1000:.2f} s | {c['tests_per_sec']:.0f} | {c['cpu_ms'] / 1000:.2f} s | {c['cpu_ms_per_test']:.2f} | {c['cpu_cores_avg']:.2f} | {mb(c['peak_rss_kb_vmhwm'])} MiB | {c['before']['goroutines']} / {c['after_immediate']['goroutines']} / {c['after_gc_settle']['goroutines']} | {f3(o['cold_ms'])} |")
out()
for key, name in ENG:
    c = load(f"{key}-conc.json")
    out(f"{name} conc errors: {c['overall']['errors'] or 'none'}; per protocol cold p50: " + ", ".join(f"{p} {c['per_proto'][p]['cold_ms']['p50']:.2f}" for p in PROTOS))
out()

# leaks
out("### Leaks: 2000 bare create/remove cycles, then 2000 full tests (each snapshot after runtime.GC() and 2 s settle)\n")
out("| engine | snapshot | RSS MiB | heap alloc KiB | heap objects | goroutines | fds |")
out("|---|---|---|---|---|---|---|")
for key, name in ENG:
    l = load(f"{key}-leak.json")
    for snap in ["snap_after_start", "snap_after_warmup60", "snap_after_bare_create_remove", "snap_after_full_tests", "snap_after_free_os_memory"]:
        s = l[snap]
        out(f"| {name} | {snap.replace('snap_', '')} | {mb(s['rss_kb'])} | {s['heap_alloc_kb']} | {s['heap_objects']} | {s['goroutines']} | {s['fds']} |")
out()
for key, name in ENG:
    l = load(f"{key}-leak.json")
    out(f"{name}: bare cycles {l['cycles']} in {l['bare_wall_ms']:.0f} ms (fail {l['bare_fail']} {l['bare_err']}); full tests in {l['full_wall_ms']:.0f} ms (fail {l['full_fail']})")
out()

# errors
out("### Correctness: wrong credentials (3 trials each, 5 s timeout)\n")
out("| case | engine | result | ms to error (min / p50 / max) | timeouts | stage | error text |")
out("|---|---|---|---|---|---|---|")
errs = {k: {(c["proto"], c["variant"]): c for c in load(f"{k}-errors.json")["cases"]} for k, _ in ENG}
for case in errs["sbprobe"]:
    for key, name in ENG:
        c = errs[key][case]
        d = c["ms_to_result"]
        bad = [s for s in c["samples"] if not s["ok"]]
        stage = ", ".join(sorted({s["stage"] for s in bad})) or "-"
        texts = sorted({re.sub(r"127\.0\.0\.1:\d+->", "127.0.0.1:<port>->", s["err"]) for s in bad})
        text = " / ".join(texts).replace("|", "/") or "-"
        res = f"{c['ok']}/{c['trials']} ok"
        out(f"| {case[0]} {case[1]} | {name} | {res} | {d['min']:.1f} / {d['p50']:.1f} / {d['max']:.1f} | {c['timeouts']} | {stage} | {text} |")
out()

# urltest
out("### URLTest helper, 5 runs per protocol (fresh outbound each run)\n")
out("| protocol | engine | reported ms | wall ms | errors |")
out("|---|---|---|---|---|")
for p in PROTOS:
    for key, name in ENG:
        runs = [r for r in load(f"{key}-urltest.json")["runs"] if r["proto"] == p]
        rep = ", ".join(str(r.get("reported_ms")) for r in runs)
        wall = ", ".join(f"{r['wall_ms']:.1f}" for r in runs)
        e = sorted({r["err"] for r in runs if r.get("err")})
        out(f"| {p} | {name} | {rep} | {wall} | {'; '.join(e) or '-'} |")


# follow-ups
F = "out/followup"
R = "out/repeat"
if os.path.isdir(F):
    out()
    out("### Follow-up: leak attribution, 300 full tests per protocol, then 45 s linger with GC every 5 s\n")
    out("| engine | protocol | goroutines (after warmup / after 300 / after linger) | fds | heap alloc KiB | RSS MiB |")
    out("|---|---|---|---|---|---|")
    for key, name in ENG:
        for p in PROTOS:
            d = json.load(open(f"{F}/{key}-leak-{p}.json"))
            a, b, c = d["snap_after_warmup60"], d["snap_after_full_tests"], d["snap_after_linger"]
            g = lambda k: f"{a[k]} / {b[k]} / {c[k]}"
            out(f"| {name} | {p} | {g('goroutines')} | {g('fds')} | {g('heap_alloc_kb')} | {mb(a['rss_kb'])} / {mb(b['rss_kb'])} / {mb(c['rss_kb'])} |")
    out()
    out("### Follow-up: public reality destination (www.apple.com:443), 2 rounds x 5 trials, engines alternated\n")
    out("| engine | case | ok | timeouts | ms to result min / p50 / max | error text |")
    out("|---|---|---|---|---|---|")
    for key, name in ENG:
        agg = {}
        for r in (1, 2):
            for c in json.load(open(f"{F}/{key}-public-{r}.json"))["cases"]:
                agg.setdefault(c["variant"], []).extend(c["samples"])
        for v, ss in agg.items():
            t = [s.get("to_error_ms") or (s["create_ms"] + s["cold_ms"]) for s in ss]
            ok = sum(s["ok"] for s in ss)
            to = sum(bool(s.get("timed_out")) for s in ss)
            errs = sorted({s.get("err", "") for s in ss if not s["ok"]})
            out(f"| {name} | {v} | {ok}/{len(ss)} | {to} | {min(t):.1f} / {statistics.median(t):.1f} / {max(t):.1f} | {' / '.join(errs) or '-'} |")
if os.path.isdir(R):
    out()
    out("### Repeats: concurrency 3 runs each (32 x 50), all six protocols and the five without tuic\n")
    out("| mix | engine | tests/s (3 runs) | CPU ms/test | peak RSS VmHWM MiB | goroutines after GC+2 s | ok | cold p50 / p99 ms |")
    out("|---|---|---|---|---|---|---|---|")
    for kind in ["all", "notuic"]:
        for key, name in ENG:
            rows = [json.load(open(f"{R}/{key}-conc-{kind}-{i}.json")) for i in (1, 2, 3)]
            j = lambda f: ", ".join(f(r) for r in rows)
            cpu = j(lambda r: "%.2f" % r["cpu_ms_per_test"])
            cold = j(lambda r: "%.1f/%.0f" % (r["overall"]["cold_ms"]["p50"], r["overall"]["cold_ms"]["p99"]))
            tps = j(lambda r: str(round(r["tests_per_sec"])))
            hwm = j(lambda r: mb(r["peak_rss_kb_vmhwm"]))
            gor = j(lambda r: str(r["after_gc_settle"]["goroutines"]))
            okk = j(lambda r: str(r["overall"]["ok"]))
            out(f"| {kind} | {name} | {tps} | {cpu} | {hwm} | {gor} | {okk} | {cold} |")
    out()
    out("### Repeats: sequential, 2 more runs each (cold p50 ms / cold p99 ms / CPU ms per test)\n")
    out("| engine | run | " + " | ".join(PROTOS) + " |")
    out("|---|---|" + "---|" * len(PROTOS))
    for key, name in ENG:
        for i in (1, 2):
            d = json.load(open(f"{R}/{key}-seq-{i}.json"))["per_proto"]
            out(f"| {name} | {i} | " + " | ".join(f"{d[p]['cold_ms']['p50']:.3f} / {d[p]['cold_ms']['p99']:.2f} / {d[p]['cpu_ms_per_test']:.2f}" for p in PROTOS) + " |")
