#!/bin/bash
# Follow-up runs: per-protocol leak attribution with a linger window, and
# more trials of the public-destination reality cases.
set -u
B=/bench/bin; O=/bench/out/followup; S=/bench/server
mkdir -p "$O"
$B/benchaux setup $S >/dev/null
$B/benchaux serve $S & AUX=$!
$B/sing-box run -c $S/server.json > "$O/server.log" 2>&1 & SRV=$!
sleep 2
for e in sbprobe mhprobe; do
  for p in ss vmess_ws vless_reality trojan_tls hysteria2 tuic; do
    $B/$e leak -only $p -cycles 300 -linger 45s -out "$O/$e-leak-$p.json" 2>>"$O/$e-leak.stderr" &
  done
done
wait %3 %4 %5 %6 %7 %8 %9 %10 %11 %12 %13 %14 2>/dev/null
echo "leak done $(date -u +%T)"
for round in 1 2; do
  for e in sbprobe mhprobe; do
    $B/$e errors -cases vless_reality:public_valid,vless_reality:public_wrong_short_id -trials 5 -out "$O/$e-public-$round.json" 2>>"$O/$e-public.stderr"
  done
done
echo "public done $(date -u +%T)"
kill $SRV $AUX; wait 2>/dev/null
