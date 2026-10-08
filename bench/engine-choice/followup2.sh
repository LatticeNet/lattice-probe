#!/bin/bash
# Repeats for variance: conc x3 (all protocols, and without tuic), seq x2.
set -u
B=/bench/bin; O=/bench/out/repeat; S=/bench/server
mkdir -p "$O"
$B/benchaux setup $S >/dev/null
$B/benchaux serve $S & AUX=$!
$B/sing-box run -c $S/server.json > "$O/server.log" 2>&1 & SRV=$!
sleep 2
for i in 1 2 3; do
  for e in sbprobe mhprobe; do
    $B/$e conc -out "$O/$e-conc-all-$i.json"; sleep 2
    $B/$e conc -only ss,vmess_ws,vless_reality,trojan_tls,hysteria2 -out "$O/$e-conc-notuic-$i.json"; sleep 2
  done
done
for i in 1 2; do
  for e in mhprobe sbprobe; do $B/$e seq -out "$O/$e-seq-$i.json"; sleep 2; done
done
kill $SRV $AUX; wait 2>/dev/null
