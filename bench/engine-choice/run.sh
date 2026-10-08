#!/bin/bash
# Runs inside the --cpus 2 --memory 4g container. Usage: run.sh smoke|full
set -u
MODE=${1:-full}
B=/bench/bin; O=/bench/out/$MODE; S=/bench/server
mkdir -p "$O"
srvcpu() { awk '{print $14+$15}' /proc/$SRV/stat; }  # clock ticks (100/s)
note() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$O/run.log"; }

$B/benchaux setup $S >/dev/null
$B/benchaux serve $S & AUX=$!
$B/sing-box run -c $S/server.json > "$O/server.log" 2>&1 & SRV=$!
sleep 2
kill -0 $SRV || { echo "server died"; cat "$O/server.log"; exit 1; }
note "arch=$(uname -m) nproc=$(nproc) cgroup_cpu=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null) cgroup_mem=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)"
ls -l $B >> "$O/run.log"

run() { # engine mode extra...
  local e=$1 m=$2; shift 2
  local c0; c0=$(srvcpu)
  local t0; t0=$(date +%s%N)
  $B/$e $m -out "$O/$e-$m.json" "$@" 2>>"$O/$e-$m.stderr"
  local rc=$?
  note "$e $m rc=$rc wall_s=$(( ($(date +%s%N)-t0)/1000000 ))ms server_cpu_ticks=$(( $(srvcpu)-c0 ))"
}

if [ "$MODE" = smoke ]; then
  for e in sbprobe mhprobe; do
    run $e seq -n 3
    run $e errors -trials 1
  done
else
  for i in $(seq 1 10); do
    for e in sbprobe mhprobe; do
      BENCH_T0=$(date +%s%N) $B/$e start -out "$O/$e-start-$i.json" 2>>"$O/$e-start.stderr"
    done
  done
  note "start x10 done"
  for m in errors urltest seq conc leak; do
    for e in sbprobe mhprobe; do run $e $m; sleep 3; done
  done
fi
kill $SRV $AUX 2>/dev/null
wait 2>/dev/null
note "done"
