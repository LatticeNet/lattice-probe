# Benchmarks

## probebench

Measures this engine against a local lab: UDP relay, throughput, the server check and memory, per protocol. The lab and the engine run in separate processes so the engine's memory is measured alone; memory figures come from `/proc` and are reported on Linux only.

```sh
go build -tags with_quic,with_utls -o probebench ./bench/probebench
./probebench lab -out lab.json &
./probebench run -lab lab.json -n 20 > report.json
```

Run it inside a container with the deployment's limits (`--cpus 0.5 --memory 128m`) to see the numbers hkg will see.

## engine-choice

The 2026-10-08 benchmark that chose sing-box over mihomo for design 27: both cores embedded the way the probe uses them and driven by one shared harness. `RESULTS.md` is the write-up and `tables.md` the generated tables. The programs are separate Go modules (`harness`, `sbprobe`, `mhprobe`) and are not part of this module's build; `build.sh` and `run.sh` expect the layout described at the end of `RESULTS.md`. The raw JSON, the built binaries and the generated throwaway keys stayed with the run and are not in this repository.
