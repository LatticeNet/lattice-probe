#!/bin/sh
# Builds both probes, the aux helper, and the upstream sing-box server.
set -eu
export CGO_ENABLED=0 GOFLAGS=-mod=mod GOTOOLCHAIN=auto GOPROXY=https://goproxy.cn,direct
mkdir -p /bench/bin
SBTAGS=with_quic,with_utls,with_wireguard
cd /bench/sbprobe && go build -trimpath -ldflags "-s -w" -tags "$SBTAGS" -o /bench/bin/sbprobe .
cd /bench/mhprobe && go build -trimpath -ldflags "-s -w" -o /bench/bin/mhprobe .
cd /bench/harness && go build -trimpath -ldflags "-s -w" -o /bench/bin/benchaux ./cmd/benchaux
GOBIN=/bench/bin go install -trimpath -ldflags "-s -w" -tags "$SBTAGS" github.com/sagernet/sing-box/cmd/sing-box@v1.13.19
ls -l /bench/bin
