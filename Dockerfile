# syntax=docker/dockerfile:1.7

# The probe is pure Go with cgo off, so the build stage runs on the
# builder's own platform and cross-compiles: a multi-arch image needs no
# emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG GOPROXY=https://proxy.golang.org,direct
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# VERSION is the release without the leading v; empty keeps the version
# compiled into internal/spec.
ARG VERSION=
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -trimpath \
      -tags with_quic,with_utls \
      -ldflags "-s -w ${VERSION:+-X github.com/LatticeNet/lattice-probe/internal/spec.Version=${VERSION}}" \
      -o /out/ ./cmd/lattice-probe ./cmd/probectl \
 && mkdir -p /out/run/lattice-probe

# distroless static: CA certificates, /etc/passwd with uid 65532, no shell.
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=
ARG COMMIT=unknown
COPY --from=build /out/lattice-probe /out/probectl /usr/local/bin/
# The socket directory is normally a volume shared with lattice-server; it
# exists here so the image also runs with a read-only root and no volume.
COPY --from=build --chown=65532:65532 /out/run/lattice-probe /run/lattice-probe
USER 65532:65532
ENV LATTICE_PROBE_SOCKET=/run/lattice-probe/probe.sock
LABEL org.opencontainers.image.title="Lattice Probe" \
      org.opencontainers.image.description="Tests pasted proxy outbounds in one long-lived sing-box instance" \
      org.opencontainers.image.source="https://github.com/LatticeNet/lattice-probe" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/probectl", "-health"]
ENTRYPOINT ["/usr/local/bin/lattice-probe"]
