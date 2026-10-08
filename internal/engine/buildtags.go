//go:build !(with_quic && with_utls)

package engine

// The probe needs QUIC (hysteria, hysteria2, tuic) and uTLS (reality)
// compiled into sing-box. A build without them would refuse those
// protocols at create time and report a working line as invalid, so the
// build fails here instead. Build and test with -tags with_quic,with_utls.
var _ = lattice_probe_requires_build_tags_with_quic_and_with_utls
