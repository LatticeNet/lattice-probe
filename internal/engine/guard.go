package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/policy"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// guardType is the internal outbound every probed outbound detours to. It
// is registered on the probe's own registry and is not an allowed request
// type, so a request can neither create it nor point a detour at it.
const guardType = "lattice-guard"

const (
	guardResolveTimeout = 5 * time.Second
	guardDialTimeout    = 10 * time.Second
)

// guardOptions carries the per-request state. It is only ever built in Go;
// decoded from JSON it is empty and the constructor refuses it.
type guardOptions struct {
	state *guardState
}

// guardState is the single place a probed outbound reaches the network.
// It resolves names itself, refuses any address the policy refuses, and
// checks again inside the socket's Control hook with the exact address the
// kernel is about to connect to. The address dialled is therefore always
// one that passed the check, whatever a name resolves to later.
type guardState struct {
	policy   *policy.Policy
	resolver policy.Resolver
	dialer   net.Dialer

	mu      sync.Mutex
	hosts   map[string][]netip.Addr // names resolved by this request, already checked
	refused *policy.Refusal         // first refusal of this request
}

func newGuardState(p *policy.Policy, r policy.Resolver) *guardState {
	st := &guardState{policy: p, resolver: r, hosts: make(map[string][]netip.Addr)}
	st.dialer = net.Dialer{Timeout: guardDialTimeout, Control: st.control}
	return st
}

// Refused returns the first address this request was refused, if any.
func (st *guardState) Refused() *policy.Refusal {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.refused
}

func (st *guardState) refuse(r *policy.Refusal) error {
	r.DialTime = true
	st.mu.Lock()
	if st.refused == nil {
		st.refused = r
	}
	st.mu.Unlock()
	return r
}

// control runs after the socket exists and before connect(2), with the
// numeric address being connected.
func (st *guardState) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return st.refuse(&policy.Refusal{Reason: "not a numeric address: " + address})
	}
	if r := st.policy.Check(ap.Addr()); r != nil {
		return st.refuse(r)
	}
	return nil
}

// resolve returns the checked addresses of dest, IPv4 first. A name is
// refused whole when any of its addresses is refused.
func (st *guardState) resolve(ctx context.Context, dest M.Socksaddr) ([]netip.Addr, error) {
	if dest.IsIP() {
		a := dest.Addr.Unmap()
		if r := st.policy.Check(a); r != nil {
			return nil, st.refuse(r)
		}
		return []netip.Addr{a}, nil
	}
	if !dest.IsFqdn() {
		return nil, errors.New("no destination address")
	}
	host := strings.ToLower(strings.TrimSuffix(dest.Fqdn, "."))
	st.mu.Lock()
	cached, ok := st.hosts[host]
	st.mu.Unlock()
	if ok {
		return cached, nil
	}
	ctx, cancel := context.WithTimeout(ctx, guardResolveTimeout)
	defer cancel()
	found, err := st.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	checked := make([]netip.Addr, 0, len(found))
	for _, a := range found {
		a = a.Unmap()
		if r := st.policy.Check(a); r != nil {
			r.Host = host
			return nil, st.refuse(r)
		}
		checked = append(checked, a)
	}
	sort.SliceStable(checked, func(i, j int) bool { return checked[i].Is4() && !checked[j].Is4() })
	st.mu.Lock()
	st.hosts[host] = checked
	st.mu.Unlock()
	return checked, nil
}

// dial connects to dest over TCP or connected UDP, trying the checked
// addresses in order.
func (st *guardState) dial(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	addrs, err := st.resolve(ctx, dest)
	if err != nil {
		return nil, err
	}
	nw := "tcp"
	if N.NetworkName(network) == N.NetworkUDP {
		nw = "udp"
	}
	var first error
	for _, a := range addrs {
		conn, err := st.dialer.DialContext(ctx, nw, netip.AddrPortFrom(a, dest.Port).String())
		if err == nil {
			return conn, nil
		}
		if first == nil {
			first = err
		}
		if ctx.Err() != nil || st.Refused() != nil {
			break
		}
	}
	return nil, first
}

// listenPacket opens an unconnected UDP socket whose every write is
// checked, so a protocol that sends to more than one address (port
// hopping, a SOCKS relay address) still only reaches checked ones.
func (st *guardState) listenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	if _, err := st.resolve(ctx, dest); err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", "")
	if err != nil {
		return nil, err
	}
	return &guardPacketConn{PacketConn: pc, st: st}, nil
}

// guardPacketConn embeds only the net.PacketConn interface, so nothing
// above it can reach the raw *net.UDPConn and its unchecked write methods.
type guardPacketConn struct {
	net.PacketConn
	st *guardState
}

func (c *guardPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dest := M.SocksaddrFromNet(addr)
	ctx, cancel := context.WithTimeout(context.Background(), guardResolveTimeout)
	defer cancel()
	addrs, err := c.st.resolve(ctx, dest)
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrs[0], dest.Port)))
}

type guardOutbound struct {
	outbound.Adapter
	st *guardState
}

func newGuard(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options guardOptions) (adapter.Outbound, error) {
	if options.state == nil {
		return nil, errors.New("outbound type " + guardType + " is internal to the probe")
	}
	return &guardOutbound{
		Adapter: outbound.NewAdapter(guardType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		st:      options.state,
	}, nil
}

func (g *guardOutbound) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	return g.st.dial(ctx, network, dest)
}

func (g *guardOutbound) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return g.st.listenPacket(ctx, dest)
}
