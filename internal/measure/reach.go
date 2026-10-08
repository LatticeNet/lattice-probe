package measure

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
)

// ErrNoAnswer means a QUIC server check sent its Initial and heard nothing.
var ErrNoAnswer = errors.New("no answer to a QUIC handshake")

// TCPConnect times a plain TCP connect made by dial, outside any proxy
// protocol, and closes the connection. dial should connect to an address
// that is already resolved, or the time includes the name lookup.
func TCPConnect(ctx context.Context, dial func(ctx context.Context) (net.Conn, error)) (time.Duration, error) {
	start := time.Now()
	conn, err := dial(ctx)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	conn.Close()
	return rtt, nil
}

// QUICReach starts a QUIC handshake to raddr over pc and returns the time
// from the first datagram sent to the first datagram received. Any answer
// counts, including a handshake failure, because the question is whether
// the server is there, not whether the probe could log in. pc is closed
// before QUICReach returns.
func QUICReach(ctx context.Context, pc net.PacketConn, raddr net.Addr, serverName string, alpn []string) (time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	rec := &firstAnswer{PacketConn: pc, start: time.Now(), heard: cancel}
	defer rec.Close()
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	tlsConf := &tls.Config{
		ServerName: serverName,
		NextProtos: alpn,
		MinVersion: tls.VersionTLS13,
		// Only an answer is wanted; the certificate is the outbound's
		// business and is checked when the outbound itself connects.
		InsecureSkipVerify: true, //nolint:gosec // reachability check only, no data is sent
	}
	conf := &quic.Config{}
	if deadline, ok := ctx.Deadline(); ok {
		conf.HandshakeIdleTimeout = time.Until(deadline)
	}
	conn, err := quic.Dial(ctx, rec, raddr, tlsConf, conf)
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	if rtt, ok := rec.rtt(); ok {
		return rtt, nil
	}
	if err == nil || errors.Is(err, context.Canceled) && ctx.Err() == nil {
		err = ErrNoAnswer
	}
	if IsTimeout(err) {
		err = ErrNoAnswer
	}
	return 0, err
}

// firstAnswer records when the first datagram leaves and the first one
// arrives, and cancels the handshake as soon as anything is heard.
type firstAnswer struct {
	net.PacketConn
	start time.Time
	sent  atomic.Int64
	got   atomic.Int64
	heard context.CancelFunc
	once  sync.Once
}

func (c *firstAnswer) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.sent.CompareAndSwap(0, int64(time.Since(c.start)))
	return c.PacketConn.WriteTo(p, addr)
}

func (c *firstAnswer) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && n > 0 {
		c.got.CompareAndSwap(0, int64(time.Since(c.start)))
		c.once.Do(c.heard)
	}
	return n, addr, err
}

func (c *firstAnswer) rtt() (time.Duration, bool) {
	got := c.got.Load()
	if got == 0 {
		return 0, false
	}
	return time.Duration(got - c.sent.Load()), true
}
