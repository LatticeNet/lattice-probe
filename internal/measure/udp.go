package measure

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// udpRetry is how long the first DNS query waits before it is sent once
// more, so a single lost datagram does not fail the measure.
const udpRetry = 1500 * time.Millisecond

// UDPDNS sends a DNS query for name over UDP to server through d's
// ListenPacket and returns the round trip of the query that was answered.
func UDPDNS(ctx context.Context, d N.Dialer, server, name string) (time.Duration, error) {
	dest := M.ParseSocksaddr(server)
	pc, err := d.ListenPacket(ctx, dest)
	if err != nil {
		return 0, err
	}
	// Closing the conn is the one way to unblock a read that every packet
	// conn implementation honours, whatever it does with deadlines.
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()

	type answer struct {
		id  uint16
		at  time.Time
		err error
	}
	answers := make(chan answer, 4)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFrom(buf)
			var a answer
			if err != nil {
				a.err = err
			} else {
				var msg dns.Msg
				if msg.Unpack(buf[:n]) != nil || !msg.Response {
					continue
				}
				a.id, a.at = msg.Id, time.Now()
			}
			select {
			case answers <- a:
			default:
			}
			if err != nil {
				return
			}
		}
	}()

	sent := make(map[uint16]time.Time, 2)
	send := func() error {
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(name), dns.TypeA)
		packet, err := query.Pack()
		if err != nil {
			return err
		}
		sent[query.Id] = time.Now()
		if _, err := pc.WriteTo(packet, dest); err != nil {
			return fmt.Errorf("send DNS query: %w", err)
		}
		return nil
	}
	if err := send(); err != nil {
		return 0, err
	}
	retry := time.NewTimer(udpRetry)
	defer retry.Stop()
	resent := false
	for {
		select {
		case a := <-answers:
			if a.err != nil {
				if ctx.Err() != nil {
					return 0, errors.New("no DNS answer over UDP before the deadline")
				}
				return 0, fmt.Errorf("read DNS answer: %w", a.err)
			}
			if at, ok := sent[a.id]; ok {
				return a.at.Sub(at), nil
			}
		case <-retry.C:
			if !resent {
				resent = true
				if err := send(); err != nil {
					return 0, err
				}
			}
		case <-ctx.Done():
			return 0, errors.New("no DNS answer over UDP before the deadline")
		}
	}
}
