package engine

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func itoa(n int) string { return strconv.Itoa(n) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func splitHostPort(t testing.TB, addr string) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return host, n
}

// closedPort returns a loopback port nothing listens on.
func closedPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}

// countingListener listens on loopback and counts accepted connections.
func countingListener(t testing.TB) (string, func() int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), n.Load
}
