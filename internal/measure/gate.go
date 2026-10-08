package measure

import (
	"net"
	"sync"
)

// writeFirstConn holds back the first Read until the first Write has
// returned. Several clients finish their lazy handshake inside the first
// Write and only then record what the server's reply is checked against
// (shadowsocks 2022 stores its request salt after the write), while
// net/http reads and writes on separate goroutines. On a fast path the
// reply can arrive before that bookkeeping is done and fail a working
// line. Every measurement here writes first, so waiting costs nothing.
type writeFirstConn struct {
	net.Conn
	once    sync.Once
	written chan struct{}
}

func writeFirst(c net.Conn) net.Conn {
	return &writeFirstConn{Conn: c, written: make(chan struct{})}
}

func (c *writeFirstConn) open() { c.once.Do(func() { close(c.written) }) }

func (c *writeFirstConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.open()
	return n, err
}

func (c *writeFirstConn) Read(p []byte) (int, error) {
	<-c.written
	return c.Conn.Read(p)
}

func (c *writeFirstConn) Close() error {
	c.open()
	return c.Conn.Close()
}
