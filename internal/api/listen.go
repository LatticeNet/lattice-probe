//go:build unix

package api

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// SocketMode lets the owner and the group (lattice-server joins the probe's
// group) talk to the probe, and nobody else.
const SocketMode = 0o660

// Listen opens the unix socket at path with mode 0660. A stale socket left
// by a previous run is replaced; a live one, or a path that is not a
// socket, is an error.
func Listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			conn.Close()
			return nil, fmt.Errorf("another process is serving %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// The umask closes the window between bind(2) and chmod(2) in which the
	// socket would otherwise carry the default mode.
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, SocketMode); err != nil {
		ln.Close()
		return nil, err
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(true)
	return ln, nil
}
