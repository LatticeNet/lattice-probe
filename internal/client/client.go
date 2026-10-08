// Package client talks to a running lattice-probe over its unix socket. It
// serves probectl and the daemon's own -health check.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/spec"
)

// Client is an HTTP client bound to one socket path.
type Client struct {
	http *http.Client
}

// New returns a client for the socket at path; timeout bounds each call.
func New(path string, timeout time.Duration) *Client {
	return &Client{http: &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}}
}

// Health reads GET /v1/health.
func (c *Client) Health() (*spec.Health, error) {
	resp, err := c.http.Get("http://probe/v1/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health answered %d", resp.StatusCode)
	}
	var h spec.Health
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Probe sends POST /v1/probe. A refusal comes back as *spec.RequestError.
func (c *Client) Probe(req *spec.Request) (*spec.Result, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Post("http://probe/v1/probe", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e spec.ErrorBody
		if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
			return nil, &spec.RequestError{Stage: e.Error.Stage, Message: fmt.Sprintf("%s (HTTP %d)", e.Error.Message, resp.StatusCode)}
		}
		return nil, fmt.Errorf("probe answered %d", resp.StatusCode)
	}
	var res spec.Result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
