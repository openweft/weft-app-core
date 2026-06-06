// Package transport models the authenticated paths a client app uses
// to reach a datacenter's weft-webui.
//
// The desktop apps never point a WebView straight at a public weft-webui
// listener — the platform deliberately runs no worldwide web service.
// Instead every datacenter exposes its weft-webui only on a private
// address (its WireGuard mesh IP, or behind SSH on a host), and the app
// reaches it through a Backend : something that can both probe a DC for
// health and dial a raw connection to its webui.
//
// A Backend is transport-agnostic on purpose. The failover Supervisor
// only ever asks two things of it — "are you healthy?" and "give me a
// connection" — so DirectTCP, SSHForward and WireGuard are
// interchangeable from its point of view.
package transport

import (
	"context"
	"net"
	"time"
)

// Endpoint is one datacenter's weft-webui, named for the UI banner.
type Endpoint struct {
	// Name is the technical ID — propagated to logs, known-hosts,
	// metrics — and the fallback label when DisplayName is empty.
	Name string
	// DisplayName is the operator-facing label (Topbar chip, menubar
	// title, tray submenu). Empty = fall back to Name.
	DisplayName string
	// Backend is the transport used to reach this DC's webui.
	Backend Backend
}

// Label returns the operator-facing name : DisplayName when set,
// Name otherwise. Centralised so the menubar, tray, control server
// and webinject all derive the chip text the same way.
func (e Endpoint) Label() string {
	if e.DisplayName != "" {
		return e.DisplayName
	}
	return e.Name
}

// Backend reaches a single datacenter's weft-webui.
//
// Dial returns a connection to the webui's HTTP(S) listener. The
// loopback Gateway proxies WebView bytes over whatever Dial returns, so
// the transport (TCP / SSH channel / WireGuard tunnel) is invisible
// above this line.
//
// Probe reports whether the DC is currently reachable and serving. It
// must be cheap and bounded by the context deadline — the Supervisor
// calls it on a timer for every endpoint.
type Backend interface {
	Dial(ctx context.Context) (net.Conn, error)
	Probe(ctx context.Context) error
	// Target is a stable, log-friendly description of where this backend
	// points (e.g. "10.80.0.11:8443" or "ssh://bastion-a/127.0.0.1:8443").
	Target() string
	// Close releases any long-lived resources (an SSH client, a tunnel).
	Close() error
}

// DirectTCP dials a webui listener over plain TCP. Used when the app
// already shares the DC's network — e.g. an operator on the mesh, or in
// tests. It performs no authentication of its own : the network itself
// (WireGuard, a VPN, localhost) is the boundary.
type DirectTCP struct {
	// Addr is "host:port" of the weft-webui listener.
	Addr string
	// TLS, when true, the webui speaks HTTPS on Addr. Informational only —
	// the Gateway streams bytes verbatim either way — but Probe uses it to
	// decide how to health-check.
	TLS bool
	// DialTimeout bounds a single Dial / Probe. Zero means 5s.
	DialTimeout time.Duration
}

func (d *DirectTCP) timeout() time.Duration {
	if d.DialTimeout <= 0 {
		return 5 * time.Second
	}
	return d.DialTimeout
}

func (d *DirectTCP) Dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.timeout()}
	return dialer.DialContext(ctx, "tcp", d.Addr)
}

// Probe opens and immediately closes a TCP connection. A successful
// handshake is taken as "the listener is up" ; the Gateway + the SPA's
// own retry handle finer-grained HTTP errors.
func (d *DirectTCP) Probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout())
	defer cancel()
	conn, err := d.Dial(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (d *DirectTCP) Target() string { return d.Addr }
func (d *DirectTCP) Close() error   { return nil }
