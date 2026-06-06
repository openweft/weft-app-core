package transport

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DialContextFunc dials a "host:port" over some network. It matches the
// signature exposed by a userspace WireGuard netstack
// (golang.zx2c4.com/wireguard/tun/netstack's Net.DialContext) as well as
// net.Dialer.DialContext, so either can back a WireGuard endpoint.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// WireGuard reaches a DC's weft-webui across the cluster WireGuard mesh,
// of which the device is a userspace peer. weft-app-core stays free of
// the (large, cgo-adjacent) wireguard-go dependency by taking the mesh
// dialer as a function : the app brings up the netstack tunnel once and
// hands its DialContext here.
//
// The webui listener binds the mesh interface only, so this transport —
// like SSHForward — means the platform exposes no public web service.
type WireGuard struct {
	// Mesh is the mesh dialer (wireguard-go netstack's DialContext, or any
	// equivalent). Required.
	Mesh DialContextFunc
	// MeshAddr is the webui listener's mesh address, "host:port".
	MeshAddr string
	// DialTimeout bounds a single dial / probe. Zero means 5s.
	DialTimeout time.Duration
}

func (w *WireGuard) timeout() time.Duration {
	if w.DialTimeout <= 0 {
		return 5 * time.Second
	}
	return w.DialTimeout
}

func (w *WireGuard) Dial(ctx context.Context) (net.Conn, error) {
	if w.Mesh == nil {
		return nil, fmt.Errorf("wireguard backend %s: no mesh dialer configured", w.MeshAddr)
	}
	return w.Mesh(ctx, "tcp", w.MeshAddr)
}

func (w *WireGuard) Probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, w.timeout())
	defer cancel()
	conn, err := w.Dial(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (w *WireGuard) Target() string { return "wg://" + w.MeshAddr }
func (w *WireGuard) Close() error   { return nil }
