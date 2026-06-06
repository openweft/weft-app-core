package failover

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
)

// Gateway is a loopback TCP listener that proxies every accepted
// connection to whichever DC the Supervisor currently considers active.
//
// This is what makes failover seamless to the WebView : the app points
// the WebView at the Gateway's single, stable loopback origin
// (http://127.0.0.1:<port>) and never changes it. When a DC dies the
// Supervisor re-selects under the Gateway; the next connection the
// WebView opens lands on the new DC. Because the origin never changes,
// the SPA's cookies, OIDC session and in-memory state all survive — the
// only visible effect is the in-flight requests that were cut, which the
// SPA's own retry re-issues against the (now healthy) origin.
//
// The transport underneath (SSH / WireGuard) provides confidentiality
// and authentication, so the proxied protocol is plain HTTP and the
// loopback origin needs no TLS — sidestepping the certificate-name
// mismatch that raw TLS pass-through would hit on 127.0.0.1.
type Gateway struct {
	sup *Supervisor
	ln  net.Listener

	mu     sync.Mutex
	closed bool
}

// NewGateway binds a loopback listener. Pass addr "127.0.0.1:0" to let
// the OS pick a free port (read it back with URL/Addr). The Supervisor
// should be Run separately.
func NewGateway(sup *Supervisor, addr string) (*Gateway, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("gateway listen %s: %w", addr, err)
	}
	return &Gateway{sup: sup, ln: ln}, nil
}

// Addr is the bound loopback address, e.g. "127.0.0.1:54123".
func (g *Gateway) Addr() string { return g.ln.Addr().String() }

// URL is the origin to hand the WebView.
func (g *Gateway) URL() string { return "http://" + g.Addr() }

// Serve accepts connections until ctx is cancelled or the Gateway is
// closed. Blocks; run in its own goroutine.
func (g *Gateway) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		g.Close()
	}()
	for {
		client, err := g.ln.Accept()
		if err != nil {
			g.mu.Lock()
			closed := g.closed
			g.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go g.handle(ctx, client)
	}
}

// handle proxies one client connection to the active DC backend.
func (g *Gateway) handle(ctx context.Context, client net.Conn) {
	defer client.Close()

	ep, ok := g.sup.Active()
	if !ok {
		// All DCs down — drop the connection. The WebView surfaces a
		// connection error and the SPA banner (driven by OnSwitch ->
		// __weftFailoverNotice) tells the user. Nothing useful to proxy.
		return
	}

	upstream, err := ep.Backend.Dial(ctx)
	if err != nil {
		return
	}
	defer upstream.Close()

	// Bidirectional copy; wait for both directions to finish so we don't
	// truncate an in-flight transfer when one side closes first.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, client)
		if tc, ok := upstream.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-ctx.Done():
			return
		}
	}
}

// Close stops accepting and unblocks Serve.
func (g *Gateway) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	g.mu.Unlock()
	return g.ln.Close()
}
