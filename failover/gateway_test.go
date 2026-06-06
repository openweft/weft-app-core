package failover

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openweft/weft-app-core/transport"
)

// liveBackend dials a real TCP server (an httptest-style listener) and is
// togglable so we can simulate a DC going away.
type liveBackend struct {
	mu   sync.Mutex
	addr string
	up   bool
}

func (l *liveBackend) set(addr string, up bool) { l.mu.Lock(); l.addr, l.up = addr, up; l.mu.Unlock() }
func (l *liveBackend) Probe(ctx context.Context) error {
	c, err := l.Dial(ctx)
	if err != nil {
		return err
	}
	return c.Close()
}
func (l *liveBackend) Dial(ctx context.Context) (net.Conn, error) {
	l.mu.Lock()
	addr, up := l.addr, l.up
	l.mu.Unlock()
	if !up {
		return nil, errors.New("down")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}
func (l *liveBackend) Target() string { return "live" }
func (l *liveBackend) Close() error   { return nil }

// startEcho starts an HTTP server that replies with `body` and returns
// its addr + a stop func.
func startEcho(t *testing.T, body string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	})}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close() }
}

func httpGet(t *testing.T, url string) (string, error) {
	t.Helper()
	// DisableKeepAlives: every GET opens a fresh connection to the
	// gateway, so we exercise its per-connection routing to the *current*
	// active DC. (A kept-alive connection stays pinned to the DC it first
	// landed on — the intended single-origin seam, but not what this test
	// asserts.)
	c := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Scan()
	return sc.Text(), nil
}

// TestGatewayProxiesActiveAndFailsOver is the end-to-end seam : two echo
// servers stand in for two DCs, the Gateway exposes one stable loopback
// origin, and a GET through it lands on whichever DC the Supervisor has
// active — before and after a failover.
func TestGatewayProxiesActiveAndFailsOver(t *testing.T) {
	addrA, stopA := startEcho(t, "served-by-A")
	defer stopA()
	addrB, stopB := startEcho(t, "served-by-B")
	defer stopB()

	ba := &liveBackend{}
	ba.set(addrA, true)
	bb := &liveBackend{}
	bb.set(addrB, true)

	now := time.Unix(0, 0)
	s := New(
		[]transport.Endpoint{{Name: "A", Backend: ba}, {Name: "B", Backend: bb}},
		Options{HoldDown: time.Hour, Now: func() time.Time { return now }},
	)
	s.round(context.Background()) // -> A

	gw, err := NewGateway(s, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gw.Serve(ctx)

	if got, err := httpGet(t, gw.URL()); err != nil || got != "served-by-A" {
		t.Fatalf("via gateway = %q, %v; want served-by-A", got, err)
	}

	// A goes down; Supervisor fails over to B. The Gateway origin is
	// unchanged, so the very same URL now reaches B.
	ba.set(addrA, false)
	now = now.Add(time.Second)
	s.round(context.Background())
	if name := func() string { ep, _ := s.Active(); return ep.Name }(); name != "B" {
		t.Fatalf("after A down, active=%q want B", name)
	}
	if got, err := httpGet(t, gw.URL()); err != nil || got != "served-by-B" {
		t.Fatalf("via gateway after failover = %q, %v; want served-by-B", got, err)
	}
}

func TestGatewayDropsWhenAllDown(t *testing.T) {
	b := &liveBackend{} // never up
	now := time.Unix(0, 0)
	s := New([]transport.Endpoint{{Name: "A", Backend: b}}, Options{Now: func() time.Time { return now }})
	s.round(context.Background())

	gw, err := NewGateway(s, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gw.Serve(ctx)

	if _, err := httpGet(t, gw.URL()); err == nil {
		t.Fatal("expected error when all DCs down, got nil")
	}
}
