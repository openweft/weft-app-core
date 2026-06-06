package shell

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewRejectsEmpty(t *testing.T) {
	if _, err := New(Config{}, Options{}); err == nil {
		t.Fatal("expected error for empty endpoint list")
	}
}

func TestBuildBackendValidation(t *testing.T) {
	cases := []struct {
		name string
		ec   EndpointConfig
	}{
		{"direct-no-addr", EndpointConfig{Kind: Direct}},
		{"ssh-missing-fields", EndpointConfig{Kind: SSH, SSHAddr: "h:22"}},
		{"wg-no-dialer", EndpointConfig{Kind: WireGuard, Addr: "h:1"}},
		{"unknown-kind", EndpointConfig{Kind: "carrier-pigeon", Addr: "h:1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildBackend(c.ec, Options{}); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

// TestShellEndToEndDirect stands up a real HTTP server as the "DC",
// configures a Direct endpoint, and verifies the Shell's gateway origin
// proxies to it and the init script advertises that origin.
func TestShellEndToEndDirect(t *testing.T) {
	ln, _ := startServer(t, "ok-from-dc")
	defer ln.Close()

	sh, err := New(Config{
		GatewayAddr: "127.0.0.1:0",
		Endpoints: []EndpointConfig{
			{Name: "DC-A", Kind: Direct, Addr: ln.Addr().String()},
		},
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sh.Run(ctx)

	// Wait for the first probe round to select the DC.
	if !waitActive(sh, time.Second) {
		t.Fatal("no DC became active")
	}

	body := httpGet(t, sh.URL())
	if body != "ok-from-dc" {
		t.Fatalf("gateway body = %q", body)
	}

	if s := sh.InitScript(); !strings.Contains(s, "__WEFT_ENDPOINTS__") || !strings.Contains(s, sh.URL()) {
		t.Fatalf("init script missing origin: %s", s)
	}

	st := sh.Status()
	if len(st) != 1 || st[0].Name != "DC-A" {
		t.Fatalf("status = %+v", st)
	}
}

func waitActive(sh *Shell, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, s := range sh.Status() {
			if s.Active {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func startServer(t *testing.T, body string) (net.Listener, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})}
	go srv.Serve(l)
	return l, func() { srv.Close() }
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	c := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
