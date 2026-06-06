// Package control is the loopback IPC between a desktop app's tray
// process (which owns the failover Supervisor + Gateway) and its
// WebView process (which renders the dashboard).
//
// macOS — and, for symmetry, the other desktop apps — give a process one
// main run loop, and both the system-tray library and the WebView want
// it. The apps therefore split into two processes; this tiny HTTP server
// is how the tray tells the WebView which datacenter is currently active
// so the WebView can raise the dashboard's "connection switched" banner.
//
// It is pure Go and unit-tested here, independent of any app's cgo code.
package control

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/openweft/weft-app-core/failover"
)

// Active is the state the tray publishes and the WebView reads.
type Active struct {
	Name string `json:"name"` // technical DC name
	// Label is the operator-facing DC display name
	// (cfg.cluster.dc.display_name when set, else Name).
	Label string `json:"label,omitempty"`
	// Cluster is the technical parent-cluster name ; "" in legacy
	// single-endpoint mode.
	Cluster string `json:"cluster,omitempty"`
	// ClusterLabel is the parent cluster's display name ; "" => use
	// Cluster.
	ClusterLabel string `json:"cluster_label,omitempty"`
	AllDown      bool   `json:"allDown"`
}

// FullLabel composes "Cluster · DC" (with the right labels) when the
// endpoint carries a cluster, otherwise just the DC label. The
// dashboard seeds the Topbar chip with this string.
func (a Active) FullLabel() string {
	cl := a.ClusterLabel
	if cl == "" {
		cl = a.Cluster
	}
	dc := a.Label
	if dc == "" {
		dc = a.Name
	}
	if cl == "" {
		return dc
	}
	return cl + " · " + dc
}

// Server holds the latest active-DC state behind a loopback HTTP server.
type Server struct {
	mu      sync.RWMutex
	current Active
}

// NewServer returns an empty server (no DC active yet).
func NewServer() *Server { return &Server{} }

// Publish is wired to failover.Options.OnSwitch.
func (s *Server) Publish(sw failover.Switch) {
	s.mu.Lock()
	label := sw.ToLabel
	if label == "" {
		label = sw.ToName
	}
	s.current = Active{
		Name:         sw.ToName,
		Label:        label,
		Cluster:      sw.ToCluster,
		ClusterLabel: sw.ToClusterLabel,
		AllDown:      sw.AllDown,
	}
	s.mu.Unlock()
}

// Active returns the current state.
func (s *Server) Active() Active {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Handler serves GET /active -> Active as JSON.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/active", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(s.Active()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	return mux
}

// Listen binds a loopback listener and serves in the background until ctx
// is cancelled, returning the origin (e.g. "http://127.0.0.1:53219").
func (s *Server) Listen(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: s.Handler()}
	go srv.Serve(ln)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	return "http://" + ln.Addr().String(), nil
}

// Client polls a control server for active-DC changes. It is used by the
// WebView process; on each change it calls onChange(prev, cur) — typically
// to evaluate webinject.FailoverNotice into the WebView.
type Client struct {
	BaseURL  string
	Interval time.Duration // default 2s
	HTTP     *http.Client  // default: 3s timeout
}

// Get does a one-shot fetch of the current Active state. The dashboard
// uses it to seed the Topbar's persistent DC chip before the WebView's
// SPA paints (the Watch loop would only fire on the *next* change).
func (c *Client) Get(ctx context.Context) (Active, error) {
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 3 * time.Second}
	}
	return fetch(ctx, hc, c.BaseURL)
}

// Watch polls until ctx is cancelled, invoking onChange whenever the
// active DC name changes (including the first non-empty value).
func (c *Client) Watch(ctx context.Context, onChange func(prev, cur Active)) {
	interval := c.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 3 * time.Second}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var prev Active
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur, err := fetch(ctx, hc, c.BaseURL)
			if err != nil {
				continue
			}
			if cur != prev {
				onChange(prev, cur)
				prev = cur
			}
		}
	}
}

func fetch(ctx context.Context, hc *http.Client, base string) (Active, error) {
	var a Active
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/active", nil)
	if err != nil {
		return a, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return a, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&a)
	return a, err
}
