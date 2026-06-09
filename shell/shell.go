// Package shell wires the pieces of weft-app-core into the one object a
// desktop app actually drives : it turns a Config into transport
// Backends, runs a failover Supervisor and a loopback Gateway, and hands
// back the single stable origin to point a WebView at.
//
// It is pure Go (stdlib + x/crypto/ssh), so the three desktop apps share
// — and test — all the non-UI logic here; their main.go is then just the
// platform's tray + WebView glue (cgo) around a Shell.
package shell

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/openweft/weft-app-core/failover"
	"github.com/openweft/weft-app-core/transport"
	"github.com/openweft/weft-app-core/webinject"
)

// TransportKind selects how a DC's webui is reached.
type TransportKind string

const (
	Direct    TransportKind = "direct"
	SSH       TransportKind = "ssh"
	WireGuard TransportKind = "wireguard"
)

// ClusterConfig is one weft cluster — a single etcd quorum. Its `dcs`
// are the (typically 3) machine rooms that host the etcd peers ;
// they're close enough (sub-millisecond RTT, same metro / 100GbE
// backbone) that the raft consensus is healthy and the failover
// Supervisor probes between them transparently. Crossing a WAN (>5ms
// RTT) means a SECOND cluster, not another DC — that's federation,
// not failover.
type ClusterConfig struct {
	// Name is the technical cluster ID — propagated to logs, metrics,
	// known-hosts. Lowercase kebab convention : "paris", "tokyo".
	Name string `json:"name"`
	// DisplayName is the operator-facing label (menubar title, chip).
	// Falls back to Name when empty. "Paris", "Tokyo".
	DisplayName string `json:"display_name,omitempty"`
	// DCs are the rooms / racks inside the cluster. Failover picks
	// across them ; the first index is most preferred.
	DCs []DCConfig `json:"dcs"`
}

// DCConfig describes one datacenter (machine room / rack) inside a
// ClusterConfig. The transport fields mirror the legacy
// EndpointConfig — only the surrounding shape changed.
type DCConfig struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"display_name,omitempty"`
	Kind        TransportKind `json:"kind"`

	// Direct / WireGuard: the webui listener address "host:port".
	Addr string `json:"addr,omitempty"`

	// SSH transport fields.
	SSHAddr        string `json:"ssh_addr,omitempty"`
	User           string `json:"user,omitempty"`
	KeyPath        string `json:"key_path,omitempty"`
	KnownHostsPath string `json:"known_hosts_path,omitempty"`
	WebUIAddr      string `json:"webui_addr,omitempty"`
	// LoomAddr is the SSH-forwarded address of weft-loom-server in
	// this DC ("host:port"). When set, the shell spawns a second
	// supervisor + gateway dedicated to loom alongside the primary
	// webui pair. Empty = loom disabled in this DC ; the primary
	// webui pipeline is unaffected.
	LoomAddr string `json:"loom_addr,omitempty"`
}

// EndpointConfig is the legacy single-DC shape (no cluster grouping).
// Loaded when app.json declares `endpoints[]` instead of `clusters[]`
// ; wrapped into a single auto-named ClusterConfig at load time so the
// rest of the pipeline only sees the new shape. New configs SHOULD
// use clusters[] ; this stays as a backward-compat shim.
type EndpointConfig struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`

	Kind TransportKind `json:"kind"`

	Addr string `json:"addr,omitempty"`

	SSHAddr        string `json:"ssh_addr,omitempty"`
	User           string `json:"user,omitempty"`
	KeyPath        string `json:"key_path,omitempty"`
	KnownHostsPath string `json:"known_hosts_path,omitempty"`
	WebUIAddr      string `json:"webui_addr,omitempty"`
	// LoomAddr enables the loom secondary supervisor + gateway. Same
	// semantics as DCConfig.LoomAddr — empty leaves loom off.
	LoomAddr string `json:"loom_addr,omitempty"`
}

// Config is the app's connection configuration, typically loaded from
// JSON next to the binary or discovered via DNS at startup. The
// canonical shape is `clusters[]` with nested `dcs[]` ; the legacy
// `endpoints[]` shape is still accepted and wrapped into a single
// cluster at load time.
type Config struct {
	// Clusters is the new shape : one entry per etcd quorum, each
	// with its own DCs[]. Failover lives within a cluster ; switching
	// between clusters is operator-driven (federation territory).
	Clusters []ClusterConfig `json:"clusters,omitempty"`
	// Endpoints is the legacy flat shape, kept for backward
	// compatibility. When set, it's auto-wrapped into a single cluster.
	// Deprecated : use Clusters[] in new configs.
	Endpoints []EndpointConfig `json:"endpoints,omitempty"`
	// GatewayAddr is the loopback bind for the WebView origin. Default
	// "127.0.0.1:0" (OS-assigned port).
	GatewayAddr string `json:"gateway_addr,omitempty"`
	// Interval / HoldDown tune the Supervisor; zero -> package defaults.
	Interval time.Duration `json:"interval,omitempty"`
	HoldDown time.Duration `json:"hold_down,omitempty"`
}

// EachDC iterates every DC across every cluster, in declaration
// order, calling fn with the parent cluster + dc + global index.
// Used by New() to flatten the nested shape into the supervisor's
// flat endpoint list.
func (c Config) EachDC(fn func(cluster ClusterConfig, dc DCConfig, idx int)) {
	idx := 0
	for _, cl := range c.normalisedClusters() {
		for _, dc := range cl.DCs {
			fn(cl, dc, idx)
			idx++
		}
	}
}

// normalisedClusters returns the cluster list after merging the
// legacy Endpoints[] into a single auto-named cluster ("default"
// when no Clusters[] is present, no-op otherwise). Mutating the
// returned slice is safe — it's a copy.
func (c Config) normalisedClusters() []ClusterConfig {
	if len(c.Endpoints) == 0 {
		out := make([]ClusterConfig, len(c.Clusters))
		copy(out, c.Clusters)
		return out
	}
	// Legacy : wrap endpoints in a default cluster. If Clusters[] is
	// also set, concatenate — but document this is unusual.
	wrapped := ClusterConfig{Name: "default"}
	for _, ep := range c.Endpoints {
		wrapped.DCs = append(wrapped.DCs, DCConfig{
			Name: ep.Name, DisplayName: ep.DisplayName, Kind: ep.Kind,
			Addr: ep.Addr, SSHAddr: ep.SSHAddr, User: ep.User,
			KeyPath: ep.KeyPath, KnownHostsPath: ep.KnownHostsPath,
			WebUIAddr: ep.WebUIAddr,
			LoomAddr:  ep.LoomAddr,
		})
	}
	if len(c.Clusters) == 0 {
		return []ClusterConfig{wrapped}
	}
	return append([]ClusterConfig{wrapped}, c.Clusters...)
}

// LoadConfig reads a JSON Config from path. Accepts the duration fields
// either as a Go duration string ("15s", "1m30s") or as raw nanoseconds —
// stdlib's time.Duration only natively decodes the latter, but the
// shipped config.example.json uses the human-readable form, so we
// decode via a shadow type that tolerates both.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	type shadow struct {
		Clusters    []ClusterConfig  `json:"clusters"`
		Endpoints   []EndpointConfig `json:"endpoints"`
		GatewayAddr string           `json:"gateway_addr,omitempty"`
		Interval    json.RawMessage  `json:"interval,omitempty"`
		HoldDown    json.RawMessage  `json:"hold_down,omitempty"`
	}
	var sh shadow
	if err := json.Unmarshal(b, &sh); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.Clusters = sh.Clusters
	cfg.Endpoints = sh.Endpoints
	cfg.GatewayAddr = sh.GatewayAddr
	if d, err := decodeDuration(sh.Interval); err != nil {
		return cfg, fmt.Errorf("parse config %s: interval: %w", path, err)
	} else {
		cfg.Interval = d
	}
	if d, err := decodeDuration(sh.HoldDown); err != nil {
		return cfg, fmt.Errorf("parse config %s: hold_down: %w", path, err)
	} else {
		cfg.HoldDown = d
	}
	return cfg, nil
}

// decodeDuration parses a duration field that may appear in JSON as
// either a string ("15s") or a number (nanoseconds). Empty input
// returns 0 (the package default kicks in downstream).
func decodeDuration(raw json.RawMessage) (time.Duration, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return 0, nil
		}
		return time.ParseDuration(s)
	}
	// Fall back to numeric ns (raw int64).
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("not a duration string or int : %s", string(raw))
	}
	return time.Duration(n), nil
}

// Options carries dependencies a Config can't express.
type Options struct {
	// MeshDialer is required if any endpoint uses the WireGuard transport
	// (the app brings up the userspace tunnel and passes its DialContext).
	MeshDialer transport.DialContextFunc
	// OnSwitch is invoked on every active-DC change. The app typically
	// evaluates webinject.FailoverNotice into the WebView here so the SPA
	// raises its banner. Called from the probe goroutine — keep it quick.
	OnSwitch func(failover.Switch)
	// AuthToken, if set, is the opaque session token the platform binary
	// obtained from its auth window (OIDC PKCE id_token, OpenPubkey cert
	// JWT, …). The shell carries it through to InitScript so the WebView
	// fetch interceptor adds `Authorization: Bearer <token>` to every
	// same-origin API call. Empty = no auth header injected (current
	// dev / SSH-tunnel-only behaviour).
	AuthToken string
	// SSHPassphrase, if non-nil, is called whenever an SSH endpoint's
	// private key is passphrase-protected. Returns the passphrase bytes
	// that decrypt the key. Platform implementations (weft-app-osx)
	// wrap macOS Keychain ; absent means "fail on encrypted keys" with
	// a clear error message pointing at `--store-ssh-passphrase`.
	SSHPassphrase transport.PassphraseFunc
}

// Shell holds the running per-service supervisor + gateway pairs.
// The primary pair (sup/gw) targets weft-webui. The optional loom pair
// (loomSup/loomGW) targets weft-loom-server ; it's built only when at
// least one DC in the config carries a LoomAddr. When loom is off, the
// loom pair fields are nil and LoomURL() returns "".
type Shell struct {
	sup       *failover.Supervisor
	gw        *failover.Gateway
	loomSup   *failover.Supervisor
	loomGW    *failover.Gateway
	authToken string
}

// New builds the backends, supervisor and gateway from cfg. It does not
// start probing or accepting — call Run.
//
// Accepts both the new clusters[].dcs[] shape and the legacy
// endpoints[] shape (auto-wrapped into a single "default" cluster by
// Config.normalisedClusters).
func New(cfg Config, opts Options) (*Shell, error) {
	clusters := cfg.normalisedClusters()
	if len(clusters) == 0 {
		return nil, fmt.Errorf("shell: no clusters or endpoints configured")
	}
	var eps []transport.Endpoint
	for _, cl := range clusters {
		if len(cl.DCs) == 0 {
			return nil, fmt.Errorf("shell: cluster %q has no dcs", cl.Name)
		}
		clusterLabel := cl.DisplayName
		if clusterLabel == "" {
			clusterLabel = cl.Name
		}
		for _, dc := range cl.DCs {
			b, err := buildBackend(dcToLegacy(dc), opts)
			if err != nil {
				return nil, fmt.Errorf("cluster %q dc %q: %w", cl.Name, dc.Name, err)
			}
			eps = append(eps, transport.Endpoint{
				Name:         dc.Name,
				DisplayName:  dc.DisplayName,
				Cluster:      cl.Name,
				ClusterLabel: clusterLabel,
				Backend:      b,
			})
		}
	}

	sup := failover.New(eps, failover.Options{
		Interval: cfg.Interval,
		HoldDown: cfg.HoldDown,
		OnSwitch: opts.OnSwitch,
	})
	gw, err := failover.NewGateway(sup, cfg.GatewayAddr)
	if err != nil {
		return nil, err
	}

	// Optional loom secondary pair : every DC that exposes a loom_addr
	// gets a loom-pointed backend, fed into a sibling supervisor +
	// gateway. Loopback bind defaults to ":0" (kernel-picked) so it
	// doesn't collide with the primary gateway. When no DC has
	// loom_addr the loom pair stays nil — LoomURL() returns "" and
	// the platform UI suppresses the "Open Loom" menu item.
	var loomSup *failover.Supervisor
	var loomGW *failover.Gateway
	var loomEps []transport.Endpoint
	for _, cl := range clusters {
		clusterLabel := cl.DisplayName
		if clusterLabel == "" {
			clusterLabel = cl.Name
		}
		for _, dc := range cl.DCs {
			if dc.LoomAddr == "" {
				continue
			}
			lb, err := buildBackend(dcToLegacyLoom(dc), opts)
			if err != nil {
				return nil, fmt.Errorf("loom : cluster %q dc %q: %w", cl.Name, dc.Name, err)
			}
			loomEps = append(loomEps, transport.Endpoint{
				Name:         dc.Name,
				DisplayName:  dc.DisplayName,
				Cluster:      cl.Name,
				ClusterLabel: clusterLabel,
				Backend:      lb,
			})
		}
	}
	if len(loomEps) > 0 {
		loomSup = failover.New(loomEps, failover.Options{
			Interval: cfg.Interval,
			HoldDown: cfg.HoldDown,
			// No OnSwitch on the loom pair — the primary already
			// notifies the SPA ; loom failover is silent from the UI's
			// perspective (the WebView origin doesn't change).
		})
		var lerr error
		loomGW, lerr = failover.NewGateway(loomSup, "")
		if lerr != nil {
			return nil, fmt.Errorf("loom gateway: %w", lerr)
		}
	}

	return &Shell{
		sup:       sup,
		gw:        gw,
		loomSup:   loomSup,
		loomGW:    loomGW,
		authToken: opts.AuthToken,
	}, nil
}

// dcToLegacyLoom is the loom counterpart of dcToLegacy : it swaps
// LoomAddr in for WebUIAddr so buildBackend's SSHForward path targets
// the loom listener instead of the webui one. All other fields
// (transport, ssh, key) are shared with the primary endpoint — both
// services live on the same host, reached through the same key.
func dcToLegacyLoom(dc DCConfig) EndpointConfig {
	return EndpointConfig{
		Name: dc.Name, DisplayName: dc.DisplayName, Kind: dc.Kind,
		Addr: dc.LoomAddr, SSHAddr: dc.SSHAddr, User: dc.User,
		KeyPath: dc.KeyPath, KnownHostsPath: dc.KnownHostsPath,
		WebUIAddr: dc.LoomAddr,
	}
}

// dcToLegacy converts the new DCConfig to the legacy EndpointConfig
// shape buildBackend expects. Mechanical field-for-field copy ; kept
// as a one-liner so buildBackend isn't churned by the rename.
func dcToLegacy(dc DCConfig) EndpointConfig {
	return EndpointConfig{
		Name: dc.Name, DisplayName: dc.DisplayName, Kind: dc.Kind,
		Addr: dc.Addr, SSHAddr: dc.SSHAddr, User: dc.User,
		KeyPath: dc.KeyPath, KnownHostsPath: dc.KnownHostsPath,
		WebUIAddr: dc.WebUIAddr,
	}
}

// Run starts the supervisor and gateway. It blocks until ctx is
// cancelled, then tears both down. Run it in its own goroutine; the
// main thread belongs to the platform UI loop.
//
// When loom is enabled, the loom supervisor + gateway are started in
// background goroutines bound to the same ctx ; their lifetime is
// always a strict subset of the primary pair's.
func (s *Shell) Run(ctx context.Context) error {
	go s.sup.Run(ctx)
	if s.loomSup != nil {
		go s.loomSup.Run(ctx)
	}
	if s.loomGW != nil {
		go func() {
			if err := s.loomGW.Serve(ctx); err != nil {
				// Match the primary gateway's error policy : log via
				// the platform's caller, don't kill the process.
				_ = err
			}
		}()
	}
	return s.gw.Serve(ctx) // returns nil on ctx cancel / Close
}

// URL is the stable loopback origin to load in the WebView.
func (s *Shell) URL() string { return s.gw.URL() }

// LoomURL returns the loopback origin for the loom secondary gateway,
// or "" when loom is disabled (no DC in the config exposes loom_addr).
// The platform's tray uses this to decide whether to surface an
// "Open Loom" menu item.
func (s *Shell) LoomURL() string {
	if s.loomGW == nil {
		return ""
	}
	return s.loomGW.URL()
}

// SwitchCluster scopes failover to the named cluster's DCs only —
// every endpoint outside the cluster is quarantined so the supervisor
// can't pick one. Tray's "Switch cluster" menu calls this. Pass "" to
// clear the filter and restore the legacy flat pool behaviour.
//
// The supervisor emits an OnSwitch when this changes the active DC,
// so the dashboard's Topbar chip + the menubar title update via the
// usual webinject.FailoverNotice path.
func (s *Shell) SwitchCluster(cluster string) { s.sup.SetClusterFilter(cluster) }

// ActiveCluster returns the cluster name the currently-selected DC
// belongs to. Empty when nothing is reachable or in legacy
// single-cluster mode.
func (s *Shell) ActiveCluster() string { return s.sup.ActiveCluster() }

// Clusters returns the unique cluster names from the configuration,
// in declaration order. Tray uses it to populate "Switch cluster".
func (s *Shell) Clusters() []string { return s.sup.Clusters() }

// InitScript is the document-start JS to inject into the WebView: it
// tells the SPA about the (single, stable) gateway origin so its API
// client comes up failover-aware. When AuthToken is set on Options,
// the snippet also installs a fetch-level Bearer interceptor for
// every same-origin API call (see webinject.AuthInterceptor).
func (s *Shell) InitScript() string {
	base := webinject.InitScript(webinject.Config{
		Endpoints: []webinject.Endpoint{{Name: "cluster", URL: s.gw.URL()}},
	})
	if s.authToken == "" {
		return base
	}
	return base + "\n" + webinject.AuthInterceptor(webinject.AuthConfig{
		Token:      s.authToken,
		Origin:     s.gw.URL(),
		HeaderName: AuthHeaderName,
		Prefix:     AuthHeaderPrefix,
	})
}

// Status returns each DC's name + health for a tray menu / status view.
func (s *Shell) Status() []failover.EndpointStatus { return s.sup.Snapshot() }

// Close stops the gateway (Run's ctx cancel does the same).
func (s *Shell) Close() error { return s.gw.Close() }

// buildBackend turns one EndpointConfig into a transport.Backend.
func buildBackend(ec EndpointConfig, opts Options) (transport.Backend, error) {
	switch ec.Kind {
	case Direct:
		if ec.Addr == "" {
			return nil, fmt.Errorf("direct transport needs addr")
		}
		return &transport.DirectTCP{Addr: ec.Addr}, nil

	case SSH:
		if ec.SSHAddr == "" || ec.WebUIAddr == "" {
			return nil, fmt.Errorf("ssh transport needs ssh_addr and webui_addr")
		}
		signer, err := transport.LoadSignerWithPassphrase(ec.KeyPath, opts.SSHPassphrase)
		if err != nil {
			return nil, err
		}
		hk, err := hostKeyCallback(ec.KnownHostsPath)
		if err != nil {
			return nil, err
		}
		return &transport.SSHForward{
			SSHAddr: ec.SSHAddr, User: ec.User, Signer: signer,
			HostKey: hk, WebUIAddr: ec.WebUIAddr,
		}, nil

	case WireGuard:
		if opts.MeshDialer == nil {
			return nil, fmt.Errorf("wireguard transport needs Options.MeshDialer")
		}
		if ec.Addr == "" {
			return nil, fmt.Errorf("wireguard transport needs addr (mesh host:port)")
		}
		return &transport.WireGuard{Mesh: opts.MeshDialer, MeshAddr: ec.Addr}, nil

	default:
		return nil, fmt.Errorf("unknown transport kind %q", ec.Kind)
	}
}

func hostKeyCallback(path string) (ssh.HostKeyCallback, error) {
	if path == "" {
		return nil, fmt.Errorf("known_hosts_path required (refusing to skip host verification)")
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	return cb, nil
}
