// Package failover keeps a client app pointed at a healthy datacenter.
//
// The Supervisor watches every DC's weft-webui through its transport
// Backend and maintains a single "active" choice. Selection is biased
// toward the highest-priority (lowest-index, i.e. nearest) DC that is
// healthy, with hysteresis so a DC that is flapping up and down does not
// whipsaw the active connection :
//
//   - A DC that fails its probe is marked unhealthy immediately
//     (fail fast — we want to move off a dead DC at once).
//   - A DC that starts passing again must stay healthy for HoldDown
//     before it is eligible to be re-selected (fail back slow).
//
// The Supervisor owns no I/O of its own beyond calling Backend.Probe on
// a timer; the loopback Gateway (gateway.go) consumes its Active choice
// to proxy WebView traffic, giving the user a single stable origin whose
// backing DC can change underneath without a page reload.
package failover

import (
	"context"
	"sync"
	"time"

	"github.com/openweft/weft-app-core/transport"
)

// Health is a DC's current standing in the Supervisor.
type Health int

const (
	// Unknown — not yet probed.
	Unknown Health = iota
	// Up — last probe succeeded (and, for fail-back, has been up long
	// enough to be eligible).
	Up
	// Down — last probe failed.
	Down
)

func (h Health) String() string {
	switch h {
	case Up:
		return "up"
	case Down:
		return "down"
	default:
		return "unknown"
	}
}

// Switch describes an active-DC change, delivered to OnSwitch.
type Switch struct {
	FromName string // technical ID ; empty on the very first selection
	ToName   string // technical ID
	// FromLabel / ToLabel mirror From/To but carry the operator-facing
	// label (DisplayName if set, Name otherwise) — what the menubar +
	// chip render. Falls back to FromName/ToName when DisplayName isn't
	// configured.
	FromLabel string
	ToLabel   string
	// FromCluster / ToCluster carry the technical parent-cluster name
	// for the friendly "Cluster · DC" rendering. Empty in legacy
	// single-cluster mode.
	FromCluster string
	ToCluster   string
	// FromClusterLabel / ToClusterLabel are the cluster display
	// names (cluster.display_name when set, else cluster.name).
	FromClusterLabel string
	ToClusterLabel   string
	// AllDown is true when no DC is healthy; ToName is then empty and the
	// Gateway should surface the "all datacenters unreachable" state.
	AllDown bool
}

// Options tunes the Supervisor. Zero values get sensible defaults.
type Options struct {
	// Interval between probe rounds. Default 3s.
	Interval time.Duration
	// HoldDown a recovered DC must stay healthy before it may be
	// re-selected (anti-flap fail-back window). Default 15s.
	HoldDown time.Duration
	// ProbeTimeout bounds a single Backend.Probe. Default 4s.
	ProbeTimeout time.Duration
	// Now is injected for tests. Default time.Now.
	Now func() time.Time
	// OnSwitch, if set, is called whenever the active DC changes (or the
	// cluster goes all-down / recovers). Called from the probe goroutine;
	// keep it quick and non-blocking.
	OnSwitch func(Switch)
}

func (o *Options) withDefaults() {
	if o.Interval <= 0 {
		o.Interval = 3 * time.Second
	}
	if o.HoldDown <= 0 {
		o.HoldDown = 15 * time.Second
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = 4 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

type epState struct {
	ep      transport.Endpoint
	health  Health
	healthy bool      // last probe result
	upSince time.Time // when it most recently transitioned to healthy
	// disabled = excluded from selection (still probed so the tray's
	// health glyphs stay accurate). Used by SetClusterFilter to scope
	// failover to the active cluster's DCs only — switching to another
	// cluster is operator-driven, never a probe-triggered failover.
	disabled bool
}

// Supervisor selects a healthy DC from an ordered endpoint list.
type Supervisor struct {
	opts Options

	mu      sync.RWMutex
	eps     []*epState
	active  int  // index into eps, or -1 when all-down
	allDown bool // mirrors active == -1, kept for OnSwitch edge detection
}

// New builds a Supervisor over endpoints in priority order (index 0 =
// most preferred). It does not start probing; call Run.
func New(endpoints []transport.Endpoint, opts Options) *Supervisor {
	opts.withDefaults()
	s := &Supervisor{opts: opts, active: -1, allDown: true}
	for _, ep := range endpoints {
		s.eps = append(s.eps, &epState{ep: ep, health: Unknown})
	}
	return s
}

// Active returns the currently selected endpoint and true, or a zero
// Endpoint and false when every DC is down.
func (s *Supervisor) Active() (transport.Endpoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active < 0 {
		return transport.Endpoint{}, false
	}
	return s.eps[s.active].ep, true
}

// ActiveCluster returns the technical name of the cluster the
// currently-active DC belongs to. Empty when nothing is active or in
// legacy single-cluster mode.
func (s *Supervisor) ActiveCluster() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active < 0 {
		return ""
	}
	return s.eps[s.active].ep.Cluster
}

// Clusters returns the unique cluster names declared across all
// endpoints, in first-seen order. Tray uses it to populate the
// "Switch cluster" submenu.
func (s *Supervisor) Clusters() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	out := []string{}
	for _, e := range s.eps {
		if e.ep.Cluster != "" && !seen[e.ep.Cluster] {
			seen[e.ep.Cluster] = true
			out = append(out, e.ep.Cluster)
		}
	}
	return out
}

// SetClusterFilter scopes failover to the named cluster's DCs only —
// every endpoint outside the cluster is marked disabled so the probe
// loop's reselectLocked skips it. Passing "" clears the filter (every
// DC is eligible again — the legacy flat behaviour).
//
// The call triggers an immediate reselect ; if the previously-active
// DC was in another cluster, this returns a Switch through OnSwitch.
// Probing of disabled endpoints continues so the tray's health
// glyphs stay accurate.
func (s *Supervisor) SetClusterFilter(cluster string) {
	s.mu.Lock()
	for _, e := range s.eps {
		e.disabled = cluster != "" && e.ep.Cluster != cluster
	}
	now := s.opts.Now()
	from, to, fromLabel, toLabel, fromCluster, toCluster, fromClusterLabel, toClusterLabel, changed, allDown := s.reselectLocked(now)
	s.mu.Unlock()
	if changed && s.opts.OnSwitch != nil {
		s.opts.OnSwitch(Switch{
			FromName: from, ToName: to,
			FromLabel: fromLabel, ToLabel: toLabel,
			FromCluster: fromCluster, ToCluster: toCluster,
			FromClusterLabel: fromClusterLabel, ToClusterLabel: toClusterLabel,
			AllDown: allDown,
		})
	}
}

// Snapshot reports each endpoint's name and health, in priority order.
// Useful for a tray menu or status view.
func (s *Supervisor) Snapshot() []EndpointStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]EndpointStatus, len(s.eps))
	for i, e := range s.eps {
		out[i] = EndpointStatus{
			Name:         e.ep.Name,
			DisplayName:  e.ep.DisplayName,
			Cluster:      e.ep.Cluster,
			ClusterLabel: e.ep.ClusterLabel,
			Target:       e.ep.Backend.Target(),
			Health:       e.health,
			Active:       i == s.active,
		}
	}
	return out
}

// EndpointStatus is a read-only view of one endpoint's standing.
type EndpointStatus struct {
	Name         string
	DisplayName  string // operator-facing DC label ; empty = use Name
	Cluster      string // parent cluster technical name ; "" in legacy mode
	ClusterLabel string // parent cluster display label ; "" => use Cluster
	Target       string
	Health       Health
	Active       bool
}

// Label returns the operator-facing DC name : DisplayName when set,
// Name otherwise.
func (e EndpointStatus) Label() string {
	if e.DisplayName != "" {
		return e.DisplayName
	}
	return e.Name
}

// ClusterLabelOrName returns the cluster's display name when set, the
// technical cluster name otherwise. Empty in legacy single-cluster mode.
func (e EndpointStatus) ClusterLabelOrName() string {
	if e.ClusterLabel != "" {
		return e.ClusterLabel
	}
	return e.Cluster
}

// FullLabel composes "Cluster · DC" when a cluster name is present,
// otherwise just the DC label. The menubar title + Topbar chip use it.
func (e EndpointStatus) FullLabel() string {
	cl := e.ClusterLabelOrName()
	if cl == "" {
		return e.Label()
	}
	return cl + " · " + e.Label()
}

// Run probes on a ticker until ctx is cancelled. It runs one round
// immediately so Active is meaningful as soon as the first round
// completes. Safe to call in its own goroutine.
func (s *Supervisor) Run(ctx context.Context) {
	t := time.NewTicker(s.opts.Interval)
	defer t.Stop()
	s.round(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.round(ctx)
		}
	}
}

// round probes every endpoint concurrently, updates health with
// hysteresis, then re-selects the active DC.
func (s *Supervisor) round(ctx context.Context) {
	now := s.opts.Now()

	// Probe all endpoints concurrently.
	results := make([]bool, len(s.eps))
	var wg sync.WaitGroup
	for i := range s.eps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, s.opts.ProbeTimeout)
			defer cancel()
			results[i] = s.eps[i].ep.Backend.Probe(pctx) == nil
		}(i)
	}
	wg.Wait()

	s.mu.Lock()
	for i, ok := range results {
		e := s.eps[i]
		if ok {
			if !e.healthy {
				// down/unknown -> up : start the hold-down clock.
				e.upSince = now
			}
			e.healthy = true
			e.health = Up
		} else {
			e.healthy = false
			e.health = Down
			e.upSince = time.Time{}
		}
	}
	from, to, fromLabel, toLabel, fromCluster, toCluster, fromClusterLabel, toClusterLabel, changed, allDown := s.reselectLocked(now)
	s.mu.Unlock()

	if changed && s.opts.OnSwitch != nil {
		s.opts.OnSwitch(Switch{
			FromName: from, ToName: to,
			FromLabel: fromLabel, ToLabel: toLabel,
			FromCluster: fromCluster, ToCluster: toCluster,
			FromClusterLabel: fromClusterLabel, ToClusterLabel: toClusterLabel,
			AllDown: allDown,
		})
	}
}

// reselectLocked picks the best endpoint and updates s.active. Returns
// the names involved and whether a user-visible change occurred. Must
// hold s.mu.
//
// The hold-down (anti-flap) only ever gates *failing back* over a DC
// that is still working : if the active DC is healthy, a more-preferred
// DC must have been healthy for HoldDown before we switch to it. When
// the active DC is down (or there is none yet — cold start, or recovery
// from all-down), any healthy DC is taken immediately, highest priority
// first. So we fail over fast and fail back slow.
func (s *Supervisor) reselectLocked(now time.Time) (from, to, fromLabel, toLabel, fromCluster, toCluster, fromClusterLabel, toClusterLabel string, changed, allDown bool) {
	prev := s.active
	// A disabled active counts as not-healthy : SetClusterFilter
	// disabling the current pick must force a fresh selection in
	// whatever DCs remain eligible.
	activeHealthy := prev >= 0 && s.eps[prev].healthy && !s.eps[prev].disabled

	best := -1
	for i := range s.eps {
		e := s.eps[i]
		if e.disabled {
			continue // belongs to a non-active cluster, never selectable
		}
		if !e.healthy {
			continue
		}
		if !activeHealthy {
			best = i // nothing working: grab the top healthy DC now
			break
		}
		if i == prev {
			best = i // reached the active DC before any eligible better one: keep it
			break
		}
		if i < prev && now.Sub(e.upSince) >= s.opts.HoldDown {
			best = i // a more-preferred DC has solidly recovered: fail back
			break
		}
		// healthy but lower priority than active, or hasn't cleared
		// hold-down yet — skip.
	}

	if best == prev {
		return "", "", "", "", "", "", "", "", false, s.active < 0
	}

	var prevName, prevLabel, prevCluster, prevClusterLabel string
	if prev >= 0 {
		ep := s.eps[prev].ep
		prevName = ep.Name
		prevLabel = ep.Label()
		prevCluster = ep.Cluster
		prevClusterLabel = ep.ClusterLabel
	}
	s.active = best
	if best < 0 {
		s.allDown = true
		return prevName, "", prevLabel, "", prevCluster, "", prevClusterLabel, "", true, true
	}
	s.allDown = false
	ep := s.eps[best].ep
	return prevName, ep.Name, prevLabel, ep.Label(), prevCluster, ep.Cluster, prevClusterLabel, ep.ClusterLabel, true, false
}
