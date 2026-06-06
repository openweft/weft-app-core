// Package discovery turns DNS into an ordered list of datacenter
// targets, matching the resolution scheme the platform already uses for
// the gRPC API : one SRV record per DC, served by the per-DC CoreDNS
// microVMs (or, as a fallback, a multi-A name with one address per DC).
//
// It deliberately returns plain host:port Targets, not transport
// Backends — the app decides which transport (DirectTCP / SSHForward /
// WireGuard) wraps each target, since that choice depends on how the
// device reaches the mesh, not on DNS.
package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
)

// Target is one resolved datacenter endpoint.
type Target struct {
	// Name is a stable label for the DC, derived from the SRV target host
	// (e.g. "weft-a" from "weft-a.weft.internal."). Shown in the UI.
	Name string
	// Host is the resolved hostname or IP.
	Host string
	// Port is the service port.
	Port int
	// Priority / Weight copied from the SRV record (0 for A-record
	// fallback). Lower Priority is preferred.
	Priority uint16
	Weight   uint16
}

// Addr is "host:port".
func (t Target) Addr() string { return net.JoinHostPort(t.Host, fmt.Sprint(t.Port)) }

// Resolver wraps the bits of *net.Resolver discovery needs, so tests can
// stub DNS.
type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// SRV resolves "_<service>._<proto>.<domain>" into per-DC targets,
// ordered by SRV priority then name for stable, repeatable ordering.
//
// Example: SRV("weft-webui", "tcp", "weft.internal", r) against
//
//	_weft-webui._tcp.weft.internal. IN SRV 0 33 8443 weft-a.weft.internal.
//	_weft-webui._tcp.weft.internal. IN SRV 0 33 8443 weft-b.weft.internal.
//	_weft-webui._tcp.weft.internal. IN SRV 0 33 8443 weft-c.weft.internal.
//
// yields three targets named weft-a / weft-b / weft-c.
func SRV(ctx context.Context, service, proto, domain string, r Resolver) ([]Target, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	_, recs, err := r.LookupSRV(ctx, service, proto, domain)
	if err != nil {
		return nil, fmt.Errorf("lookup SRV _%s._%s.%s: %w", service, proto, domain, err)
	}
	out := make([]Target, 0, len(recs))
	for _, rec := range recs {
		out = append(out, Target{
			Name:     label(rec.Target),
			Host:     trimDot(rec.Target),
			Port:     int(rec.Port),
			Priority: rec.Priority,
			Weight:   rec.Weight,
		})
	}
	sortTargets(out)
	return out, nil
}

// A resolves a multi-A name into one target per address, all on the same
// port. The fallback when SRV is unavailable (e.g. public ingress where
// api.weft.example.com has one A record per DC). Names are synthesised
// as "<host>#<n>" since A records carry no per-DC label.
func A(ctx context.Context, host string, port int, r Resolver) ([]Target, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("lookup host %s: %w", host, err)
	}
	// Stable order: sort addresses lexically so the "primary" choice is
	// deterministic across resolutions.
	sort.Strings(addrs)
	out := make([]Target, 0, len(addrs))
	for i, a := range addrs {
		out = append(out, Target{
			Name: fmt.Sprintf("%s#%d", host, i+1),
			Host: a,
			Port: port,
		})
	}
	return out, nil
}

func sortTargets(ts []Target) {
	sort.SliceStable(ts, func(i, j int) bool {
		if ts[i].Priority != ts[j].Priority {
			return ts[i].Priority < ts[j].Priority
		}
		return ts[i].Name < ts[j].Name
	})
}

// label extracts the first DNS label of an SRV target host, used as the
// DC name: "weft-a.weft.internal." -> "weft-a".
func label(host string) string {
	h := trimDot(host)
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			return h[:i]
		}
	}
	return h
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
