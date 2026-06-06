package shell

import (
	"context"
	"fmt"

	"github.com/openweft/weft-app-core/discovery"
)

// Discover builds a Shell whose endpoints come from DNS instead of a
// static endpoint list. It resolves the per-DC SRV records
// (_<service>._<proto>.<domain>) the platform already publishes and wraps
// each discovered DC in a Direct transport — the common case when the
// device is on the WireGuard mesh and the webui listener binds the mesh
// interface only.
//
// `base` supplies everything except the endpoints (GatewayAddr, Interval,
// HoldDown); its Endpoints field is ignored and replaced by what DNS
// returns. For SSH-fronted clusters prefer a static Config — the bastion
// list is small and stable, and SSH needs per-DC key/known-hosts details
// DNS can't carry.
func Discover(ctx context.Context, service, proto, domain string, r discovery.Resolver, base Config, opts Options) (*Shell, error) {
	targets, err := discovery.SRV(ctx, service, proto, domain, r)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("discover: no SRV targets for _%s._%s.%s", service, proto, domain)
	}
	base.Endpoints = make([]EndpointConfig, 0, len(targets))
	for _, t := range targets {
		base.Endpoints = append(base.Endpoints, EndpointConfig{
			Name: t.Name,
			Kind: Direct,
			Addr: t.Addr(),
		})
	}
	return New(base, opts)
}
