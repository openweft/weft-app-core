// Package webinject renders the small JavaScript glue that lets the
// native shell drive the dashboard's failover UI.
//
// It is the Go side of the contract defined in weft-webui's
// src/lib/endpoints.ts :
//
//   - InitScript builds the `window.__WEFT_ENDPOINTS__ = {…}` assignment
//     the shell evaluates *before* the SPA bundle loads, so the API
//     client comes up already knowing every DC. With a single-origin
//     Gateway this list is just the one loopback origin; with
//     multi-origin transports it lists them all.
//
//   - FailoverNotice builds a `window.__weftFailoverNotice(from,to)` call
//     the shell evaluates when the Supervisor re-points the Gateway, so
//     the SPA raises its "connection switched" banner even though the
//     origin (and thus its own fetch-level failover) never noticed.
//
// Every value is JSON-encoded, so it is safe to interpolate names that
// came from DNS.
package webinject

import "encoding/json"

// Endpoint mirrors the {name,url} shape endpoints.ts expects.
type Endpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Config mirrors window.__WEFT_ENDPOINTS__.
type Config struct {
	Endpoints    []Endpoint `json:"endpoints"`
	QuarantineMs int        `json:"quarantineMs,omitempty"`
	// CurrentDC is the human name of the DC the shell currently routes
	// traffic to. In single-gateway mode (one loopback URL, the shell
	// does failover invisibly behind it) this is the only signal the SPA
	// has to render the persistent Topbar chip.
	CurrentDC string `json:"currentDC,omitempty"`
}

// InitScript returns JS that sets window.__WEFT_ENDPOINTS__. Evaluate it
// as a document-start user script (before the SPA loads).
func InitScript(cfg Config) string {
	b, _ := json.Marshal(cfg)
	return "window.__WEFT_ENDPOINTS__ = " + string(b) + ";"
}

// FailoverNotice returns JS that raises the SPA's switched-DC banner.
// `from` may be empty (first selection). Guards against the SPA not yet
// having registered the hook.
func FailoverNotice(from, to string) string {
	f, _ := json.Marshal(from)
	t, _ := json.Marshal(to)
	return "window.__weftFailoverNotice && window.__weftFailoverNotice(" + string(f) + "," + string(t) + ");"
}

// SetEndpoints returns JS that swaps the SPA's endpoint list at runtime
// (e.g. after re-resolving DNS).
func SetEndpoints(cfg Config) string {
	b, _ := json.Marshal(cfg)
	return "window.__weftSetEndpoints && window.__weftSetEndpoints(" + string(b) + ");"
}
