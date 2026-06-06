# weft-app-core

Shared Go library for the Weft desktop client apps
([weft-app-osx](https://github.com/openweft/weft-app-osx),
[weft-app-gtk](https://github.com/openweft/weft-app-gtk),
[weft-app-windows](https://github.com/openweft/weft-app-windows)). The
mobile apps ([android](https://github.com/openweft/weft-app-android) /
[ios](https://github.com/openweft/weft-app-ios)) mirror this logic
natively.

The apps are thin shells: a menu-bar / tray icon that opens the
[`weft-webui`](https://github.com/openweft/weft-webui) dashboard in a
WebView. This module is everything *behind* the WebView — how it finds
the cluster, reaches it securely, and stays connected when a datacenter
falls over.

It is **pure Go and dependency-light** (stdlib + `x/crypto/ssh`), so it
builds and tests offline. The cgo-heavy WebView and tray bindings live in
the per-platform app repos, not here.

## What it does

```
DNS (SRV/A)                Transport per DC              Failover
──────────────             ────────────────              ────────────────
discovery.SRV()  ──────▶   transport.Backend   ──────▶   failover.Supervisor
  one Target per DC          DirectTCP                      health probes
                             SSHForward   (x/crypto/ssh)    anti-flap select
                             WireGuard    (mesh dialer)     active DC
                                                                │
                                                                ▼
                                                       failover.Gateway
                                                  one stable loopback origin
                                                  the WebView never re-points
```

### `discovery`
Resolves the same per-DC `SRV` records the gRPC API uses
(`_weft-webui._tcp.<domain>`), or a multi-A name as a fallback, into an
ordered list of `Target`s (preferred DC first).

### `transport`
A `Backend` reaches one DC's webui. Three implementations, interchangeable
to the supervisor:

| Backend      | Reaches the webui via                              | Public listener? |
|--------------|----------------------------------------------------|------------------|
| `DirectTCP`  | plain TCP (device already on the mesh / localhost) | —                |
| `SSHForward` | SSH local-forward, key auth (`x/crypto/ssh`)       | **no**           |
| `WireGuard`  | userspace mesh dialer (wireguard-go netstack)      | **no**           |

`SSHForward` and `WireGuard` mean the platform exposes **no worldwide web
service** — the transport key gates the network, dex OIDC still gates the
session inside the UI.

### `failover`
`Supervisor` probes every DC on a timer and keeps one **active** choice
with hysteresis — *fail over fast, fail back slow*:

- a DC that fails a probe is dropped immediately;
- a recovered, more-preferred DC must stay healthy for `HoldDown` before
  it is re-selected, so a flapping DC never whipsaws the connection;
- when nothing is active (cold start / all-down recovery) any healthy DC
  is taken at once.

`Gateway` is a loopback listener that proxies each connection to the
active DC. The WebView loads its single stable origin
(`http://127.0.0.1:<port>`) and **never re-points**, so a DC swap
preserves cookies, OIDC session and SPA state — the page never reloads.

### `webinject`
Renders the JS contract the WebView side
([`weft-webui` `src/lib/endpoints.ts`](https://github.com/openweft/weft-webui))
expects: `window.__WEFT_ENDPOINTS__` (injected at document-start) and the
`__weftFailoverNotice(from,to)` call that raises the dashboard's
"connection switched" banner when the gateway swaps DC under it.

## Two cooperating failover layers

1. **Single-origin (this library's `Gateway`)** — seamless: the WebView
   never sees an origin change. On swap, in-flight requests are cut and
   the SPA's own retry re-issues them against the same origin.
2. **Multi-origin (the SPA's `endpoints.ts`)** — if the app prefers to
   expose every DC at once (via `webinject.InitScript`), the SPA rotates
   across origins itself. Cross-origin sessions are the caveat; the
   single-origin gateway avoids it.

Most apps use the gateway and let the SPA handle same-origin retry.

## Develop

```sh
task check   # go vet ./... && go test ./... -race
```
