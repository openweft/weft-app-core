// Auth-token injection. The dashboard WebView loads
// http://127.0.0.1:<port>/ (the gateway origin) and from there the SPA
// issues same-origin `fetch()` calls. Once the operator has signed in,
// every one of those calls needs an `Authorization: Bearer <token>`
// header so the webui (running with `--auth-mode bearer` upstream)
// accepts it.
//
// We can't put the header on the Go side : the gateway is L4 (raw TCP
// proxy) and doesn't see HTTP. So the header is added in the page, by
// monkey-patching `window.fetch` (and XMLHttpRequest.open + send) to
// stamp the header on every same-origin request before forwarding to
// the real implementation.
//
// The injected snippet is JSON-safe (token + origin go through
// json.Marshal) so an attacker can't break out by smuggling a quote.
package webinject

import (
	"encoding/json"
	"strings"
)

// AuthConfig describes how the fetch interceptor should stamp requests.
type AuthConfig struct {
	// Token is the opaque bearer token (an OIDC id_token, an OpenPubkey
	// cert JWT, …). Required.
	Token string
	// Origin is the gateway origin to scope the interceptor to, e.g.
	// "http://127.0.0.1:54123". The interceptor only adds the header on
	// requests whose URL parses as same-origin to this, so cross-origin
	// `fetch("https://other-cdn/…")` calls the SPA might still issue
	// (analytics, assets) don't leak the token.
	Origin string
	// HeaderName defaults to "Authorization".
	HeaderName string
	// Prefix defaults to "Bearer " (with trailing space).
	Prefix string
}

// AuthInterceptor returns the JS that installs a fetch + XHR Bearer
// interceptor. Evaluate it as a document-start user script (same hook
// as InitScript). Empty token = empty script (caller usually skips the
// inject in that case, but we tolerate it so callers don't have to).
func AuthInterceptor(cfg AuthConfig) string {
	if cfg.Token == "" {
		return ""
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = "Authorization"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "Bearer "
	}
	tok, _ := json.Marshal(cfg.Prefix + cfg.Token)
	origin, _ := json.Marshal(cfg.Origin)
	hdr, _ := json.Marshal(cfg.HeaderName)

	// The IIFE captures the token + origin + header at install time so a
	// rogue page script can't read them off `window`.
	const tpl = `(function(){
  var __WEFT_TOKEN = %s;
  var __WEFT_ORIGIN = %s;
  var __WEFT_HEADER = %s;
  function sameOrigin(u){
    try{
      if(!u) return true;
      var a = new URL(u, __WEFT_ORIGIN || window.location.href);
      if(!__WEFT_ORIGIN) return a.origin === window.location.origin;
      var o = new URL(__WEFT_ORIGIN);
      return a.origin === o.origin;
    }catch(e){ return true; }
  }
  if (window.fetch){
    var __weftRealFetch = window.fetch.bind(window);
    window.fetch = function(input, init){
      try{
        var url = (typeof input === 'string' || input instanceof URL) ? String(input) : (input && input.url);
        if (sameOrigin(url)){
          init = init || {};
          var h = new Headers(init.headers || (input && input.headers) || {});
          if (!h.has(__WEFT_HEADER)) h.set(__WEFT_HEADER, __WEFT_TOKEN);
          init.headers = h;
        }
      }catch(e){}
      return __weftRealFetch(input, init);
    };
  }
  if (window.XMLHttpRequest){
    var __weftRealOpen = XMLHttpRequest.prototype.open;
    var __weftRealSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url){
      this.__weftStamp = sameOrigin(url);
      return __weftRealOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(){
      try{
        if (this.__weftStamp) this.setRequestHeader(__WEFT_HEADER, __WEFT_TOKEN);
      }catch(e){}
      return __weftRealSend.apply(this, arguments);
    };
  }
})();`
	return sprintf(tpl, string(tok), string(origin), string(hdr))
}

// sprintf is a tiny strings.Replace-based templater so we don't pull in
// fmt for one site. Replaces successive %s placeholders left-to-right.
func sprintf(tpl string, args ...string) string {
	for _, a := range args {
		idx := strings.Index(tpl, "%s")
		if idx < 0 {
			break
		}
		tpl = tpl[:idx] + a + tpl[idx+2:]
	}
	return tpl
}
