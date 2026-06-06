// inject_auth wires Options.AuthToken into the WebView init script as a
// fetch-level Bearer interceptor. The actual JS lives in
// webinject/auth.go ; this file is the shell-side seam so the API is
// `shell.InitScript()` for callers and the JS-rendering detail stays in
// webinject.
package shell

import "github.com/openweft/weft-app-core/webinject"

// AuthInitScript returns just the auth-interceptor JS for this shell,
// or "" when no token is configured. Useful for platform binaries that
// build their own init script piecewise (e.g. weft-app-osx layers in
// the failover-notice hook above the cluster endpoint block).
func (s *Shell) AuthInitScript() string {
	if s == nil || s.authToken == "" {
		return ""
	}
	return webinject.AuthInterceptor(webinject.AuthConfig{
		Token:      s.authToken,
		Origin:     s.gw.URL(),
		HeaderName: AuthHeaderName,
		Prefix:     AuthHeaderPrefix,
	})
}
