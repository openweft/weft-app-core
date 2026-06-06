// Auth glue : a per-Shell session token, exposed to the platform binary
// so it can wire it into the WebView (as a Bearer header on every API
// fetch) and into any outbound HTTP the gateway might do directly.
//
// The shell itself does no auth I/O — issuing / refreshing the token
// lives in the platform binary (see weft-app-osx/auth.go). What lives
// here is just the small, platform-agnostic carrier so the rest of the
// shell (gateway, init script) can pick it up.
package shell

// AuthHeaderName is the HTTP header name the WebView fetch interceptor
// adds when AuthToken is non-empty. Exposed as a constant so the
// platform binary and any future inbound transports stay in lockstep.
const AuthHeaderName = "Authorization"

// AuthHeaderPrefix is the value prefix : "Bearer " (with the trailing
// space). Concatenated with the opaque token.
const AuthHeaderPrefix = "Bearer "

// AuthToken returns the token configured on this Shell, or "" when no
// auth was wired. Provided as a method so callers don't have to keep
// Options around.
func (s *Shell) AuthToken() string {
	if s == nil {
		return ""
	}
	return s.authToken
}
