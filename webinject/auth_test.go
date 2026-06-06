package webinject

import (
	"strings"
	"testing"
)

func TestAuthInterceptorEmptyTokenSkips(t *testing.T) {
	if s := AuthInterceptor(AuthConfig{}); s != "" {
		t.Fatalf("empty token should produce empty snippet, got %q", s)
	}
}

func TestAuthInterceptorEscapesQuote(t *testing.T) {
	s := AuthInterceptor(AuthConfig{
		Token:  `bad"token`,
		Origin: "http://127.0.0.1:1",
	})
	// The token must be JSON-encoded inside the snippet, never raw.
	if strings.Contains(s, `bad"token"`) {
		t.Fatalf("token was not JSON-escaped: %s", s)
	}
	if !strings.Contains(s, `bad\"token`) {
		t.Fatalf("expected JSON-escaped token, got: %s", s)
	}
}

func TestAuthInterceptorIncludesHookSites(t *testing.T) {
	s := AuthInterceptor(AuthConfig{Token: "tok", Origin: "http://127.0.0.1:1"})
	for _, want := range []string{
		"window.fetch",
		"XMLHttpRequest.prototype.open",
		"XMLHttpRequest.prototype.send",
		"Authorization",
		"Bearer tok",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("snippet missing %q\n%s", want, s)
		}
	}
}

func TestAuthInterceptorCustomHeader(t *testing.T) {
	s := AuthInterceptor(AuthConfig{
		Token:      "tok",
		Origin:     "http://127.0.0.1:1",
		HeaderName: "X-Weft-Token",
		Prefix:     "Token ",
	})
	if !strings.Contains(s, "X-Weft-Token") {
		t.Fatalf("expected custom header in snippet: %s", s)
	}
	if !strings.Contains(s, `"Token tok"`) {
		t.Fatalf("expected custom-prefix token in snippet: %s", s)
	}
}
