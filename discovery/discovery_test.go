package discovery

import (
	"context"
	"net"
	"testing"
)

type stubResolver struct {
	srv  []*net.SRV
	host []string
	err  error
}

func (s stubResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", s.srv, s.err
}
func (s stubResolver) LookupHost(context.Context, string) ([]string, error) {
	return s.host, s.err
}

func TestSRVOrdersByPriorityThenName(t *testing.T) {
	r := stubResolver{srv: []*net.SRV{
		{Target: "weft-c.weft.internal.", Port: 8443, Priority: 0, Weight: 33},
		{Target: "weft-a.weft.internal.", Port: 8443, Priority: 0, Weight: 33},
		{Target: "weft-b.weft.internal.", Port: 8443, Priority: 10, Weight: 33},
	}}
	ts, err := SRV(context.Background(), "weft-webui", "tcp", "weft.internal", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 3 {
		t.Fatalf("got %d targets", len(ts))
	}
	// Priority 0 group sorted by name (a before c); priority 10 last.
	if ts[0].Name != "weft-a" || ts[1].Name != "weft-c" || ts[2].Name != "weft-b" {
		t.Fatalf("order = %q,%q,%q", ts[0].Name, ts[1].Name, ts[2].Name)
	}
	if ts[0].Addr() != "weft-a.weft.internal:8443" {
		t.Fatalf("addr = %q", ts[0].Addr())
	}
}

func TestAFallbackOneTargetPerAddress(t *testing.T) {
	r := stubResolver{host: []string{"203.0.113.20", "203.0.113.10"}}
	ts, err := A(context.Background(), "api.weft.example.com", 443, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 {
		t.Fatalf("got %d targets", len(ts))
	}
	// Sorted lexically -> .10 first.
	if ts[0].Host != "203.0.113.10" || ts[0].Addr() != "203.0.113.10:443" {
		t.Fatalf("target0 = %+v", ts[0])
	}
}
