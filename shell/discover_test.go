package shell

import (
	"context"
	"net"
	"testing"
)

type stubResolver struct {
	srv []*net.SRV
}

func (s stubResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", s.srv, nil
}
func (s stubResolver) LookupHost(context.Context, string) ([]string, error) {
	return nil, nil
}

func TestDiscoverBuildsDirectEndpointsFromSRV(t *testing.T) {
	r := stubResolver{srv: []*net.SRV{
		{Target: "weft-a.weft.internal.", Port: 8080, Priority: 0},
		{Target: "weft-b.weft.internal.", Port: 8080, Priority: 0},
	}}

	sh, err := Discover(context.Background(), "weft-webui", "tcp", "weft.internal", r,
		Config{GatewayAddr: "127.0.0.1:0"}, Options{})
	if err != nil {
		t.Fatal(err)
	}

	st := sh.Status()
	if len(st) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(st))
	}
	if st[0].Name != "weft-a" || st[0].Target != "weft-a.weft.internal:8080" {
		t.Fatalf("endpoint[0] = %+v", st[0])
	}
	if st[1].Name != "weft-b" {
		t.Fatalf("endpoint[1] = %+v", st[1])
	}
}

func TestDiscoverErrorsOnNoTargets(t *testing.T) {
	if _, err := Discover(context.Background(), "weft-webui", "tcp", "weft.internal",
		stubResolver{}, Config{}, Options{}); err == nil {
		t.Fatal("expected error when SRV returns no targets")
	}
}
