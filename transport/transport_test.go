package transport

import (
	"context"
	"net"
	"testing"
)

func TestDirectTCPProbeAndDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	d := &DirectTCP{Addr: ln.Addr().String()}
	if err := d.Probe(context.Background()); err != nil {
		t.Fatalf("probe up listener: %v", err)
	}
	c, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if d.Target() != ln.Addr().String() {
		t.Fatalf("target = %q", d.Target())
	}
}

func TestDirectTCPProbeFailsWhenDown(t *testing.T) {
	// Bind then close to get a port nothing is listening on.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	d := &DirectTCP{Addr: addr}
	if err := d.Probe(context.Background()); err == nil {
		t.Fatal("expected probe to fail against a closed port")
	}
}

func TestWireGuardNeedsDialer(t *testing.T) {
	w := &WireGuard{MeshAddr: "10.0.0.1:8080"} // no Mesh dialer
	if err := w.Probe(context.Background()); err == nil {
		t.Fatal("expected error when no mesh dialer configured")
	}
	if w.Target() != "wg://10.0.0.1:8080" {
		t.Fatalf("target = %q", w.Target())
	}
}
