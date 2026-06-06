package control

import (
	"context"
	"testing"
	"time"

	"github.com/openweft/weft-app-core/failover"
)

func TestServerPublishAndWatch(t *testing.T) {
	s := NewServer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}

	changes := make(chan Active, 8)
	cl := &Client{BaseURL: base, Interval: 10 * time.Millisecond}
	go cl.Watch(ctx, func(_, cur Active) { changes <- cur })

	s.Publish(failover.Switch{ToName: "DC-A"})
	if got := <-changes; got.Name != "DC-A" {
		t.Fatalf("first change = %+v want DC-A", got)
	}

	s.Publish(failover.Switch{ToName: "DC-B", FromName: "DC-A"})
	if got := <-changes; got.Name != "DC-B" {
		t.Fatalf("second change = %+v want DC-B", got)
	}

	s.Publish(failover.Switch{AllDown: true})
	if got := <-changes; !got.AllDown {
		t.Fatalf("third change = %+v want allDown", got)
	}
}
