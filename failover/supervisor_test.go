package failover

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/openweft/weft-app-core/transport"
)

// fakeBackend is a Backend whose health is flipped by the test.
type fakeBackend struct {
	mu sync.Mutex
	up bool
}

func (f *fakeBackend) set(up bool) { f.mu.Lock(); f.up = up; f.mu.Unlock() }

func (f *fakeBackend) Probe(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.up {
		return nil
	}
	return errors.New("down")
}
func (f *fakeBackend) Dial(context.Context) (net.Conn, error) { return nil, errors.New("no dial") }
func (f *fakeBackend) Target() string                         { return "fake" }
func (f *fakeBackend) Close() error                           { return nil }

func mkSup(now *time.Time, holddown time.Duration, backends ...*fakeBackend) (*Supervisor, *[]Switch) {
	var switches []Switch
	eps := make([]transport.Endpoint, len(backends))
	names := []string{"A", "B", "C", "D"}
	for i, b := range backends {
		eps[i] = transport.Endpoint{Name: names[i], Backend: b}
	}
	s := New(eps, Options{
		HoldDown: holddown,
		Now:      func() time.Time { return *now },
		OnSwitch: func(sw Switch) { switches = append(switches, sw) },
	})
	return s, &switches
}

func activeName(t *testing.T, s *Supervisor) string {
	t.Helper()
	ep, ok := s.Active()
	if !ok {
		return ""
	}
	return ep.Name
}

func TestColdStartPicksTopHealthyImmediately(t *testing.T) {
	now := time.Unix(0, 0)
	a, b := &fakeBackend{up: true}, &fakeBackend{up: true}
	s, sw := mkSup(&now, 15*time.Second, a, b)

	s.round(context.Background())

	if got := activeName(t, s); got != "A" {
		t.Fatalf("cold start: active=%q want A", got)
	}
	if len(*sw) != 1 || (*sw)[0].ToName != "A" || (*sw)[0].FromName != "" {
		t.Fatalf("cold start switch = %+v", *sw)
	}
}

func TestFailoverIsImmediate(t *testing.T) {
	now := time.Unix(0, 0)
	a, b := &fakeBackend{up: true}, &fakeBackend{up: true}
	s, sw := mkSup(&now, 15*time.Second, a, b)
	s.round(context.Background()) // -> A

	a.set(false)
	now = now.Add(time.Second)
	s.round(context.Background()) // A down, B already long-healthy -> B now

	if got := activeName(t, s); got != "B" {
		t.Fatalf("after A down: active=%q want B", got)
	}
	last := (*sw)[len(*sw)-1]
	if last.FromName != "A" || last.ToName != "B" || last.AllDown {
		t.Fatalf("failover switch = %+v", last)
	}
}

func TestFailBackWaitsForHoldDown(t *testing.T) {
	now := time.Unix(0, 0)
	a, b := &fakeBackend{up: true}, &fakeBackend{up: true}
	s, _ := mkSup(&now, 15*time.Second, a, b)
	s.round(context.Background()) // -> A

	a.set(false)
	now = now.Add(time.Second)
	s.round(context.Background()) // -> B

	// A recovers, but hold-down (15s) hasn't elapsed: stay on B.
	a.set(true)
	now = now.Add(time.Second) // A.upSince = t=2s
	s.round(context.Background())
	if got := activeName(t, s); got != "B" {
		t.Fatalf("within hold-down: active=%q want B (no flap)", got)
	}

	// Past the hold-down window from A.upSince: fail back to preferred A.
	now = now.Add(20 * time.Second)
	s.round(context.Background())
	if got := activeName(t, s); got != "A" {
		t.Fatalf("after hold-down: active=%q want A", got)
	}
}

func TestAllDownThenRecover(t *testing.T) {
	now := time.Unix(0, 0)
	a, b := &fakeBackend{up: true}, &fakeBackend{up: true}
	s, sw := mkSup(&now, 15*time.Second, a, b)
	s.round(context.Background()) // -> A

	a.set(false)
	b.set(false)
	now = now.Add(time.Second)
	s.round(context.Background())
	if _, ok := s.Active(); ok {
		t.Fatalf("all down: expected no active endpoint")
	}
	if last := (*sw)[len(*sw)-1]; !last.AllDown {
		t.Fatalf("expected AllDown switch, got %+v", last)
	}

	// Only B comes back — even though it just came up, we take it at once
	// (no active DC to protect, so hold-down doesn't apply).
	b.set(true)
	now = now.Add(time.Second)
	s.round(context.Background())
	if got := activeName(t, s); got != "B" {
		t.Fatalf("recovery: active=%q want B (immediate, no hold-down)", got)
	}
}

func TestStaysOnPreferredWhenHealthy(t *testing.T) {
	now := time.Unix(0, 0)
	a, b := &fakeBackend{up: true}, &fakeBackend{up: true}
	s, sw := mkSup(&now, 15*time.Second, a, b)
	s.round(context.Background()) // -> A
	// B flapping should never matter while A is healthy.
	for i := 0; i < 5; i++ {
		b.set(i%2 == 0)
		now = now.Add(time.Second)
		s.round(context.Background())
	}
	if got := activeName(t, s); got != "A" {
		t.Fatalf("active=%q want A (B flap must not whipsaw)", got)
	}
	if len(*sw) != 1 {
		t.Fatalf("expected exactly 1 switch (initial), got %d: %+v", len(*sw), *sw)
	}
}
