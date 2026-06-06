package failover

import (
	"context"
	"testing"
	"time"

	"github.com/openweft/weft-app-core/transport"
)

// mkClusterSup builds a supervisor over endpoints that carry a Cluster
// tag — the cluster_filter tests need the cluster metadata that
// mkSup() in supervisor_test.go doesn't set.
func mkClusterSup(eps []transport.Endpoint) (*Supervisor, *[]Switch) {
	var switches []Switch
	now := time.Now()
	s := New(eps, Options{
		HoldDown:     0,
		ProbeTimeout: time.Millisecond,
		Now:          func() time.Time { return now },
		OnSwitch:     func(sw Switch) { switches = append(switches, sw) },
	})
	return s, &switches
}

func TestSetClusterFilter_QuarantinesOtherClusters(t *testing.T) {
	bP1 := &fakeBackend{}
	bP1.set(true)
	bP2 := &fakeBackend{}
	bP2.set(true)
	bT1 := &fakeBackend{}
	bT1.set(true)
	eps := []transport.Endpoint{
		{Name: "p1", Cluster: "paris", ClusterLabel: "Paris", Backend: bP1},
		{Name: "p2", Cluster: "paris", ClusterLabel: "Paris", Backend: bP2},
		{Name: "t1", Cluster: "tokyo", ClusterLabel: "Tokyo", Backend: bT1},
	}
	s, switches := mkClusterSup(eps)

	// One round of probes brings everything Up + selects p1 (priority 0).
	s.round(context.Background())
	if a, ok := s.Active(); !ok || a.Name != "p1" {
		t.Fatalf("initial active = %+v ok=%v ; want p1", a, ok)
	}

	// Switch to tokyo : p1 + p2 quarantined ; t1 becomes active.
	s.SetClusterFilter("tokyo")
	if a, ok := s.Active(); !ok || a.Name != "t1" {
		t.Errorf("after filter=tokyo active = %+v ; want t1", a)
	}
	if got := len(*switches); got < 2 {
		t.Errorf("switches = %d ; want at least 2 (initial select + filter switch)", got)
	}

	// Switch back to paris : p1 reselected.
	s.SetClusterFilter("paris")
	if a, _ := s.Active(); a.Name != "p1" {
		t.Errorf("back to paris active = %+v ; want p1", a)
	}

	// Empty filter : p1 still wins (legacy flat pool, top priority).
	s.SetClusterFilter("")
	if a, _ := s.Active(); a.Name != "p1" {
		t.Errorf("clear filter active = %+v ; want p1 (unchanged)", a)
	}
}

func TestSetClusterFilter_QuarantinedStillProbed(t *testing.T) {
	bP1 := &fakeBackend{}
	bP1.set(true)
	bT1 := &fakeBackend{}
	bT1.set(true)
	eps := []transport.Endpoint{
		{Name: "p1", Cluster: "paris", Backend: bP1},
		{Name: "t1", Cluster: "tokyo", Backend: bT1},
	}
	s, _ := mkClusterSup(eps)

	s.SetClusterFilter("paris")
	s.round(context.Background())

	snap := s.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d ; want 2", len(snap))
	}
	for _, st := range snap {
		if st.Health != Up {
			t.Errorf("%s health = %v ; want Up (probes run on disabled endpoints too)", st.Name, st.Health)
		}
	}
}

func TestClusters_DedupOrder(t *testing.T) {
	eps := []transport.Endpoint{
		{Name: "p1", Cluster: "paris", Backend: &fakeBackend{}},
		{Name: "t1", Cluster: "tokyo", Backend: &fakeBackend{}},
		{Name: "p2", Cluster: "paris", Backend: &fakeBackend{}},
		{Name: "n1", Cluster: "nairobi", Backend: &fakeBackend{}},
	}
	s, _ := mkClusterSup(eps)
	got := s.Clusters()
	want := []string{"paris", "tokyo", "nairobi"}
	if len(got) != len(want) {
		t.Fatalf("clusters = %v ; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("clusters[%d] = %q ; want %q", i, got[i], want[i])
		}
	}
}
