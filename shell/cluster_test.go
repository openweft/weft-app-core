package shell

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfig_LegacyEndpoints : a config that still uses the
// pre-cluster shape (endpoints[]) loads and normalises into a single
// "default" cluster. Pinned so a stale operator config doesn't break
// after the rename.
func TestLoadConfig_LegacyEndpoints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.json")
	if err := os.WriteFile(path, []byte(`{
        "endpoints": [
          {"name":"DC-1","kind":"direct","addr":"10.0.0.1:8443"},
          {"name":"DC-2","kind":"direct","addr":"10.0.0.2:8443"}
        ]
      }`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Endpoints) != 2 {
		t.Errorf("Endpoints = %d ; want 2", len(cfg.Endpoints))
	}
	if len(cfg.Clusters) != 0 {
		t.Errorf("Clusters = %d ; want 0 (legacy shape)", len(cfg.Clusters))
	}
	norm := cfg.normalisedClusters()
	if len(norm) != 1 || norm[0].Name != "default" {
		t.Errorf("normalised = %+v ; want one cluster 'default'", norm)
	}
	if len(norm[0].DCs) != 2 || norm[0].DCs[0].Name != "DC-1" {
		t.Errorf("wrapped DCs = %+v", norm[0].DCs)
	}
}

// TestLoadConfig_NewClusters : the canonical clusters[].dcs[] shape
// round-trips field-for-field, with the legacy endpoints[] absent.
func TestLoadConfig_NewClusters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.json")
	if err := os.WriteFile(path, []byte(`{
        "clusters": [
          {
            "name": "paris",
            "display_name": "Paris",
            "dcs": [
              {"name":"salle-jaures","display_name":"Salle Jaurès",
               "kind":"direct","addr":"10.0.0.1:8443"},
              {"name":"salle-bercy","kind":"direct","addr":"10.0.0.2:8443"}
            ]
          },
          {
            "name": "tokyo",
            "dcs": [
              {"name":"shinjuku","kind":"direct","addr":"10.1.0.1:8443"}
            ]
          }
        ]
      }`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Clusters) != 2 {
		t.Fatalf("Clusters = %d ; want 2", len(cfg.Clusters))
	}
	if cfg.Clusters[0].DisplayName != "Paris" {
		t.Errorf("paris display_name = %q", cfg.Clusters[0].DisplayName)
	}
	if cfg.Clusters[1].DisplayName != "" {
		t.Errorf("tokyo display_name should fall back ; got %q", cfg.Clusters[1].DisplayName)
	}
	// EachDC should walk paris (2 DCs) then tokyo (1 DC) for a total of 3.
	var visited []string
	cfg.EachDC(func(cluster ClusterConfig, dc DCConfig, idx int) {
		visited = append(visited, cluster.Name+":"+dc.Name)
	})
	if got, want := visited, []string{"paris:salle-jaures", "paris:salle-bercy", "tokyo:shinjuku"}; len(got) != 3 || got[0] != want[0] || got[2] != want[2] {
		t.Errorf("visit order = %v ; want %v", got, want)
	}
}

// TestLoadConfig_MixedShape : when both shapes coexist (e.g. an
// operator is migrating), endpoints[] becomes the FIRST (legacy
// "default") cluster, then the explicit clusters[] follow.
func TestLoadConfig_MixedShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.json")
	if err := os.WriteFile(path, []byte(`{
        "endpoints": [
          {"name":"old-dc","kind":"direct","addr":"10.0.0.1:8443"}
        ],
        "clusters": [
          {"name":"paris","dcs":[{"name":"jaures","kind":"direct","addr":"10.0.0.2:8443"}]}
        ]
      }`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	norm := cfg.normalisedClusters()
	if len(norm) != 2 {
		t.Fatalf("normalised = %d clusters ; want 2", len(norm))
	}
	if norm[0].Name != "default" || norm[1].Name != "paris" {
		t.Errorf("cluster order = [%q, %q] ; want [default, paris]", norm[0].Name, norm[1].Name)
	}
}
