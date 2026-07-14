package catalog

import (
	"path/filepath"
	"testing"
)

func TestLoadFirstSnapshot(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	if len(snapshot.Spec.Candidates) != 2 {
		t.Fatalf("expected two candidates, got %d", len(snapshot.Spec.Candidates))
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatalf("digest catalog: %v", err)
	}
	if len(digest) != len("sha256:")+64 {
		t.Fatalf("unexpected digest %q", digest)
	}
}

func TestCatalogRejectsDuplicateCandidate(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	snapshot.Spec.Candidates[1].ID = snapshot.Spec.Candidates[0].ID
	if report := snapshot.Validate(); report.Valid {
		t.Fatal("expected duplicate candidate to be invalid")
	}
}
