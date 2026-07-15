package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

func TestLoadFirstSnapshot(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	candidates := snapshot.Candidates()
	if len(candidates) != 2 {
		t.Fatalf("expected two candidates, got %d", len(candidates))
	}
	if candidates[0].HardwareProfileRef == "" || len(candidates[0].HardwareModels) == 0 {
		t.Fatalf("expected hardware compatibility to be compiled: %#v", candidates[0])
	}
	governance := snapshot.Diagnostics()
	if len(governance) != 1 || governance[0].Code != "YARA-CAT-040" || governance[0].Severity != "warning" {
		t.Fatalf("expected quarantined compatibility warning, got %#v", governance)
	}
	for _, candidate := range candidates {
		if candidate.HardwareProfileRef == "core.placeholder-nvidia-conflicted" {
			t.Fatalf("quarantined compatibility tuple became eligible: %#v", candidate)
		}
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatalf("digest catalog: %v", err)
	}
	if len(digest) != len("sha256:")+64 {
		t.Fatalf("unexpected digest %q", digest)
	}
}

func TestCatalogRejectsDuplicatePositiveCompatibilityTuple(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	duplicate := snapshot.manifests.Compatibility[0]
	for _, assertion := range snapshot.manifests.Compatibility {
		if assertion.Metadata.ID == "core.placeholder-coder-small" {
			duplicate = assertion
			break
		}
	}
	duplicate.Metadata.ID = "core.placeholder-coder-small-duplicate"
	snapshot.manifests.Compatibility = append(snapshot.manifests.Compatibility, duplicate)
	snapshot.candidates, snapshot.governanceDiagnostics = compileCandidates(snapshot.manifests)
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-039") {
		t.Fatalf("expected duplicate positive tuple error, got %#v", report.Diagnostics)
	}
}

func containsDiagnostic(items []diagnostics.Diagnostic, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

func TestCatalogRejectsManifestPathTraversal(t *testing.T) {
	root := t.TempDir()
	index := []byte("apiVersion: yara.dev/v1alpha1\nkind: CatalogSnapshot\nmetadata:\n  name: traversal\n  version: 0.1.0\nspec:\n  manifests: [../outside.yaml]\n")
	path := filepath.Join(root, "snapshot.yaml")
	if err := os.WriteFile(path, index, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "escapes the catalog root") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestCatalogRejectsManifestSymlinkEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "catalog")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("create catalog root: %v", err)
	}
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked.yaml")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	index := []byte("apiVersion: yara.dev/v1alpha1\nkind: CatalogSnapshot\nmetadata:\n  name: symlink\n  version: 0.1.0\nspec:\n  manifests: [linked.yaml]\n")
	path := filepath.Join(root, "snapshot.yaml")
	if err := os.WriteFile(path, index, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink escape rejection, got %v", err)
	}
}
