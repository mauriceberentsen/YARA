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
	if !containsDiagnostic(governance, "YARA-CAT-040") || !containsDiagnostic(governance, "YARA-CAT-055") {
		t.Fatalf("expected quarantined compatibility warning, got %#v", governance)
	}
	topology, ok := snapshot.SelectTopology([]string{"chat", "coding"})
	if !ok || topology.ID != "core.private-chat-coding" || len(topology.Roles) != 2 || len(topology.DeploymentStages) != 2 {
		t.Fatalf("expected compiled multi-component topology, got %#v", topology)
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

func TestCuratedV02SnapshotCompilesOnlyBoundedEvidence(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load curated catalog: %v", err)
	}
	if candidates := snapshot.Candidates(); len(candidates) != 6 {
		t.Fatalf("expected six compatibility-bounded candidates, got %d", len(candidates))
	} else {
		for _, candidate := range candidates {
			if candidate.Conditions.RuntimeVersion != "0.25.1" || candidate.Conditions.ModelRevision == "" || candidate.Conditions.MinimumDriverVersion == "" || candidate.Conditions.ComputePlatform != "cuda-13.0" || candidate.Conditions.MaximumContextTokens != 32768 {
				t.Fatalf("candidate lost its compatibility envelope: %#v", candidate)
			}
			for _, evidence := range candidate.Evidence {
				if evidence.Source == "" {
					t.Fatalf("candidate evidence is not traceable: %#v", candidate)
				}
			}
		}
	}
	components := make(map[string]ComponentManifest, len(snapshot.manifests.Components))
	for _, component := range snapshot.manifests.Components {
		components[component.Metadata.ID] = component
	}
	if components["core.open-webui"].Spec.Policy.OpenSource || components["core.open-webui"].Spec.License == nil || components["core.open-webui"].Spec.License.OSIApproved {
		t.Fatal("Open WebUI branding license was incorrectly represented as OSI open source")
	}
	if components["core.langfuse"].Spec.Policy.OpenSource || components["core.langfuse"].Spec.License == nil || components["core.langfuse"].Spec.License.OSIApproved {
		t.Fatal("Langfuse published image was incorrectly represented as wholly OSI open source")
	}
	if !components["core.qdrant"].Spec.Policy.Telemetry || !components["core.grafana"].Spec.Policy.Telemetry {
		t.Fatal("conservative upstream telemetry facts must remain visible until hardened profiles are tested")
	}
}

func TestCatalogRejectsStaleManifestAtSnapshotTime(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	snapshot.manifests.Components[0].Provenance.ReviewAfter = snapshot.Metadata.PublishedAt
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-054") {
		t.Fatalf("expected stale evidence error, got %#v", report.Diagnostics)
	}
}

func TestCatalogRejectsMissingManifestOwner(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	snapshot.manifests.Models[0].Metadata.Owners = nil
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-051") {
		t.Fatalf("expected ownership error, got %#v", report.Diagnostics)
	}
}

func TestCatalogRejectsIncompleteSupportedComponentEvidence(t *testing.T) {
	snapshot := loadTestSnapshot(t)
	component := &snapshot.manifests.Components[0]
	component.Metadata.Status = "supported"
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-057") {
		t.Fatalf("expected incomplete component evidence error, got %#v", report.Diagnostics)
	}
}

func TestCatalogRejectsMalformedImmutableArtifact(t *testing.T) {
	snapshot := loadTestSnapshot(t)
	component := &snapshot.manifests.Components[0]
	component.Spec.Category = "gateway"
	component.Spec.UpstreamVersion = component.Metadata.Version
	component.Spec.Homepage = "https://example.invalid/gateway"
	component.Spec.Health = &HealthContract{Protocol: "http", Path: "/health"}
	component.Spec.License = &LicenseFacts{ID: "Apache-2.0", Source: "https://example.invalid/license", OSIApproved: true, Redistribution: "allowed"}
	component.Spec.Artifacts = []ArtifactReference{{Type: "oci-image", Ref: "example.invalid/gateway:1.0.0", Digest: "latest", Platforms: []string{"linux/amd64"}}}
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-065") {
		t.Fatalf("expected malformed artifact error, got %#v", report.Diagnostics)
	}
}

func TestCatalogRejectsLicensePolicyMismatch(t *testing.T) {
	snapshot := loadTestSnapshot(t)
	component := &snapshot.manifests.Components[0]
	component.Spec.Category = "gateway"
	component.Spec.UpstreamVersion = component.Metadata.Version
	component.Spec.Homepage = "https://example.invalid/gateway"
	component.Spec.Health = &HealthContract{Protocol: "http", Path: "/health"}
	component.Spec.License = &LicenseFacts{ID: "LicenseRef-Proprietary", Source: "https://example.invalid/license", OSIApproved: false, Redistribution: "forbidden"}
	component.Spec.Artifacts = []ArtifactReference{{Type: "oci-image", Ref: "example.invalid/gateway:1.0.0", Digest: "sha256:" + strings.Repeat("a", 64), Platforms: []string{"linux/amd64"}}}
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-063") {
		t.Fatalf("expected license policy mismatch error, got %#v", report.Diagnostics)
	}
}

func TestCatalogRejectsCompatibilityVersionDrift(t *testing.T) {
	snapshot := loadTestSnapshot(t)
	assertion := &snapshot.manifests.Compatibility[0]
	assertion.Spec.Conditions = &CompatibilityConditions{RuntimeVersion: "9.9.9", ModelRevision: strings.Repeat("b", 40)}
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-061") || !containsDiagnostic(report.Diagnostics, "YARA-CAT-062") {
		t.Fatalf("expected runtime and model revision mismatch errors, got %#v", report.Diagnostics)
	}
}

func TestCatalogRejectsUntraceableOrOverbroadCompatibilityBounds(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load curated catalog: %v", err)
	}
	assertion := &snapshot.manifests.Compatibility[0]
	assertion.Spec.Evidence[0].Source = ""
	for index := range snapshot.manifests.Models {
		if snapshot.manifests.Models[index].Metadata.ID == assertion.Spec.ModelRef {
			assertion.Spec.Conditions.MaximumContextTokens = snapshot.manifests.Models[index].Spec.ContextTokens + 1
		}
	}
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-067") || !containsDiagnostic(report.Diagnostics, "YARA-CAT-069") {
		t.Fatalf("expected traceability and model context errors, got %#v", report.Diagnostics)
	}
}

func TestCatalogRejectsCyclicTopology(t *testing.T) {
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	topology := snapshot.manifests.Topologies[0]
	topology.Spec.Connections = append(topology.Spec.Connections, TopologyConnection{
		From: "inference", To: "gateway", Contract: "integration.api.openai-chat/v1",
	})
	snapshot.manifests.Topologies[0] = topology
	if report := snapshot.Validate(); report.Valid || !containsDiagnostic(report.Diagnostics, "YARA-CAT-047") {
		t.Fatalf("expected topology cycle error, got %#v", report.Diagnostics)
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

func loadTestSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	snapshot, err := Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return &snapshot
}

func TestCatalogRejectsManifestPathTraversal(t *testing.T) {
	root := t.TempDir()
	index := []byte("apiVersion: yara.dev/v1alpha1\nkind: CatalogSnapshot\nmetadata:\n  name: traversal\n  version: 0.1.0\n  publishedAt: 2026-07-15T00:00:00Z\nspec:\n  manifests: [../outside.yaml]\n")
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
	index := []byte("apiVersion: yara.dev/v1alpha1\nkind: CatalogSnapshot\nmetadata:\n  name: symlink\n  version: 0.1.0\n  publishedAt: 2026-07-15T00:00:00Z\nspec:\n  manifests: [linked.yaml]\n")
	path := filepath.Join(root, "snapshot.yaml")
	if err := os.WriteFile(path, index, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink escape rejection, got %v", err)
	}
}
