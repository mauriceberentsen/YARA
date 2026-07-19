package renderer

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/planner"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestDockerComposeRenderIsDeterministicAndPinned(t *testing.T) {
	plan, snapshot := v02Plan(t)
	renderer := DockerCompose{}
	first, err := renderer.Render("reference-stack", plan, snapshot)
	if err != nil {
		t.Fatalf("render first bundle: %v", err)
	}
	second, err := renderer.Render("reference-stack", plan, snapshot)
	if err != nil {
		t.Fatalf("render second bundle: %v", err)
	}
	if !reflect.DeepEqual(first, second) || first.Metadata.BundleID != second.Metadata.BundleID {
		t.Fatal("identical plan and catalog did not produce an identical bundle")
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("bundle is invalid: %#v", report.Diagnostics)
	}
	compose := first.Spec.Files[0].Content
	for _, expected := range []string{
		"vllm/vllm-openai:v0.25.1@sha256:e4f88a835143cd22aee2397a26ec6bb80b3a4a6fe0c882bcbc63822904766089",
		"ghcr.io/berriai/litellm:v1.93.0@sha256:a1745e629abfb17d434426ff48b115f54f4f4c4a0f5af241de569e93c63c411e",
		"internal: true", "read_only: true", "no-new-privileges:true",
	} {
		if !strings.Contains(compose, expected) {
			t.Fatalf("Compose output lacks %q:\n%s", expected, compose)
		}
	}
	if strings.Contains(compose, "ports:") || strings.Contains(compose, "password") || strings.Contains(compose, "token") {
		t.Fatalf("Compose preview exposes an unapproved boundary or secret-like value:\n%s", compose)
	}
	if len(first.Spec.Artifacts) != 3 || first.Spec.Artifacts[0].Type != "huggingface-snapshot" || len(first.Spec.Artifacts[0].Files) != 2 {
		t.Fatalf("immutable artifact inventory is incomplete: %#v", first.Spec.Artifacts)
	}
}

func TestDockerComposeRejectsPlanCatalogMismatch(t *testing.T) {
	plan, _ := v02Plan(t)
	v01, err := catalog.Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load v0.1 catalog: %v", err)
	}
	if _, err := (DockerCompose{}).Render("reference-stack", plan, v01); err == nil {
		t.Fatal("renderer accepted a catalog not bound by the plan")
	}
}

func TestDockerComposeRejectsUnknownAdapter(t *testing.T) {
	plan, snapshot := v02Plan(t)
	plan.Spec.Topology.Instances[0].ComponentRef = "core.unknown@1.0.0"
	assigned, err := plan.AssignPlanID()
	if err != nil {
		t.Fatalf("reassign plan identity: %v", err)
	}
	if _, err := (DockerCompose{}).Render("reference-stack", assigned, snapshot); err == nil {
		t.Fatal("renderer silently replaced an unsupported component")
	}
}

func v02Plan(t *testing.T) (resources.PlatformPlan, catalog.Snapshot) {
	t.Helper()
	root := filepath.Join("..", "..")
	request, err := resources.LoadPlatformRequest(filepath.Join(root, "docs", "examples", "v0.2-platform-request.yaml"))
	if err != nil {
		t.Fatalf("load request: %v", err)
	}
	inventory, err := resources.LoadInventory(filepath.Join(root, "docs", "examples", "v0.2-inventory.yaml"))
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	snapshot, err := catalog.Load(filepath.Join(root, "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	result := planner.Create(request, inventory, snapshot)
	if !result.Report.Valid {
		t.Fatalf("create plan: %#v", result.Report.Diagnostics)
	}
	return result.Plan, snapshot
}
