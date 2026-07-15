package planner

import (
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestHigherScoringOversizedCandidateCannotWin(t *testing.T) {
	request, inventory, snapshot := loadGoldenInputs(t)
	result := Create(request, inventory, snapshot)
	if !result.Report.Valid {
		t.Fatalf("planning failed: %#v", result.Report.Diagnostics)
	}
	decision := result.Plan.Spec.Decisions[0]
	if decision.Selected != "core.placeholder-coder-small" {
		t.Fatalf("expected small candidate, got %s", decision.Selected)
	}
	if len(decision.Alternatives) != 1 || decision.Alternatives[0].Code != "YARA-HW-004" {
		t.Fatalf("expected YARA-HW-004 rejection, got %#v", decision.Alternatives)
	}
	selectedScore := 0.0
	for _, candidate := range snapshot.Candidates() {
		if candidate.ID == decision.Selected {
			selectedScore = candidate.PreferenceScore
		}
	}
	if decision.Alternatives[0].PreferenceScore <= selectedScore {
		t.Fatal("fixture must prove the rejected candidate had a higher preference score")
	}
	if !containsPlanDiagnostic(result.Plan.Spec.Diagnostics, "YARA-CAT-040") {
		t.Fatalf("expected catalog governance diagnostic in plan: %#v", result.Plan.Spec.Diagnostics)
	}
	if !containsPlanDiagnostic(result.Plan.Spec.Diagnostics, "YARA-CAT-055") {
		t.Fatalf("expected experimental catalog warning in plan: %#v", result.Plan.Spec.Diagnostics)
	}
	topology := result.Plan.Spec.Topology
	if len(topology.Instances) != 2 || len(topology.Connections) != 1 || len(topology.DeploymentStages) != 2 {
		t.Fatalf("expected two-role topology, got %#v", topology)
	}
	if topology.Instances[0].ID != "gateway" || topology.Instances[0].ComponentRef != "core.placeholder-gateway@1.0.0" {
		t.Fatalf("expected resolved gateway instance, got %#v", topology.Instances[0])
	}
	if topology.DeploymentStages[0][0] != "inference" || topology.DeploymentStages[1][0] != "gateway" {
		t.Fatalf("dependency stages are unsafe: %#v", topology.DeploymentStages)
	}
}

func containsPlanDiagnostic(items []diagnostics.Diagnostic, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

func TestPlanIsDeterministic(t *testing.T) {
	request, inventory, snapshot := loadGoldenInputs(t)
	first := Create(request, inventory, snapshot)
	second := Create(request, inventory, snapshot)
	if first.Plan.Metadata.PlanID != second.Plan.Metadata.PlanID {
		t.Fatalf("plan IDs differ: %s != %s", first.Plan.Metadata.PlanID, second.Plan.Metadata.PlanID)
	}
}

func TestNoFeasibleCandidateReturnsDiagnostic(t *testing.T) {
	request, inventory, snapshot := loadGoldenInputs(t)
	inventory.Spec.Hosts[0].Accelerators[0].AllocatableMemoryGiB = 1
	result := Create(request, inventory, snapshot)
	if result.Report.Valid {
		t.Fatal("expected planning to fail")
	}
	if result.Report.Diagnostics[0].Code != "YARA-PLAN-001" {
		t.Fatalf("unexpected diagnostic: %#v", result.Report.Diagnostics)
	}
}

func TestCandidateRequiresExplicitHardwareCompatibility(t *testing.T) {
	request, inventory, snapshot := loadGoldenInputs(t)
	inventory.Spec.Hosts[0].Accelerators[0].Model = "unasserted-device"
	evaluated := evaluate(request, inventory.Spec.Hosts[0].Accelerators[0], snapshot.Candidates()[0])
	if evaluated.Rejection == nil || evaluated.Rejection.Code != "YARA-HW-002" {
		t.Fatalf("expected explicit hardware compatibility rejection, got %#v", evaluated.Rejection)
	}
}

func loadGoldenInputs(t *testing.T) (resources.PlatformRequest, resources.Inventory, catalog.Snapshot) {
	t.Helper()
	request, err := resources.LoadPlatformRequest(filepath.Join("..", "..", "docs", "examples", "platform-request.yaml"))
	if err != nil {
		t.Fatalf("load request: %v", err)
	}
	inventory, err := resources.LoadInventory(filepath.Join("..", "..", "docs", "examples", "inventory.yaml"))
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	snapshot, err := catalog.Load(filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return request, inventory, snapshot
}
