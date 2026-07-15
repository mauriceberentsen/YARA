package planner

import (
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
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
