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
	search := result.Plan.Spec.Search
	if !search.CompleteWithinBounds || search.Truncated || search.GlobalOptimalityClaimed || search.EvaluatedServingCandidates != 2 || search.FeasibleServingCandidates != 1 || search.RejectedServingCandidates != 1 {
		t.Fatalf("unexpected search summary: %#v", search)
	}
	confidence := result.Plan.Spec.Confidence
	if confidence.Level != "low" || confidence.Method != "minimum-factor-v1" || len(confidence.Factors) != 4 {
		t.Fatalf("unexpected confidence summary: %#v", confidence)
	}
	if confidence.Factors[3].ID != "serving-evidence" || confidence.Factors[3].Level != "medium" {
		t.Fatalf("serving evidence confidence was not preserved: %#v", confidence.Factors)
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

func TestCuratedV02CatalogPlansRealCodingStack(t *testing.T) {
	request, err := resources.LoadPlatformRequest(filepath.Join("..", "..", "docs", "examples", "v0.2-platform-request.yaml"))
	if err != nil {
		t.Fatalf("load v0.2 request: %v", err)
	}
	inventory, err := resources.LoadInventory(filepath.Join("..", "..", "docs", "examples", "v0.2-inventory.yaml"))
	if err != nil {
		t.Fatalf("load v0.2 inventory: %v", err)
	}
	snapshot, err := catalog.Load(filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load v0.2 catalog: %v", err)
	}
	if len(snapshot.Candidates()) != 6 {
		t.Fatalf("expected six real serving candidates, got %d", len(snapshot.Candidates()))
	}
	if components := snapshot.ComponentsForRole("interface.web-chat"); len(components) != 0 {
		t.Fatalf("known-only Open WebUI must not be selectable: %#v", components)
	}

	result := Create(request, inventory, snapshot)
	if !result.Report.Valid {
		t.Fatalf("planning with v0.2 catalog failed: %#v", result.Report.Diagnostics)
	}
	decision := result.Plan.Spec.Decisions[0]
	if decision.Selected != "compat.vllm-qwen-coder-7b-awq-rtx4090" {
		t.Fatalf("expected coding model on RTX 4090, got %s", decision.Selected)
	}
	if len(result.Plan.Spec.Topology.Instances) != 2 || result.Plan.Spec.Topology.Instances[0].ComponentRef != "core.litellm@1.93.0" || result.Plan.Spec.Topology.Instances[1].ComponentRef != "core.vllm@0.25.1" {
		t.Fatalf("unexpected real component topology: %#v", result.Plan.Spec.Topology.Instances)
	}
	if !containsPlanDiagnostic(result.Plan.Spec.Diagnostics, "YARA-CAT-055") {
		t.Fatalf("experimental evidence warning missing from v0.2 plan: %#v", result.Plan.Spec.Diagnostics)
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

func TestEveryServingHardConstraintHasFailingCounterexample(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		mutate   func(*resources.PlatformRequest, *resources.Inventory, *catalog.ServingCandidate)
	}{
		{"hardware assertion", "YARA-HW-002", func(_ *resources.PlatformRequest, inventory *resources.Inventory, _ *catalog.ServingCandidate) {
			inventory.Spec.Hosts[0].Accelerators[0].Model = "unasserted-device"
		}},
		{"context envelope", "YARA-CAP-002", func(request *resources.PlatformRequest, _ *resources.Inventory, candidate *catalog.ServingCandidate) {
			candidate.Conditions.MaximumContextTokens = request.Spec.Workload.MaximumContextTokens - 1
		}},
		{"driver minimum", "YARA-HW-003", func(_ *resources.PlatformRequest, inventory *resources.Inventory, candidate *catalog.ServingCandidate) {
			candidate.Conditions.MinimumDriverVersion = "535"
			inventory.Spec.Hosts[0].Accelerators[0].DriverVersion = "534.99"
		}},
		{"required capability", "YARA-CAP-001", func(_ *resources.PlatformRequest, _ *resources.Inventory, candidate *catalog.ServingCandidate) {
			candidate.Capabilities = []string{"chat"}
		}},
		{"open source", "YARA-POL-010", func(_ *resources.PlatformRequest, _ *resources.Inventory, candidate *catalog.ServingCandidate) {
			candidate.Policy.OpenSource = false
		}},
		{"external egress", "YARA-POL-011", func(_ *resources.PlatformRequest, _ *resources.Inventory, candidate *catalog.ServingCandidate) {
			candidate.Policy.ExternalEgress = true
		}},
		{"telemetry", "YARA-POL-012", func(_ *resources.PlatformRequest, _ *resources.Inventory, candidate *catalog.ServingCandidate) {
			candidate.Policy.Telemetry = true
		}},
		{"artifact verification", "YARA-POL-013", func(_ *resources.PlatformRequest, _ *resources.Inventory, candidate *catalog.ServingCandidate) {
			candidate.Policy.ArtifactVerified = false
		}},
		{"accelerator memory", "YARA-HW-004", func(_ *resources.PlatformRequest, inventory *resources.Inventory, _ *catalog.ServingCandidate) {
			inventory.Spec.Hosts[0].Accelerators[0].AllocatableMemoryGiB = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, inventory, snapshot := loadGoldenInputs(t)
			candidate := snapshot.Candidates()[0]
			test.mutate(&request, &inventory, &candidate)
			result := evaluate(request, inventory.Spec.Hosts[0].Accelerators[0], candidate)
			if result.Rejection == nil || result.Rejection.Code != test.expected {
				t.Fatalf("expected %s, got %#v", test.expected, result.Rejection)
			}
		})
	}
}

func TestEveryGatewayPolicyConstraintHasFailingCounterexample(t *testing.T) {
	request, _, snapshot := loadGoldenInputs(t)
	components := snapshot.ComponentsForRole("gateway.openai-compatible")
	if len(components) != 1 {
		t.Fatalf("expected one gateway fixture, got %d", len(components))
	}
	tests := []struct {
		name   string
		mutate func(*catalog.ComponentCandidate)
	}{
		{"open source", func(component *catalog.ComponentCandidate) { component.Policy.OpenSource = false }},
		{"external egress", func(component *catalog.ComponentCandidate) { component.Policy.ExternalEgress = true }},
		{"telemetry", func(component *catalog.ComponentCandidate) { component.Policy.Telemetry = true }},
		{"artifact verification", func(component *catalog.ComponentCandidate) { component.Policy.ArtifactVerified = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			component := components[0]
			test.mutate(&component)
			if componentAllowed(request, component) {
				t.Fatal("policy-incompatible gateway was allowed")
			}
		})
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
