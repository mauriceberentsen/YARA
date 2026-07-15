package resources

import (
	"testing"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

func TestPlatformPlanValidationDetectsTampering(t *testing.T) {
	plan := validPlan(t)
	if report := plan.Validate(); !report.Valid {
		t.Fatalf("expected initial plan to be valid: %#v", report.Diagnostics)
	}
	plan.Spec.Topology.Instances[0].ModelRef = "core.tampered-model@1.0.0"
	report := plan.Validate()
	assertDiagnostic(t, report, "YARA-PLAN-014", "metadata.planId")
}

func TestPlatformPlanRejectsUnsafeDeploymentOrder(t *testing.T) {
	plan := validPlan(t)
	plan.Spec.Topology.Instances = append(plan.Spec.Topology.Instances, PlanInstance{
		ID: "gateway", Role: "gateway", ComponentRef: "gateway", Placement: "host", APIContracts: []string{"api"},
	})
	plan.Spec.Topology.Connections = []PlanConnection{{From: "gateway", To: "inference", Contract: "api"}}
	plan.Spec.Topology.DeploymentStages = [][]string{{"gateway"}, {"inference"}}
	plan, err := plan.AssignPlanID()
	if err != nil {
		t.Fatalf("assign plan ID: %v", err)
	}
	if report := plan.Validate(); report.Valid || !hasDiagnostic(report.Diagnostics, "YARA-PLAN-022") {
		t.Fatalf("expected unsafe deployment order diagnostic, got %#v", report.Diagnostics)
	}
}

func hasDiagnostic(items []diagnostics.Diagnostic, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

func validPlan(t *testing.T) PlatformPlan {
	t.Helper()
	plan := PlatformPlan{
		APIVersion: APIVersion,
		Kind:       "PlatformPlan",
		Metadata:   PlanMetadata{Name: "test-plan"},
		Provenance: PlanProvenance{
			RequestDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			InventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			CatalogDigest:   "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			PlannerVersion:  "0.1.0-dev",
		},
		Spec: PlatformPlanSpec{
			Status: "review-required",
			Search: PlanSearchSummary{
				Strategy: "bounded-catalog-enumeration-v1", CompleteWithinBounds: true,
				EvaluatedServingCandidates: 1, FeasibleServingCandidates: 1, RejectedServingCandidates: 0,
				Boundaries: []string{"test-fixture-only"},
			},
			Confidence: PlanConfidenceSummary{
				Level: "medium", Method: "minimum-factor-v1",
				Factors: []PlanConfidenceFactor{{ID: "test-evidence", Level: "medium", ReasonCode: "YARA-CONF-001", SubjectRefs: []string{"candidate"}}},
			},
			Topology: PlanTopology{
				Instances:   []PlanInstance{{ID: "inference", Role: "inference.text-generation", ComponentRef: "runtime", ModelRef: "model", Placement: "host/gpu", APIContracts: []string{"api"}}},
				Connections: []PlanConnection{}, DeploymentStages: [][]string{{"inference"}},
			},
			Allocations: []PlanAllocation{{InstanceID: "inference", AcceleratorID: "gpu", EstimatedMemoryGiB: 1, AllocatableMemoryGiB: 2}},
			Decisions:   []PlanDecision{{ID: "decision", Selected: "candidate", Reasons: []string{"reason"}, Evidence: []string{"evidence"}, Alternatives: []PlanAlternative{}}},
			Diagnostics: []diagnostics.Diagnostic{},
		},
	}
	assigned, err := plan.AssignPlanID()
	if err != nil {
		t.Fatalf("assign plan ID: %v", err)
	}
	return assigned
}

func TestPlatformPlanRejectsInconsistentSearchAndConfidence(t *testing.T) {
	plan := validPlan(t)
	plan.Spec.Search.EvaluatedServingCandidates = 2
	plan.Spec.Confidence.Level = "high"
	plan, err := plan.AssignPlanID()
	if err != nil {
		t.Fatalf("assign plan ID: %v", err)
	}
	report := plan.Validate()
	assertDiagnostic(t, report, "YARA-PLAN-026", "spec.search")
	assertDiagnostic(t, report, "YARA-PLAN-037", "spec.confidence.level")
}
