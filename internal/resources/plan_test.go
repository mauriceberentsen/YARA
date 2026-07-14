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
			Topology: PlanTopology{
				Instances:   []PlanInstance{{ID: "inference", Role: "inference.text-generation", RuntimeRef: "runtime", ModelRef: "model", Placement: "host/gpu", APIContract: "api"}},
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
