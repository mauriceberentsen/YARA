package plandiff

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestCompareIdenticalPlansIsNoOp(t *testing.T) {
	plan := loadExamplePlan(t)
	diff, err := Compare(plan, plan)
	if err != nil {
		t.Fatalf("compare plans: %v", err)
	}
	if diff.Spec.Changed || diff.Spec.HighestImpact != resources.DiffImpactNone || len(diff.Spec.Changes) != 0 {
		t.Fatalf("identical plans must produce a no-op diff: %#v", diff.Spec)
	}
	if report := diff.Validate(); !report.Valid {
		t.Fatalf("no-op diff is invalid: %#v", report.Diagnostics)
	}
}

func TestNoOpDiffMatchesDocumentedExample(t *testing.T) {
	plan := loadExamplePlan(t)
	actual, err := Compare(plan, plan)
	if err != nil {
		t.Fatalf("compare plans: %v", err)
	}
	expected, err := resources.LoadPlatformPlanDiff(filepath.Join("..", "..", "docs", "examples", "platform-plan-diff.json"))
	if err != nil {
		t.Fatalf("load documented diff: %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("documented diff is stale:\nactual=%#v\nexpected=%#v", actual, expected)
	}
}

func TestCompareClassifiesMaterialChangesAndCauses(t *testing.T) {
	from := loadExamplePlan(t)
	to := loadExamplePlan(t)
	to.Provenance.RequestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to.Spec.Topology.Instances[1].ModelRef = "core.placeholder-coder-q8@2.0.0"
	to.Spec.Topology.Instances[1].Placement = "host-1/gpu-1"
	to.Spec.Allocations[0].AcceleratorID = "gpu-1"
	to.Spec.Decisions[0].Selected = "core.placeholder-coder-q8"
	to.Spec.Decisions[0].Evidence = []string{"fixture.updated-model-evidence"}
	to = assignPlanID(t, to)

	diff, err := Compare(from, to)
	if err != nil {
		t.Fatalf("compare plans: %v", err)
	}
	if !diff.Spec.Changed || diff.Spec.HighestImpact != resources.DiffImpactRedeploy {
		t.Fatalf("unexpected impact: %#v", diff.Spec)
	}
	for _, classification := range []string{
		resources.DiffClassificationProvenanceChange,
		resources.DiffClassificationArtifactOrVersionUpgrade,
		resources.DiffClassificationScaleOrPlacementChange,
		resources.DiffClassificationConfigurationUpdate,
	} {
		if !hasClassification(diff.Spec.Changes, classification) {
			t.Fatalf("missing classification %s: %#v", classification, diff.Spec.Changes)
		}
	}
	if len(diff.Spec.Causes) != 1 || diff.Spec.Causes[0].Kind != "request" {
		t.Fatalf("expected request cause: %#v", diff.Spec.Causes)
	}
	modelChange := findChange(t, diff.Spec.Changes, "spec.topology.instances[inference].modelRef")
	if !slices.Contains(modelChange.DecisionRefs, "decision.inference") {
		t.Fatalf("model change must link changed decision: %#v", modelChange)
	}
	if report := diff.Validate(); !report.Valid {
		t.Fatalf("diff is invalid: %#v", report.Diagnostics)
	}
	repeated, err := Compare(from, to)
	if err != nil {
		t.Fatalf("repeat comparison: %v", err)
	}
	if repeated.Metadata.DiffID != diff.Metadata.DiffID {
		t.Fatalf("diff is not deterministic: %s != %s", repeated.Metadata.DiffID, diff.Metadata.DiffID)
	}
}

func TestComparePresentationOnlyDoesNotRequireReview(t *testing.T) {
	from := loadExamplePlan(t)
	to := loadExamplePlan(t)
	to.Metadata.Name = "renamed-plan"
	to = assignPlanID(t, to)
	diff, err := Compare(from, to)
	if err != nil {
		t.Fatalf("compare plans: %v", err)
	}
	if !diff.Spec.Changed || diff.Spec.HighestImpact != resources.DiffImpactNone || len(diff.Spec.Changes) != 1 {
		t.Fatalf("unexpected presentation diff: %#v", diff.Spec)
	}
	if diff.Spec.Changes[0].Classification != resources.DiffClassificationPresentationOnly {
		t.Fatalf("unexpected classification: %#v", diff.Spec.Changes[0])
	}
	originalID := diff.Metadata.DiffID
	diff.Spec.Changes[0].Summary = "Updated presentation wording."
	diff = assignDiffID(t, diff)
	if diff.Metadata.DiffID != originalID {
		t.Fatal("presentation summary must not affect semantic diff identity")
	}
}

func TestCompareIgnoresSetOrdering(t *testing.T) {
	from := loadExamplePlan(t)
	to := loadExamplePlan(t)
	to.Spec.Topology.Instances[0].APIContracts = append(to.Spec.Topology.Instances[0].APIContracts, "integration.api.extra/v1")
	from.Spec.Topology.Instances[0].APIContracts = append(from.Spec.Topology.Instances[0].APIContracts, "integration.api.extra/v1")
	to.Spec.Topology.Instances[0].APIContracts[0], to.Spec.Topology.Instances[0].APIContracts[1] = to.Spec.Topology.Instances[0].APIContracts[1], to.Spec.Topology.Instances[0].APIContracts[0]
	from = assignPlanID(t, from)
	to = assignPlanID(t, to)
	diff, err := Compare(from, to)
	if err != nil {
		t.Fatalf("compare plans: %v", err)
	}
	if diff.Spec.Changed {
		t.Fatalf("set ordering must not create a semantic change: %#v", diff.Spec.Changes)
	}
}

func TestCompareTreatsInstanceRemovalAsDestructive(t *testing.T) {
	from := loadExamplePlan(t)
	to := loadExamplePlan(t)
	to.Spec.Topology.Instances = to.Spec.Topology.Instances[1:]
	to.Spec.Topology.Connections = nil
	to.Spec.Topology.DeploymentStages = [][]string{{"inference"}}
	to = assignPlanID(t, to)
	diff, err := Compare(from, to)
	if err != nil {
		t.Fatalf("compare plans: %v", err)
	}
	if diff.Spec.HighestImpact != resources.DiffImpactDestructive || !hasClassification(diff.Spec.Changes, resources.DiffClassificationDestructiveReplacement) {
		t.Fatalf("instance removal must be destructive: %#v", diff.Spec)
	}
}

func loadExamplePlan(t *testing.T) resources.PlatformPlan {
	t.Helper()
	plan, err := resources.LoadPlatformPlan(filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml"))
	if err != nil {
		t.Fatalf("load example plan: %v", err)
	}
	return plan
}

func assignPlanID(t *testing.T, plan resources.PlatformPlan) resources.PlatformPlan {
	t.Helper()
	assigned, err := plan.AssignPlanID()
	if err != nil {
		t.Fatalf("assign plan ID: %v", err)
	}
	return assigned
}

func assignDiffID(t *testing.T, diff resources.PlatformPlanDiff) resources.PlatformPlanDiff {
	t.Helper()
	assigned, err := diff.AssignDiffID()
	if err != nil {
		t.Fatalf("assign diff ID: %v", err)
	}
	return assigned
}

func hasClassification(changes []resources.PlanChange, classification string) bool {
	for _, change := range changes {
		if change.Classification == classification {
			return true
		}
	}
	return false
}

func findChange(t *testing.T, changes []resources.PlanChange, path string) resources.PlanChange {
	t.Helper()
	for _, change := range changes {
		if change.Path == path {
			return change
		}
	}
	t.Fatalf("change %s not found: %#v", path, changes)
	return resources.PlanChange{}
}
