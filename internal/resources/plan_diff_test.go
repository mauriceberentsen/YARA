package resources

import (
	"path/filepath"
	"testing"
)

func TestExamplePlatformPlanDiffIsValid(t *testing.T) {
	diff, err := LoadPlatformPlanDiff(filepath.Join("..", "..", "docs", "examples", "platform-plan-diff.json"))
	if err != nil {
		t.Fatalf("load example diff: %v", err)
	}
	if report := diff.Validate(); !report.Valid {
		t.Fatalf("example diff is invalid: %#v", report.Diagnostics)
	}
}

func TestPlatformPlanDiffValidationDetectsTampering(t *testing.T) {
	diff, err := LoadPlatformPlanDiff(filepath.Join("..", "..", "docs", "examples", "platform-plan-diff.json"))
	if err != nil {
		t.Fatalf("load example diff: %v", err)
	}
	diff.Spec.HighestImpact = DiffImpactReview
	report := diff.Validate()
	assertDiagnostic(t, report, "YARA-DIFF-018", "spec.highestImpact")
	assertDiagnostic(t, report, "YARA-DIFF-019", "metadata.diffId")
}
