package resources

import (
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
)

func TestTargetPreflightResultIdentityAndSemantics(t *testing.T) {
	result := validTargetPreflightResult(t)
	if report := result.Validate(); !report.Valid {
		t.Fatalf("valid result rejected: %#v", report.Diagnostics)
	}

	result.Spec.Checks[0].Facts[0].Value = "false"
	assertDiagnostic(t, result.Validate(), "YARA-TPR-021", "metadata.resultId")
}

func TestTargetPreflightResultRejectsOutcomeThatOverstatesChecks(t *testing.T) {
	result := validTargetPreflightResult(t)
	result.Metadata.ResultID = ""
	result.Spec.Outcome = "passed"
	assertDiagnostic(t, result.Validate(), "YARA-TPR-019", "spec.outcome")
}

func validTargetPreflightResult(t *testing.T) TargetPreflightResult {
	t.Helper()
	facts := []TargetPreflightFact{{Name: "available", Value: "true"}}
	evidence, err := canonical.Digest(struct {
		ID     string
		Status string
		Facts  []TargetPreflightFact
	}{ID: "api.core-v1", Status: "blocked", Facts: facts})
	if err != nil {
		t.Fatalf("digest evidence: %v", err)
	}
	result := TargetPreflightResult{
		APIVersion: APIVersion,
		Kind:       "TargetPreflightResult",
		Metadata:   TargetPreflightResultMetadata{Name: "cluster-preflight"},
		Spec: TargetPreflightResultSpec{
			Outcome:     "blocked",
			ObservedAt:  time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
			BundleID:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PlanID:      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Observer:    TargetPreflightObserver{Name: "yara.kubernetes-readonly", Version: "0.1.0", Mode: "read-only"},
			Target:      TargetIdentity{Type: "kubernetes", ReferenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ServerVersion: "v1.35.1"},
			Checks:      []TargetPreflightCheck{{ID: "api.core-v1", Status: "blocked", DiagnosticCode: "YARA-TPR-101", Summary: "Observation is blocked.", EvidenceDigest: evidence, Facts: facts}},
			Limitations: []string{"No mutation was attempted."},
		},
	}
	result, err = result.AssignResultID()
	if err != nil {
		t.Fatalf("assign result ID: %v", err)
	}
	return result
}
