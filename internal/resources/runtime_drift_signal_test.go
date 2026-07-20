package resources

import (
	"testing"

	"github.com/mauriceberentsen/YARA/internal/canonical"
)

func TestRuntimeDriftSignalIdentityAndDeterminism(t *testing.T) {
	first := validRuntimeDriftSignal(t)
	second := validRuntimeDriftSignal(t)
	if first.Metadata.SignalID != second.Metadata.SignalID {
		t.Fatalf("expected deterministic runtime drift signal identity, got %q and %q", first.Metadata.SignalID, second.Metadata.SignalID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("valid runtime drift signal rejected: %#v", report.Diagnostics)
	}
	first.Spec.Checks[0].Observed = "vllm@0.25.0"
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated runtime drift signal retained identity")
	}
}

func TestRuntimeDriftSignalRejectsStatusMismatch(t *testing.T) {
	signal := validRuntimeDriftSignal(t)
	signal.Spec.Checks[0].Status = "drifted"
	signal.Spec.Checks[0].ReasonCode = "YARA-RDS-101"
	signal.Spec.Status = "in-sync"
	assertDiagnostic(t, signal.Validate(), "YARA-RDS-024", "spec.status")
}

func TestRuntimeDriftSignalRequiresReasonCodeForDriftedCheck(t *testing.T) {
	signal := validRuntimeDriftSignal(t)
	signal.Spec.Checks[0].Status = "drifted"
	signal.Spec.Checks[0].ReasonCode = ""
	signal.Spec.Status = "drifted"
	assertDiagnostic(t, signal.Validate(), "YARA-RDS-022", "spec.checks[0].reasonCode")
}

func validRuntimeDriftSignal(t *testing.T) RuntimeDriftSignal {
	t.Helper()
	signal := RuntimeDriftSignal{
		APIVersion: APIVersion,
		Kind:       "RuntimeDriftSignal",
		Metadata: RuntimeDriftSignalMetadata{
			Name: "gb10-runtime-drift",
		},
		Spec: RuntimeDriftSignalSpec{
			RecordedAt:          "2026-07-20T10:15:00Z",
			CatalogDigest:       testDigest('a'),
			AssertionRef:        "compat.vllm-qwen-coder-7b-awq-gb10",
			RuntimeRef:          "core.vllm@0.25.1",
			BundleID:            testDigest('b'),
			PreflightResultID:   testDigest('c'),
			PreflightObservedAt: "2026-07-20T10:00:00Z",
			MaxPreflightAge:     "30m",
			Observer: TargetPreflightObserver{
				Name:    "kubectl-get",
				Version: "1.35.6",
				Mode:    "read-only",
			},
			Target: TargetIdentity{
				Type:            "kubernetes",
				ReferenceDigest: testDigest('d'),
				ServerVersion:   "v1.35.6",
			},
			Status: "in-sync",
			Checks: []RuntimeDriftCheck{
				{
					ID:       "runtime.replicas",
					Expected: "1",
					Observed: "1",
					Status:   "matched",
				},
				{
					ID:       "runtime.version",
					Expected: "core.vllm@0.25.1",
					Observed: "core.vllm@0.25.1",
					Status:   "matched",
				},
			},
			Limitations: []string{
				"Runtime drift signal captures bounded observation facts only.",
			},
		},
	}
	for index := range signal.Spec.Checks {
		evidence, err := canonical.Digest(struct {
			ID       string
			Expected string
			Observed string
			Status   string
		}{
			ID: signal.Spec.Checks[index].ID, Expected: signal.Spec.Checks[index].Expected,
			Observed: signal.Spec.Checks[index].Observed, Status: signal.Spec.Checks[index].Status,
		})
		if err != nil {
			t.Fatal(err)
		}
		signal.Spec.Checks[index].EvidenceDigest = evidence
	}
	var err error
	signal, err = signal.AssignSignalID()
	if err != nil {
		t.Fatal(err)
	}
	return signal
}
