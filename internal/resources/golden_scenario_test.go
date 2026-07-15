package resources

import (
	"path/filepath"
	"testing"
)

func TestGoldenScenarioDetectsContentTampering(t *testing.T) {
	golden, err := LoadGoldenScenario(filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding", "scenario.yaml"))
	if err != nil {
		t.Fatalf("load scenario: %v", err)
	}
	golden.Spec.Expected.PlanID = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if report := golden.Validate(); report.Valid || !hasDiagnostic(report.Diagnostics, "YARA-SCN-019") {
		t.Fatalf("expected scenario identity mismatch: %#v", report.Diagnostics)
	}
}
