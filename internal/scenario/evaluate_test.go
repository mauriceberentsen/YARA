package scenario

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestEvaluateConformsToPinnedScenario(t *testing.T) {
	path, golden := loadExampleScenario(t)
	result := Evaluate(path, golden)
	if !result.Report.Valid {
		t.Fatalf("scenario evaluation failed: %#v", result.Report.Diagnostics)
	}
	if result.Outcome != resources.ScenarioOutcomePlanned || result.Plan.Metadata.PlanID != golden.Spec.Expected.PlanID {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestPendingReviewPacketPinsScenarioAndPlanIdentity(t *testing.T) {
	_, golden := loadExampleScenario(t)
	path := filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding", "review.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read review packet: %v", err)
	}
	for _, identity := range []string{golden.Metadata.ScenarioID, golden.Spec.Expected.PlanID} {
		if !strings.Contains(string(data), identity) {
			t.Fatalf("review packet does not pin %s", identity)
		}
	}
	if !strings.Contains(string(data), "Status: **pending**") {
		t.Fatal("review packet must not imply completed approval")
	}
}

func TestEvaluateRejectsPinnedInputDigestMismatch(t *testing.T) {
	path, golden := loadExampleScenario(t)
	golden.Spec.Inputs.Request.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	golden = assignScenarioID(t, golden)
	result := Evaluate(path, golden)
	if result.Report.Valid || !hasScenarioDiagnostic(result.Report, "YARA-SCN-030") {
		t.Fatalf("expected input digest mismatch: %#v", result.Report.Diagnostics)
	}
}

func TestEvaluateRejectsForbiddenGeneratedSelection(t *testing.T) {
	path, golden := loadExampleScenario(t)
	golden.Spec.Expected.RequiredSelections = golden.Spec.Expected.RequiredSelections[1:]
	golden.Spec.Expected.ForbiddenSelections = append(golden.Spec.Expected.ForbiddenSelections, "core.placeholder-gateway")
	sort.Strings(golden.Spec.Expected.ForbiddenSelections)
	golden = assignScenarioID(t, golden)
	if report := golden.Validate(); !report.Valid {
		t.Fatalf("test scenario is invalid: %#v", report.Diagnostics)
	}
	result := Evaluate(path, golden)
	if result.Report.Valid || !hasScenarioDiagnostic(result.Report, "YARA-SCN-035") {
		t.Fatalf("expected forbidden selection: %#v", result.Report.Diagnostics)
	}
}

func TestEvaluateRejectsUnexpectedPlanIdentity(t *testing.T) {
	path, golden := loadExampleScenario(t)
	golden.Spec.Expected.PlanID = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	golden = assignScenarioID(t, golden)
	result := Evaluate(path, golden)
	if result.Report.Valid || !hasScenarioDiagnostic(result.Report, "YARA-SCN-032") {
		t.Fatalf("expected plan identity mismatch: %#v", result.Report.Diagnostics)
	}
}

func loadExampleScenario(t *testing.T) (string, resources.GoldenScenario) {
	t.Helper()
	path := filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding", "scenario.yaml")
	golden, err := resources.LoadGoldenScenario(path)
	if err != nil {
		t.Fatalf("load scenario: %v", err)
	}
	return path, golden
}

func assignScenarioID(t *testing.T, golden resources.GoldenScenario) resources.GoldenScenario {
	t.Helper()
	assigned, err := golden.AssignScenarioID()
	if err != nil {
		t.Fatalf("assign scenario ID: %v", err)
	}
	return assigned
}

func hasScenarioDiagnostic(report diagnostics.Report, code string) bool {
	for _, item := range report.Diagnostics {
		if item.Code == code {
			return true
		}
	}
	return false
}
