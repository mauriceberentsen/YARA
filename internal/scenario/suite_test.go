package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestEvaluateAllMeetsTechnicalScenarioCount(t *testing.T) {
	root := filepath.Join("..", "..", "scenarios", "v0.1")
	result := EvaluateAll(root)
	if !result.Report.Valid {
		t.Fatalf("suite failed: %#v", result.Report.Diagnostics)
	}
	if len(result.Entries) != RequiredV01ScenarioCount || result.TechnicallyConformant != RequiredV01ScenarioCount {
		t.Fatalf("unexpected suite coverage: %#v", result)
	}
	if result.Planned != 7 || result.Infeasible != 3 {
		t.Fatalf("unexpected outcome mix: planned=%d infeasible=%d", result.Planned, result.Infeasible)
	}
	for _, entry := range result.Entries {
		golden, err := resources.LoadGoldenScenario(filepath.Join(root, entry.Name, "scenario.yaml"))
		if err != nil {
			t.Fatalf("load %s: %v", entry.Name, err)
		}
		review, err := os.ReadFile(filepath.Join(root, entry.Name, "review.md"))
		if err != nil {
			t.Fatalf("read %s review: %v", entry.Name, err)
		}
		for _, expected := range []string{"Status: **approved**", "Verdict: approved", golden.Metadata.ScenarioID} {
			if !strings.Contains(string(review), expected) {
				t.Fatalf("%s review does not contain %q", entry.Name, expected)
			}
		}
		if _, err := resources.LoadScenarioReview(filepath.Join(root, entry.Name, "review.yaml")); err != nil {
			t.Fatalf("load %s review.yaml: %v", entry.Name, err)
		}
		if golden.Spec.Expected.PlanID != "" && !strings.Contains(string(review), golden.Spec.Expected.PlanID) {
			t.Fatalf("%s review does not pin plan ID", entry.Name)
		}
	}
}

func TestEvaluateAllRejectsIncompleteAcceptanceSuite(t *testing.T) {
	root := filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding")
	result := EvaluateAll(root)
	if result.Report.Valid || !hasScenarioDiagnostic(result.Report, "YARA-SCN-042") {
		t.Fatalf("expected incomplete-suite diagnostic: %#v", result.Report.Diagnostics)
	}
}
