package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

func TestScenarioValidateReportsReviewRequiredAndAudits(t *testing.T) {
	path := filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding", "scenario.yaml")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"scenario", "validate", path, "--audit-output", auditPath}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("scenario validate failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var result scenarioValidationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.Valid || result.IndependentReview.Status != "required" || result.ReleaseEligible {
		t.Fatalf("validator overstated review status: %#v", result)
	}
	if result.PlanID == "" || !slices.Contains(result.ObservedDiagnosticCodes, "YARA-CAT-055") {
		t.Fatalf("result omits plan evidence: %#v", result)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "scenario.validate.completed" || terminal.Spec.Outcome != "success" || len(terminal.Spec.Subjects) != 2 {
		t.Fatalf("unexpected terminal event: %#v", terminal.Spec)
	}
	if terminal.Spec.Subjects[0].Kind != "GoldenScenario" || terminal.Spec.Subjects[1].Kind != "PlatformPlan" {
		t.Fatalf("audit omits scenario or plan identity: %#v", terminal.Spec.Subjects)
	}
}

func TestScenarioValidateAuditsConformanceFailure(t *testing.T) {
	sourcePath := filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding", "scenario.yaml")
	golden, err := resources.LoadGoldenScenario(sourcePath)
	if err != nil {
		t.Fatalf("load scenario: %v", err)
	}
	temp := t.TempDir()
	scenarioPath := filepath.Join(temp, "scenario.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	inputs := []struct {
		ref  *resources.GoldenScenarioInput
		name string
	}{
		{&golden.Spec.Inputs.Request, "request.yaml"},
		{&golden.Spec.Inputs.Inventory, "inventory.yaml"},
		{&golden.Spec.Inputs.Catalog, filepath.Join("catalog", "v0.1", "snapshot.yaml")},
	}
	for _, input := range inputs {
		target, err := filepath.Abs(filepath.Join(filepath.Dir(sourcePath), input.ref.Path))
		if err != nil {
			t.Fatalf("resolve input: %v", err)
		}
		link := filepath.Join(temp, input.name)
		if input.ref == &golden.Spec.Inputs.Catalog {
			target = filepath.Dir(filepath.Dir(target))
			link = filepath.Join(temp, "catalog")
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("link input: %v", err)
		}
		input.ref.Path = input.name
	}
	golden.Spec.Expected.PlanID = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	golden, err = golden.AssignScenarioID()
	if err != nil {
		t.Fatalf("assign scenario ID: %v", err)
	}
	data, err := yaml.Marshal(golden)
	if err != nil {
		t.Fatalf("encode scenario: %v", err)
	}
	if err := os.WriteFile(scenarioPath, data, 0o600); err != nil {
		t.Fatalf("write scenario: %v", err)
	}
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"scenario", "validate", scenarioPath, "--audit-output", auditPath}, &stdout, &stderr)
	if exitCode != ExitInvalidInput || !strings.Contains(stdout.String(), "YARA-SCN-032") {
		t.Fatalf("expected plan identity failure, got %d: %s", exitCode, stdout.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if terminal := events[len(events)-1]; terminal.Spec.Action != "scenario.validate.failed" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-SCN-032") {
		t.Fatalf("failure absent from audit: %#v", terminal.Spec)
	}
}

func TestScenarioValidateAllReportsTechnicalCoverageWithoutReviewApproval(t *testing.T) {
	root := filepath.Join("..", "..", "scenarios", "v0.1")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"scenario", "validate-all", root, "--audit-output", auditPath}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("scenario validate-all failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var result scenarioSuiteValidationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode suite result: %v", err)
	}
	if !result.Valid || !result.TechnicalCoverageComplete || result.ScenarioCount != 10 || result.TechnicallyConformant != 10 {
		t.Fatalf("unexpected technical coverage: %#v", result)
	}
	if result.IndependentReviewsComplete != 0 || result.IndependentReviewStatus != "required" || result.ReleaseEligible {
		t.Fatalf("suite overstated human review: %#v", result)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load suite audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify suite audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "scenario.validate-all.completed" || terminal.Spec.Outcome != "success" || len(terminal.Spec.Subjects) != 17 {
		t.Fatalf("unexpected suite terminal event: %#v", terminal.Spec)
	}
	if !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-PLAN-001") || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-CAT-055") {
		t.Fatalf("suite audit omits material outcomes: %#v", terminal.Spec.DiagnosticCodes)
	}
}

func TestScenarioValidateAllAuditsIncompleteSuiteWithoutExposingPath(t *testing.T) {
	root := filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"scenario", "validate-all", root, "--audit-output", auditPath}, &stdout, &stderr)
	if exitCode != ExitInvalidInput || !strings.Contains(stdout.String(), "YARA-SCN-042") {
		t.Fatalf("expected incomplete-suite failure, got %d: %s", exitCode, stdout.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load suite failure audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify suite failure audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "scenario.validate-all.failed" || terminal.Spec.Outcome != "failed" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-SCN-042") {
		t.Fatalf("unexpected suite failure event: %#v", terminal.Spec)
	}
	if len(terminal.Spec.Subjects) != 1 || terminal.Spec.Subjects[0].Kind != "GoldenScenarioSuiteInputReference" || strings.Contains(terminal.Spec.Subjects[0].Digest, root) {
		t.Fatalf("suite failure audit exposed or mislabeled input: %#v", terminal.Spec.Subjects)
	}
}
