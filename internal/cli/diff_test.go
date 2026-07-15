package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

func TestPlanDiffWritesNoOpResultAndAudit(t *testing.T) {
	planPath := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"plan", "diff", planPath, planPath, "--audit-output", auditPath}, &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("plan diff failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var result resources.PlatformPlanDiff
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode diff: %v", err)
	}
	if result.Spec.Changed || result.Spec.HighestImpact != resources.DiffImpactNone {
		t.Fatalf("expected no-op diff: %#v", result.Spec)
	}
	if report := result.Validate(); !report.Valid {
		t.Fatalf("CLI emitted invalid diff: %#v", report.Diagnostics)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "plan.diff.completed" || terminal.Spec.Outcome != "success" || len(terminal.Spec.Subjects) != 3 {
		t.Fatalf("unexpected terminal event: %#v", terminal.Spec)
	}
	if terminal.Spec.Subjects[2].Digest != result.Metadata.DiffID {
		t.Fatal("audit event does not reference diff identity")
	}
	if !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-CAT-055") {
		t.Fatalf("audit omits material plan warnings: %#v", terminal.Spec.DiagnosticCodes)
	}
}

func TestPlanDiffAuditsInvalidToPlan(t *testing.T) {
	root := filepath.Join("..", "..")
	planPath := filepath.Join(root, "docs", "examples", "platform-plan.yaml")
	data, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	data = bytes.Replace(data, []byte("core.placeholder-coder-q4@1.0.0"), []byte("core.tampered-model@1.0.0"), 1)
	temp := t.TempDir()
	tamperedPath := filepath.Join(temp, "tampered.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(tamperedPath, data, 0o600); err != nil {
		t.Fatalf("write tampered plan: %v", err)
	}
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"plan", "diff", planPath, tamperedPath, "--audit-output", auditPath}, &stdout, &stderr)
	if exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "plan.diff.failed" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-PLAN-014") {
		t.Fatalf("invalid-plan failure missing from audit: %#v", terminal.Spec)
	}
}

func TestPlanDiffClassifiesPlacementChange(t *testing.T) {
	planPath := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	plan, err := resources.LoadPlatformPlan(planPath)
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	plan.Spec.Topology.Instances[1].Placement = "host-1/gpu-1"
	plan.Spec.Allocations[0].AcceleratorID = "gpu-1"
	plan, err = plan.AssignPlanID()
	if err != nil {
		t.Fatalf("assign plan ID: %v", err)
	}
	data, err := yaml.Marshal(plan)
	if err != nil {
		t.Fatalf("encode plan: %v", err)
	}
	toPath := filepath.Join(t.TempDir(), "to.yaml")
	if err := os.WriteFile(toPath, data, 0o600); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"plan", "diff", planPath, toPath}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("plan diff failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var result resources.PlatformPlanDiff
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode diff: %v", err)
	}
	if result.Spec.HighestImpact != resources.DiffImpactRedeploy || !hasDiffClassification(result.Spec.Changes, resources.DiffClassificationScaleOrPlacementChange) {
		t.Fatalf("unexpected material diff: %#v", result.Spec)
	}
}

func hasDiffClassification(changes []resources.PlanChange, classification string) bool {
	for _, change := range changes {
		if change.Classification == classification {
			return true
		}
	}
	return false
}
