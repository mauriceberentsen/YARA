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
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestPlanExplainPreservesAllDecisionOutput(t *testing.T) {
	planPath := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"plan", "explain", planPath}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("plan explain failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var decisions []resources.PlanDecision
	if err := json.Unmarshal(stdout.Bytes(), &decisions); err != nil {
		t.Fatalf("decode decisions: %v", err)
	}
	if len(decisions) != 3 || decisions[0].ID != "decision.inference" {
		t.Fatalf("unexpected decisions: %#v", decisions)
	}
}

func TestPlanExplainTargetsDecisionAndAudits(t *testing.T) {
	planPath := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	args := []string{"plan", "explain", planPath, "--audit-output", auditPath, "--decision", "decision.inference"}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("targeted plan explain failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var decision resources.PlanDecision
	if err := json.Unmarshal(stdout.Bytes(), &decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if decision.ID != "decision.inference" || decision.Selected != "core.placeholder-coder-small" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	decisionDigest, err := canonical.Digest(decision)
	if err != nil {
		t.Fatalf("digest decision: %v", err)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "plan.explain.completed" || terminal.Spec.Outcome != "success" {
		t.Fatalf("unexpected terminal event: %#v", terminal.Spec)
	}
	if len(terminal.Spec.Subjects) != 2 || terminal.Spec.Subjects[1].Kind != "PlanDecision" || terminal.Spec.Subjects[1].Digest != decisionDigest {
		t.Fatalf("audit does not identify the exact decision output: %#v", terminal.Spec.Subjects)
	}
	if !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-CAT-055") {
		t.Fatalf("audit omits material plan warnings: %#v", terminal.Spec.DiagnosticCodes)
	}
}

func TestPlanExplainMissingDecisionAuditsFailure(t *testing.T) {
	planPath := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	args := []string{"plan", "explain", planPath, "--decision", "decision.missing", "--audit-output", auditPath}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "YARA-PLAN-040") {
		t.Fatalf("missing stable diagnostic: %s", stdout.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "plan.explain.failed" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-PLAN-040") {
		t.Fatalf("missing-decision failure absent from audit: %#v", terminal.Spec)
	}
}

func TestPlanExplainAuditsInvalidPlan(t *testing.T) {
	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "docs", "examples", "platform-plan.yaml"))
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	data = bytes.Replace(data, []byte("core.placeholder-coder-q4@1.0.0"), []byte("core.tampered-model@1.0.0"), 1)
	temp := t.TempDir()
	planPath := filepath.Join(temp, "tampered.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(planPath, data, 0o600); err != nil {
		t.Fatalf("write tampered plan: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"plan", "explain", planPath, "--audit-output", auditPath}, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "plan.explain.failed" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-PLAN-014") {
		t.Fatalf("invalid-plan failure absent from audit: %#v", terminal.Spec)
	}
}

func TestPlanExplainFailsClosedWhenAuditAlreadyExists(t *testing.T) {
	planPath := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("prepare audit path: %v", err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"plan", "explain", planPath, "--decision", "decision.inference", "--audit-output", auditPath}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected fail-closed invalid input, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "YARA-AUD-005") || strings.Contains(stdout.String(), "decision.inference") {
		t.Fatalf("command reported explanation despite audit failure: %s", stdout.String())
	}
}

func TestPlanExplainRejectsDuplicateOptions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"plan", "explain", "plan.yaml", "--decision", "one", "--decision", "two"}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("expected usage, got %s", stderr.String())
	}
}
