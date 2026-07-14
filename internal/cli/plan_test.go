package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestPlanCreateWritesValidPlanAndAuditChain(t *testing.T) {
	temp := t.TempDir()
	planPath := filepath.Join(temp, "plan.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	root := filepath.Join("..", "..")
	args := []string{
		"plan", "create",
		"--request", filepath.Join(root, "docs", "examples", "platform-request.yaml"),
		"--inventory", filepath.Join(root, "docs", "examples", "inventory.yaml"),
		"--catalog", filepath.Join(root, "catalog", "v0.1", "snapshot.yaml"),
		"--output", planPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("plan create failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	plan, err := resources.LoadPlatformPlan(planPath)
	if err != nil {
		t.Fatalf("load generated plan: %v", err)
	}
	if report := plan.Validate(); !report.Valid {
		t.Fatalf("generated plan is invalid: %#v", report.Diagnostics)
	}
	decision := plan.Spec.Decisions[0]
	if decision.Selected != "core.placeholder-coder-small" || decision.Alternatives[0].Code != "YARA-HW-004" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit chain: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected two audit events, got %d", len(events))
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if events[1].Spec.Subjects[3].Digest != plan.Metadata.PlanID {
		t.Fatal("completion event does not reference the generated plan")
	}
}

func TestPlanCreateDoesNotOverwriteOutput(t *testing.T) {
	temp := t.TempDir()
	planPath := filepath.Join(temp, "plan.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	root := filepath.Join("..", "..")
	args := []string{
		"plan", "create",
		"--request", filepath.Join(root, "docs", "examples", "platform-request.yaml"),
		"--inventory", filepath.Join(root, "docs", "examples", "inventory.yaml"),
		"--catalog", filepath.Join(root, "catalog", "v0.1", "snapshot.yaml"),
		"--output", planPath,
		"--audit-output", auditPath,
	}
	var firstOut, firstErr bytes.Buffer
	if exitCode := Run(args, &firstOut, &firstErr); exitCode != ExitSuccess {
		t.Fatalf("first plan create failed: %s", firstOut.String())
	}
	var secondOut, secondErr bytes.Buffer
	if exitCode := Run(args, &secondOut, &secondErr); exitCode != ExitInvalidInput {
		t.Fatalf("expected overwrite protection, got %d", exitCode)
	}
	if !strings.Contains(secondOut.String(), "file exists") {
		t.Fatalf("expected file exists diagnostic, got %s", secondOut.String())
	}
}
