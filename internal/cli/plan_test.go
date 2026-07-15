package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
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
	if !slices.Contains(events[1].Spec.DiagnosticCodes, "YARA-CAT-040") || !slices.Contains(events[1].Spec.DiagnosticCodes, "YARA-INV-002") {
		t.Fatalf("completion event must record material warnings: %#v", events[1].Spec.DiagnosticCodes)
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

func TestPlanCreateAuditsInfeasibleOutcome(t *testing.T) {
	temp := t.TempDir()
	root := filepath.Join("..", "..")
	inventoryData, err := os.ReadFile(filepath.Join(root, "docs", "examples", "inventory.yaml"))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	inventoryData = bytes.Replace(inventoryData, []byte("allocatableMemoryGiB: 22"), []byte("allocatableMemoryGiB: 1"), 1)
	inventoryPath := filepath.Join(temp, "inventory.yaml")
	if err := os.WriteFile(inventoryPath, inventoryData, 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	planPath := filepath.Join(temp, "plan.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	args := []string{
		"plan", "create",
		"--request", filepath.Join(root, "docs", "examples", "platform-request.yaml"),
		"--inventory", inventoryPath,
		"--catalog", filepath.Join(root, "catalog", "v0.1", "snapshot.yaml"),
		"--output", planPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInfeasible {
		t.Fatalf("expected infeasible exit, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(planPath); !os.IsNotExist(err) {
		t.Fatalf("infeasible planning must not write a plan, stat error: %v", err)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load failure audit chain: %v", err)
	}
	if len(events) != 2 || events[1].Spec.Action != "plan.create.infeasible" || events[1].Spec.Outcome != "infeasible" {
		t.Fatalf("unexpected terminal audit event: %#v", events)
	}
	if len(events[1].Spec.DiagnosticCodes) != 1 || events[1].Spec.DiagnosticCodes[0] != "YARA-PLAN-001" {
		t.Fatalf("expected infeasibility diagnostic in audit event: %#v", events[1].Spec.DiagnosticCodes)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify failure audit chain: %v", err)
	}
}
