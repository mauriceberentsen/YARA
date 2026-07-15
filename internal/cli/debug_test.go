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

func TestDebugBundleWritesValidRedactedBundleAndAudit(t *testing.T) {
	temp := t.TempDir()
	planPath := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	outputPath := filepath.Join(temp, "debug-bundle.json")
	auditPath := filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	args := []string{"debug", "bundle", "--plan", planPath, "--output", outputPath, "--audit-output", auditPath}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("debug bundle failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var result debugBundleResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	bundle, err := resources.LoadDebugBundle(outputPath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	if report := bundle.Validate(); !report.Valid {
		t.Fatalf("bundle is invalid: %#v", report.Diagnostics)
	}
	if !result.Valid || result.BundleID != bundle.Metadata.BundleID || len(result.Contents) != 4 {
		t.Fatalf("unexpected command result: %#v", result)
	}
	bundleData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	for _, forbidden := range []string{"private-coding-assistant", "core.placeholder-coder-small", "host-1/gpu-0", "Fits accelerator memory"} {
		if strings.Contains(string(bundleData), forbidden) {
			t.Fatalf("bundle contains omitted value %q", forbidden)
		}
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "debug.bundle.completed" || terminal.Spec.Outcome != "success" || len(terminal.Spec.Subjects) != 2 {
		t.Fatalf("unexpected terminal audit event: %#v", terminal.Spec)
	}
	if terminal.Spec.Subjects[1].Kind != "DebugBundle" || terminal.Spec.Subjects[1].Digest != bundle.Metadata.BundleID {
		t.Fatalf("audit does not identify the bundle: %#v", terminal.Spec.Subjects)
	}
	if !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-CAT-055") {
		t.Fatalf("audit omits material plan warnings: %#v", terminal.Spec.DiagnosticCodes)
	}
}

func TestDebugBundleRejectsSecretCanaryAndAuditsFailure(t *testing.T) {
	plan, err := resources.LoadPlatformPlan(filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml"))
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	const canary = "supersecretcanary123"
	plan.Provenance.PlannerVersion = "api_key=" + canary
	plan, err = plan.AssignPlanID()
	if err != nil {
		t.Fatalf("assign plan ID: %v", err)
	}
	data, err := yaml.Marshal(plan)
	if err != nil {
		t.Fatalf("encode plan: %v", err)
	}
	temp := t.TempDir()
	planPath := filepath.Join(temp, "plan.yaml")
	outputPath := filepath.Join(temp, "debug-bundle.json")
	auditPath := filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(planPath, data, 0o600); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"debug", "bundle", "--plan", planPath, "--output", outputPath, "--audit-output", auditPath}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "YARA-DBG-003") || strings.Contains(stdout.String(), canary) {
		t.Fatalf("unsafe rejection output: %s", stdout.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("secret-like content must not produce output: %v", err)
	}
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if strings.Contains(string(auditData), canary) {
		t.Fatal("audit evidence echoed the secret canary")
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "debug.bundle.failed" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-DBG-003") {
		t.Fatalf("secret rejection absent from audit: %#v", terminal.Spec)
	}
}

func TestDebugBundleFailsClosedWhenAuditAlreadyExists(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "debug-bundle.json")
	auditPath := filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("prepare audit path: %v", err)
	}
	planPath := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	var stdout, stderr bytes.Buffer
	args := []string{"debug", "bundle", "--plan", planPath, "--output", outputPath, "--audit-output", auditPath}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "YARA-AUD-005") {
		t.Fatalf("expected audit persistence diagnostic: %s", stdout.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("bundle must be rolled back after audit failure: %v", err)
	}
}

func TestDebugBundleRequiresAuditOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"debug", "bundle", "--plan", "plan.yaml", "--output", "bundle.json"}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "requires --plan, --output and --audit-output") {
		t.Fatalf("unexpected usage error: %s", stderr.String())
	}
}
