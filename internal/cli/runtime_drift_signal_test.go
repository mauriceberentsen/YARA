package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestRuntimeDriftSignalRecordWritesSignalAndAudit(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	preflight, err := resources.LoadTargetPreflightResult(preflightPath)
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "runtime-drift-signal.yaml")
	auditPath := filepath.Join(directory, "runtime-drift-signal.audit.jsonl")
	args := []string{
		"runtime", "drift-signal", "record",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--bundle", bundlePath,
		"--preflight", preflightPath,
		"--confirm-target", preflight.Spec.Target.ReferenceDigest,
		"--observer-name", "kubectl-get",
		"--observer-version", "1.35.6",
		"--status", "in-sync",
		"--check", "id=runtime.version,expected=core.vllm@0.25.1,observed=core.vllm@0.25.1,status=matched",
		"--check", "id=runtime.replicas,expected=1,observed=1,status=matched",
		"--max-preflight-age", "100000h",
		"--name", "gb10-runtime-drift",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("runtime drift-signal record failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	signal, err := resources.LoadRuntimeDriftSignal(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if signal.Spec.Status != "in-sync" || signal.Spec.RuntimeRef != "core.vllm@0.25.1" || signal.Spec.PreflightResultID != preflight.Metadata.ResultID {
		t.Fatalf("runtime drift signal omitted expected bindings: %#v", signal.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "runtime.drift-signal.record.completed" {
		t.Fatalf("terminal runtime drift audit was not emitted: %#v", events)
	}
}

func TestRuntimeDriftSignalRecordRejectsStalePreflight(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	preflight, err := resources.LoadTargetPreflightResult(preflightPath)
	if err != nil {
		t.Fatal(err)
	}
	preflight.Spec.ObservedAt = "2000-01-01T00:00:00Z"
	preflight, err = preflight.AssignResultID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, preflightPath, preflight)
	args := []string{
		"runtime", "drift-signal", "record",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--bundle", bundlePath,
		"--preflight", preflightPath,
		"--confirm-target", preflight.Spec.Target.ReferenceDigest,
		"--observer-name", "kubectl-get",
		"--observer-version", "1.35.6",
		"--status", "in-sync",
		"--check", "id=runtime.version,expected=core.vllm@0.25.1,observed=core.vllm@0.25.1,status=matched",
		"--name", "gb10-runtime-drift",
		"--output", filepath.Join(directory, "runtime-drift-signal.yaml"),
		"--audit-output", filepath.Join(directory, "runtime-drift-signal.audit.jsonl"),
		"--max-preflight-age", "15m",
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("stale preflight should fail infeasible: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "YARA-RDS-110") {
		t.Fatalf("stale preflight diagnostic code missing: %s", stdout.String())
	}
}

func TestRuntimeDriftSignalValidateCommand(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	preflight, err := resources.LoadTargetPreflightResult(preflightPath)
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "runtime-drift-signal.yaml")
	auditPath := filepath.Join(directory, "runtime-drift-signal.audit.jsonl")
	recordArgs := []string{
		"runtime", "drift-signal", "record",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--bundle", bundlePath,
		"--preflight", preflightPath,
		"--confirm-target", preflight.Spec.Target.ReferenceDigest,
		"--observer-name", "kubectl-get",
		"--observer-version", "1.35.6",
		"--status", "drifted",
		"--check", "id=runtime.version,expected=core.vllm@0.25.1,observed=core.vllm@0.24.9,status=drifted,reason-code=YARA-RDS-201",
		"--max-preflight-age", "100000h",
		"--name", "gb10-runtime-drift",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(recordArgs, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("runtime drift-signal record failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	validateAuditPath := filepath.Join(directory, "runtime-drift-signal.validate.audit.jsonl")
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"runtime-drift-signal", "validate", outputPath, "--audit-output", validateAuditPath}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("runtime-drift-signal validate failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"valid": true`) {
		t.Fatalf("unexpected runtime-drift-signal validate output: %s", stdout.String())
	}
}
