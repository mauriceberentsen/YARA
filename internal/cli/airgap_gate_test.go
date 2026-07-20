package cli

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestAirgapProvenanceGateEvaluateWritesResultAndAudit(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	args := []string{
		"airgap", "provenance-gate", "evaluate",
		"--bundle", valueForFlag(paths, "--bundle"),
		"--import-receipt", valueForFlag(paths, "--import-receipt"),
		"--transfer-receipt", valueForFlag(paths, "--transfer-receipt"),
		"--scan-receipt", valueForFlag(paths, "--scan-receipt"),
		"--reason-reference", "ticket-gate-1",
		"--name", "airgap-gate",
		"--output", filepath.Join(directory, "airgap-gate.yaml"),
		"--audit-output", filepath.Join(directory, "airgap-gate.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("airgap gate evaluate failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	result, err := resources.LoadAirgapProvenanceGateResult(filepath.Join(directory, "airgap-gate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Spec.Outcome != "passed" || result.Metadata.GateResultID == "" {
		t.Fatalf("gate result missing expected successful binding: %#v", result.Spec)
	}
	events, err := audit.LoadJSONL(filepath.Join(directory, "airgap-gate.audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "airgap.provenance-gate.evaluate.completed" {
		t.Fatalf("terminal gate audit missing: %#v", events)
	}
}

func TestAirgapProvenanceGateEvaluateFailsOnBrokenScanChain(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	scanPath := valueForFlag(paths, "--scan-receipt")
	scanReceipt, err := resources.LoadArtifactScanReceipt(scanPath)
	if err != nil {
		t.Fatal(err)
	}
	scanReceipt.Spec.PriorReceiptIDs = []string{testCLIDigest('f')}
	scanReceipt, err = scanReceipt.AssignScanReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, scanPath, scanReceipt)
	args := []string{
		"airgap", "provenance-gate", "evaluate",
		"--bundle", valueForFlag(paths, "--bundle"),
		"--import-receipt", valueForFlag(paths, "--import-receipt"),
		"--transfer-receipt", valueForFlag(paths, "--transfer-receipt"),
		"--scan-receipt", valueForFlag(paths, "--scan-receipt"),
		"--reason-reference", "ticket-gate-2",
		"--name", "airgap-gate",
		"--output", filepath.Join(directory, "airgap-gate.yaml"),
		"--audit-output", filepath.Join(directory, "airgap-gate.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("broken scan chain gate should be infeasible: exit=%d stdout=%s", exit, stdout.String())
	}
}
