package cli

import (
	"bytes"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestArtifactScanRecordWritesReceiptAndAudit(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	transferPath := valueForFlag(paths, "--transfer-receipt")
	outputPath := filepath.Join(directory, "artifact-scan-receipt.yaml")
	auditPath := filepath.Join(directory, "artifact-scan-receipt.audit.jsonl")
	args := []string{
		"artifact", "scan", "record",
		"--bundle", bundlePath,
		"--transfer-receipt", transferPath,
		"--scanner-name", "trivy",
		"--scanner-version", "0.53.0",
		"--scanner-profile", "offline-policy-default",
		"--policy-digest", testCLIDigest('9'),
		"--verdict", "passed",
		"--reason-reference", "ticket-scan-1",
		"--name", "runtime-scan",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("artifact scan record failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	receipt, err := resources.LoadArtifactScanReceipt(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	transferReceipt, err := resources.LoadArtifactTransferReceipt(transferPath)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Spec.BundleID == "" || !slices.Contains(receipt.Spec.PriorReceiptIDs, transferReceipt.Metadata.TransferReceiptID) {
		t.Fatalf("receipt omits expected scan provenance bindings: %#v", receipt.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "artifact.scan.record.completed" {
		t.Fatalf("terminal scan audit was not emitted: %#v", events)
	}
}

func TestArtifactScanRecordRejectsMismatchedTransferReceipt(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	transferPath := valueForFlag(paths, "--transfer-receipt")
	transferReceipt, err := resources.LoadArtifactTransferReceipt(transferPath)
	if err != nil {
		t.Fatal(err)
	}
	transferReceipt.Spec.BundleID = testCLIDigest('f')
	transferReceipt, err = transferReceipt.AssignTransferReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, transferPath, transferReceipt)
	args := []string{
		"artifact", "scan", "record",
		"--bundle", bundlePath,
		"--transfer-receipt", transferPath,
		"--scanner-name", "trivy",
		"--scanner-version", "0.53.0",
		"--scanner-profile", "offline-policy-default",
		"--policy-digest", testCLIDigest('9'),
		"--verdict", "passed",
		"--reason-reference", "ticket-scan-1",
		"--name", "runtime-scan",
		"--output", filepath.Join(directory, "artifact-scan-receipt.yaml"),
		"--audit-output", filepath.Join(directory, "artifact-scan-receipt.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("mismatched scan transfer receipt should fail invalid input: exit=%d stdout=%s", exit, stdout.String())
	}
}
