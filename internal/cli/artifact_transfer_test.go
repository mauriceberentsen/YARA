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

func TestArtifactTransferRecordWritesReceiptAndAudit(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	importPath := valueForFlag(paths, "--import-receipt")
	outputPath := filepath.Join(directory, "artifact-transfer-receipt.yaml")
	auditPath := filepath.Join(directory, "artifact-transfer-receipt.audit.jsonl")
	args := []string{
		"artifact", "transfer", "record",
		"--bundle", bundlePath,
		"--import-receipt", importPath,
		"--stage", "registry-to-runtime",
		"--source-attestation-ref", "ticket-src",
		"--destination-attestation-ref", "ticket-dst",
		"--name", "runtime-transfer",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("artifact transfer record failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	receipt, err := resources.LoadArtifactTransferReceipt(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Spec.BundleID == "" || !slices.Contains(receipt.Spec.PriorReceiptIDs, mustLoadImportID(t, importPath)) {
		t.Fatalf("receipt omits expected provenance bindings: %#v", receipt.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "artifact.transfer.record.completed" {
		t.Fatalf("terminal transfer audit was not emitted: %#v", events)
	}
}

func TestArtifactTransferRecordRejectsMismatchedImportReceipt(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	importPath := valueForFlag(paths, "--import-receipt")
	importReceipt, err := resources.LoadArtifactImportReceipt(importPath)
	if err != nil {
		t.Fatal(err)
	}
	importReceipt.Spec.BundleID = testCLIDigest('f')
	importReceipt, err = importReceipt.AssignImportReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, importPath, importReceipt)
	args := []string{
		"artifact", "transfer", "record",
		"--bundle", bundlePath,
		"--import-receipt", importPath,
		"--stage", "registry-to-runtime",
		"--source-attestation-ref", "ticket-src",
		"--destination-attestation-ref", "ticket-dst",
		"--name", "runtime-transfer",
		"--output", filepath.Join(directory, "artifact-transfer-receipt.yaml"),
		"--audit-output", filepath.Join(directory, "artifact-transfer-receipt.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("mismatched transfer import receipt should fail invalid input: exit=%d stdout=%s", exit, stdout.String())
	}
}

func mustLoadImportID(t *testing.T, path string) string {
	t.Helper()
	receipt, err := resources.LoadArtifactImportReceipt(path)
	if err != nil {
		t.Fatal(err)
	}
	return receipt.Metadata.ImportReceiptID
}
