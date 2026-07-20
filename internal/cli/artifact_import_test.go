package cli

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestArtifactImportRecordWritesReceiptAndAudit(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	outputPath := filepath.Join(directory, "artifact-import-receipt.yaml")
	auditPath := filepath.Join(directory, "artifact-import-receipt.audit.jsonl")
	args := []string{
		"artifact", "import", "record",
		"--bundle", bundlePath,
		"--preflight", preflightPath,
		"--importer-name", "yara-importer",
		"--importer-version", "0.1.0",
		"--internal-root", "model",
		"--name", "reference-import",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("artifact import record failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	receipt, err := resources.LoadArtifactImportReceipt(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := resources.LoadTargetPreflightResult(preflightPath)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Spec.BundleID == "" || receipt.Spec.Target.ReferenceDigest != preflight.Spec.Target.ReferenceDigest {
		t.Fatalf("receipt omitted expected import provenance bindings: %#v", receipt.Spec)
	}
	if len(receipt.Spec.ModelArtifacts) == 0 || len(receipt.Spec.ModelArtifacts[0].Files) == 0 {
		t.Fatalf("receipt omitted model artifact bindings: %#v", receipt.Spec.ModelArtifacts)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "artifact.import.record.completed" {
		t.Fatalf("terminal import audit was not emitted: %#v", events)
	}
}

func TestArtifactImportRecordRejectsMismatchedPreflight(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	preflight, err := resources.LoadTargetPreflightResult(preflightPath)
	if err != nil {
		t.Fatal(err)
	}
	preflight.Spec.BundleID = testCLIDigest('f')
	preflight, err = preflight.AssignResultID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, preflightPath, preflight)
	args := []string{
		"artifact", "import", "record",
		"--bundle", bundlePath,
		"--preflight", preflightPath,
		"--importer-name", "yara-importer",
		"--importer-version", "0.1.0",
		"--name", "reference-import",
		"--output", filepath.Join(directory, "artifact-import-receipt.yaml"),
		"--audit-output", filepath.Join(directory, "artifact-import-receipt.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("mismatched preflight should fail invalid input: exit=%d stdout=%s", exit, stdout.String())
	}
}

func TestArtifactImportRecordRejectsUnsafeInternalRoot(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	args := []string{
		"artifact", "import", "record",
		"--bundle", bundlePath,
		"--preflight", preflightPath,
		"--importer-name", "yara-importer",
		"--importer-version", "0.1.0",
		"--internal-root", "../outside",
		"--name", "reference-import",
		"--output", filepath.Join(directory, "artifact-import-receipt.yaml"),
		"--audit-output", filepath.Join(directory, "artifact-import-receipt.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("unsafe internal root should fail invalid input: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}
