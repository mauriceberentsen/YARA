package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
)

func TestCatalogCoverageWritesIncompleteAuditedReport(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	auditPath := filepath.Join(temp, "coverage.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("coverage failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var response struct {
		Valid    bool   `json:"valid"`
		Complete bool   `json:"complete"`
		ReportID string `json:"reportId"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Valid || response.Complete || response.ReportID == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
	report, err := catalogcoverage.Load(outputPath)
	if err != nil {
		t.Fatalf("load report: %v", err)
	}
	if report.Metadata.ReportID != response.ReportID || report.Spec.Summary.AcceptedEvidenceCount != 14 || report.Spec.Summary.PromotionEligibleAssertions != 0 {
		t.Fatalf("unexpected report: %#v", report.Spec.Summary)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "catalog.coverage.completed" || len(terminal.Spec.Subjects) != 2 || terminal.Spec.Subjects[1].Digest != report.Metadata.ReportID {
		t.Fatalf("unexpected coverage audit: %#v", terminal.Spec)
	}
}

func TestCatalogCoverageRollsBackReportWhenAuditCannotBeWritten(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	auditPath := filepath.Join(temp, "coverage.audit.jsonl")
	if err := os.WriteFile(auditPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("prepare audit: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("coverage report must be rolled back after audit failure: %v", err)
	}
}

func TestCatalogCoverageValidateBindsReportIdentity(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	createAuditPath := filepath.Join(temp, "create.audit.jsonl")
	var createOutput, createError bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, createAuditPath), &createOutput, &createError); exitCode != ExitSuccess {
		t.Fatalf("create coverage failed: stdout=%s stderr=%s", createOutput.String(), createError.String())
	}
	validationAuditPath := filepath.Join(temp, "validate.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"catalog", "coverage", "validate", outputPath, "--audit-output", validationAuditPath}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("validate coverage failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	report, err := catalogcoverage.Load(outputPath)
	if err != nil {
		t.Fatalf("load report: %v", err)
	}
	events, err := audit.LoadJSONL(validationAuditPath)
	if err != nil {
		t.Fatalf("load validation audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "catalog.coverage.validate.completed" || len(terminal.Spec.Subjects) != 1 || terminal.Spec.Subjects[0].Digest != report.Metadata.ReportID {
		t.Fatalf("validation audit omitted report identity: %#v", terminal.Spec)
	}
}

func catalogCoverageArgs(outputPath, auditPath string) []string {
	root := filepath.Join("..", "..", "catalog", "v0.2")
	return []string{
		"catalog", "coverage", "create", "--catalog", filepath.Join(root, "snapshot.yaml"),
		"--evidence-dir", filepath.Join(root, "evidence"), "--name", "catalog-v0.2-coverage",
		"--output", outputPath, "--audit-output", auditPath,
	}
}
