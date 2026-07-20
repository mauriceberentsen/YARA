package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
	"gopkg.in/yaml.v3"
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
	if report.Spec.Summary.LifecyclePublicationBlockedAssertions != report.Spec.Summary.AssertionCount || report.Spec.Summary.LifecyclePublicationReadyAssertions != 0 {
		t.Fatalf("unexpected lifecycle publication summary: %#v", report.Spec.Summary)
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

func TestCatalogCoverageLifecyclePublicationPolicyReportsBlockedAssertions(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	createAuditPath := filepath.Join(temp, "create.audit.jsonl")
	var createOutput, createError bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, createAuditPath), &createOutput, &createError); exitCode != ExitSuccess {
		t.Fatalf("create coverage failed: stdout=%s stderr=%s", createOutput.String(), createError.String())
	}
	policyAuditPath := filepath.Join(temp, "policy.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"catalog", "coverage", "lifecycle-publication-policy", "--report", outputPath, "--audit-output", policyAuditPath}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("lifecycle publication policy failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var response struct {
		Valid                                 bool `json:"valid"`
		LifecyclePublicationReadyAssertions   int  `json:"lifecyclePublicationReadyAssertions"`
		LifecyclePublicationBlockedAssertions int  `json:"lifecyclePublicationBlockedAssertions"`
		ReportSubject                         struct {
			Kind   string `json:"kind"`
			Digest string `json:"digest"`
		} `json:"reportSubject"`
		AssertionScope struct {
			Mode string `json:"mode"`
		} `json:"assertionScope"`
		BlockedAssertions []struct {
			Assertion   string `json:"assertion"`
			Blocker     string `json:"blocker"`
			Code        string `json:"code"`
			Remediation string `json:"remediation"`
		} `json:"blockedAssertions"`
		Taxonomy []catalogcoverage.LifecyclePublicationBlockerDefinition `json:"taxonomy"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode policy response: %v", err)
	}
	if !response.Valid || response.LifecyclePublicationReadyAssertions != 0 || response.LifecyclePublicationBlockedAssertions == 0 || len(response.BlockedAssertions) == 0 {
		t.Fatalf("unexpected lifecycle publication policy response: %#v", response)
	}
	if response.ReportSubject.Kind != catalogcoverage.Kind || response.ReportSubject.Digest == "" {
		t.Fatalf("report subject explainability metadata missing: %#v", response.ReportSubject)
	}
	if response.AssertionScope.Mode != "all" {
		t.Fatalf("unexpected assertion scope metadata: %#v", response.AssertionScope)
	}
	if response.BlockedAssertions[0].Code == "" || response.BlockedAssertions[0].Remediation == "" {
		t.Fatalf("blocked assertion remediation is not surfaced: %#v", response.BlockedAssertions[0])
	}
	if len(response.Taxonomy) == 0 {
		t.Fatalf("blocker taxonomy must be included in policy diagnostics response")
	}
	events, err := audit.LoadJSONL(policyAuditPath)
	if err != nil {
		t.Fatalf("load policy audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "catalog.coverage.lifecycle-publication-policy.completed" {
		t.Fatalf("unexpected policy audit terminal event: %#v", terminal.Spec)
	}
}

func TestCatalogCoverageLifecyclePublicationPolicyRejectsUnknownBlockerTaxonomyCode(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	createAuditPath := filepath.Join(temp, "create.audit.jsonl")
	var createOutput, createError bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, createAuditPath), &createOutput, &createError); exitCode != ExitSuccess {
		t.Fatalf("create coverage failed: stdout=%s stderr=%s", createOutput.String(), createError.String())
	}
	report, err := catalogcoverage.Load(outputPath)
	if err != nil {
		t.Fatalf("load report: %v", err)
	}
	report.Spec.Assertions[0].LifecyclePublicationReady = false
	report.Spec.Assertions[0].LifecyclePublicationBlocker = "unknown-taxonomy-code|remediation:unknown-action"
	report, err = report.AssignReportID()
	if err != nil {
		t.Fatalf("assign report id: %v", err)
	}
	reportData, err := yaml.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(outputPath, reportData, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	policyAuditPath := filepath.Join(temp, "policy.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"catalog", "coverage", "lifecycle-publication-policy", "--report", outputPath, "--audit-output", policyAuditPath}, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input for unknown blocker taxonomy code, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
}

func TestCatalogCoverageLifecyclePublicationPolicyRejectsAmbiguousRemediationEncoding(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	createAuditPath := filepath.Join(temp, "create.audit.jsonl")
	var createOutput, createError bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, createAuditPath), &createOutput, &createError); exitCode != ExitSuccess {
		t.Fatalf("create coverage failed: stdout=%s stderr=%s", createOutput.String(), createError.String())
	}
	report, err := catalogcoverage.Load(outputPath)
	if err != nil {
		t.Fatalf("load report: %v", err)
	}
	report.Spec.Assertions[0].LifecyclePublicationReady = false
	report.Spec.Assertions[0].LifecyclePublicationBlocker = "selected-approval-expiry-invalid|remediation:first|remediation:second"
	report, err = report.AssignReportID()
	if err != nil {
		t.Fatalf("assign report id: %v", err)
	}
	reportData, err := yaml.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(outputPath, reportData, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	policyAuditPath := filepath.Join(temp, "policy.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"catalog", "coverage", "lifecycle-publication-policy", "--report", outputPath, "--audit-output", policyAuditPath}, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input for ambiguous remediation encoding, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
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
