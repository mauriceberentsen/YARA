package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
	"github.com/mauriceberentsen/YARA/internal/resources"
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
		Valid                          bool   `json:"valid"`
		Complete                       bool   `json:"complete"`
		ReportID                       string `json:"reportId"`
		IntegrationEvidenceConvergence struct {
			IdentityCount        int  `json:"identityCount"`
			DeduplicatedCount    int  `json:"deduplicatedCount"`
			DeduplicationApplied bool `json:"deduplicationApplied"`
		} `json:"integrationEvidenceConvergence"`
		SigningAuthorityBoundary struct {
			Status         string `json:"status"`
			OverlapCount   int    `json:"overlapCount"`
			AmbiguityCount int    `json:"ambiguityCount"`
			Evaluated      bool   `json:"evaluated"`
		} `json:"signingAuthorityBoundary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Valid || response.Complete || response.ReportID == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
	if response.IntegrationEvidenceConvergence.IdentityCount != 0 || response.IntegrationEvidenceConvergence.DeduplicatedCount != 0 || response.IntegrationEvidenceConvergence.DeduplicationApplied {
		t.Fatalf("unexpected integration convergence diagnostics for v0.2 fixtures: %#v", response.IntegrationEvidenceConvergence)
	}
	if response.SigningAuthorityBoundary.Status != "not-evaluated" || response.SigningAuthorityBoundary.OverlapCount != 0 || response.SigningAuthorityBoundary.AmbiguityCount != 0 || response.SigningAuthorityBoundary.Evaluated {
		t.Fatalf("unexpected signing authority boundary diagnostics for v0.2 fixtures: %#v", response.SigningAuthorityBoundary)
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
		IntegrationEvidenceConvergence struct {
			IdentityCount        int  `json:"identityCount"`
			DeduplicatedCount    int  `json:"deduplicatedCount"`
			DeduplicationApplied bool `json:"deduplicationApplied"`
		} `json:"integrationEvidenceConvergence"`
		SigningAuthorityBoundary struct {
			Status         string `json:"status"`
			OverlapCount   int    `json:"overlapCount"`
			AmbiguityCount int    `json:"ambiguityCount"`
			Evaluated      bool   `json:"evaluated"`
		} `json:"signingAuthorityBoundary"`
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
	if response.IntegrationEvidenceConvergence.IdentityCount != 0 || response.IntegrationEvidenceConvergence.DeduplicatedCount != 0 || response.IntegrationEvidenceConvergence.DeduplicationApplied {
		t.Fatalf("unexpected integration convergence diagnostics for v0.2 policy response: %#v", response.IntegrationEvidenceConvergence)
	}
	if response.SigningAuthorityBoundary.Status != "not-evaluated" || response.SigningAuthorityBoundary.OverlapCount != 0 || response.SigningAuthorityBoundary.AmbiguityCount != 0 || response.SigningAuthorityBoundary.Evaluated {
		t.Fatalf("unexpected signing authority boundary diagnostics for v0.2 policy response: %#v", response.SigningAuthorityBoundary)
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

func TestCatalogCoverageCreateReportsDeduplicatedIntegrationConvergenceState(t *testing.T) {
	temp := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatalf("catalog digest: %v", err)
	}
	evidenceDir := filepath.Join(temp, "evidence")
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		t.Fatalf("create evidence dir: %v", err)
	}
	result := deterministicIntegrationResultFixtureForCLI(t, digest)
	writeCatalogCoverageYAMLFixture(t, filepath.Join(evidenceDir, "integration-one.yaml"), result)
	writeCatalogCoverageYAMLFixture(t, filepath.Join(evidenceDir, "integration-two.yaml"), result)
	writeIntegrationAuditFixture(t, filepath.Join(evidenceDir, "integration-one.audit.jsonl"), digest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, "2026-07-20T12:30:00Z")
	writeIntegrationAuditFixture(t, filepath.Join(evidenceDir, "integration-two.audit.jsonl"), digest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, "2026-07-20T12:30:00Z")
	outputPath := filepath.Join(temp, "coverage.yaml")
	auditPath := filepath.Join(temp, "coverage.audit.jsonl")
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"catalog", "coverage", "create",
		"--catalog", catalogPath,
		"--evidence-dir", evidenceDir,
		"--name", "coverage-dedup",
		"--output", outputPath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitSuccess {
		t.Fatalf("coverage create failed with %d: stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	var response struct {
		IntegrationEvidenceConvergence struct {
			IdentityCount        int  `json:"identityCount"`
			DeduplicatedCount    int  `json:"deduplicatedCount"`
			DeduplicationApplied bool `json:"deduplicationApplied"`
		} `json:"integrationEvidenceConvergence"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.IntegrationEvidenceConvergence.IdentityCount != 1 || response.IntegrationEvidenceConvergence.DeduplicatedCount != 1 || !response.IntegrationEvidenceConvergence.DeduplicationApplied {
		t.Fatalf("unexpected deduplicated integration convergence diagnostics: %#v", response.IntegrationEvidenceConvergence)
	}
}

func TestCatalogCoverageLifecyclePublicationPolicyFailsClosedOnMalformedConvergenceLimitations(t *testing.T) {
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
	filtered := make([]string, 0, len(report.Spec.Limitations))
	for _, limitation := range report.Spec.Limitations {
		if strings.HasPrefix(limitation, "integration-evidence-convergence:") {
			filtered = append(filtered, "integration-evidence-convergence:identity-count=abc,deduplicated-count=1")
			continue
		}
		filtered = append(filtered, limitation)
	}
	report.Spec.Limitations = filtered
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
	if exitCode := Run([]string{"catalog", "coverage", "lifecycle-publication-policy", "--report", outputPath, "--audit-output", policyAuditPath}, &stdout, &stderr); exitCode != ExitInternal {
		t.Fatalf("expected internal error for malformed convergence limitation record, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
}

func TestCatalogCoverageLifecyclePublicationPolicyFailsClosedOnMalformedSigningAuthorityBoundaryLimitation(t *testing.T) {
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
	filtered := make([]string, 0, len(report.Spec.Limitations))
	for _, limitation := range report.Spec.Limitations {
		if strings.HasPrefix(limitation, "signing-authority-boundary:") {
			filtered = append(filtered, "signing-authority-boundary:status=overlap,overlap-count=0,ambiguity-count=0")
			continue
		}
		filtered = append(filtered, limitation)
	}
	report.Spec.Limitations = filtered
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
	if exitCode := Run([]string{"catalog", "coverage", "lifecycle-publication-policy", "--report", outputPath, "--audit-output", policyAuditPath}, &stdout, &stderr); exitCode != ExitInternal {
		t.Fatalf("expected internal error for malformed signing-authority boundary limitation record, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
}

func TestCatalogCoverageLifecyclePublicationPolicyFailsClosedOnDuplicateSigningAuthorityBoundaryLimitations(t *testing.T) {
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
	report.Spec.Limitations = append(report.Spec.Limitations, "signing-authority-boundary:status=not-evaluated,overlap-count=0,ambiguity-count=0")
	slices.Sort(report.Spec.Limitations)
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
	if exitCode := Run([]string{"catalog", "coverage", "lifecycle-publication-policy", "--report", outputPath, "--audit-output", policyAuditPath}, &stdout, &stderr); exitCode != ExitInternal {
		t.Fatalf("expected internal error for duplicate signing-authority boundary limitation record, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
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

func TestCatalogCoverageSigningAuthorityBoundaryReportsIndependent(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	createAuditPath := filepath.Join(temp, "create.audit.jsonl")
	var createOutput, createError bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, createAuditPath), &createOutput, &createError); exitCode != ExitSuccess {
		t.Fatalf("create coverage failed: stdout=%s stderr=%s", createOutput.String(), createError.String())
	}
	_, trustPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate trust signer key: %v", err)
	}
	_, authPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate authorization issuer key: %v", err)
	}
	trustPolicy := trustPolicyFixture(t, "gate-signer", trustPrivate.Public().(ed25519.PublicKey))
	trustPolicyPath := filepath.Join(temp, "trust-policy.yaml")
	writeCatalogCoverageYAMLFixture(t, trustPolicyPath, trustPolicy)
	authorization := executionAuthorizationFixture(t, "deployment-issuer", authPrivate)
	authorizationPath := filepath.Join(temp, "authorization.yaml")
	writeCatalogCoverageYAMLFixture(t, authorizationPath, authorization)
	boundaryAuditPath := filepath.Join(temp, "boundary.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{
		"catalog", "coverage", "signing-authority-boundary",
		"--report", outputPath,
		"--trust-policy", trustPolicyPath,
		"--authorization", authorizationPath,
		"--audit-output", boundaryAuditPath,
	}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("signing authority boundary failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var response struct {
		Valid                    bool `json:"valid"`
		SigningAuthorityBoundary struct {
			Status                   string   `json:"status"`
			OverlapIdentities        []string `json:"overlapIdentities"`
			AmbiguityDiagnostics     []string `json:"ambiguityDiagnostics"`
			GateSignerCount          int      `json:"gateSignerCount"`
			AuthorizationIssuerCount int      `json:"authorizationIssuerCount"`
		} `json:"signingAuthorityBoundary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode boundary response: %v", err)
	}
	if !response.Valid || response.SigningAuthorityBoundary.Status != "independent" || len(response.SigningAuthorityBoundary.OverlapIdentities) != 0 || len(response.SigningAuthorityBoundary.AmbiguityDiagnostics) != 0 {
		t.Fatalf("unexpected signing authority boundary response: %#v", response)
	}
	events, err := audit.LoadJSONL(boundaryAuditPath)
	if err != nil {
		t.Fatalf("load boundary audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "catalog.coverage.signing-authority-boundary.completed" {
		t.Fatalf("unexpected signing authority boundary audit terminal event: %#v", terminal.Spec)
	}
}

func TestCatalogCoverageSigningAuthorityBoundaryRejectsOverlap(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	createAuditPath := filepath.Join(temp, "create.audit.jsonl")
	var createOutput, createError bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, createAuditPath), &createOutput, &createError); exitCode != ExitSuccess {
		t.Fatalf("create coverage failed: stdout=%s stderr=%s", createOutput.String(), createError.String())
	}
	_, sharedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate shared signer key: %v", err)
	}
	trustPolicy := trustPolicyFixture(t, "shared-issuer", sharedPrivate.Public().(ed25519.PublicKey))
	trustPolicyPath := filepath.Join(temp, "trust-policy.yaml")
	writeCatalogCoverageYAMLFixture(t, trustPolicyPath, trustPolicy)
	authorization := executionAuthorizationFixture(t, "shared-issuer", sharedPrivate)
	authorizationPath := filepath.Join(temp, "authorization.yaml")
	writeCatalogCoverageYAMLFixture(t, authorizationPath, authorization)
	boundaryAuditPath := filepath.Join(temp, "boundary.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{
		"catalog", "coverage", "signing-authority-boundary",
		"--report", outputPath,
		"--trust-policy", trustPolicyPath,
		"--authorization", authorizationPath,
		"--audit-output", boundaryAuditPath,
	}, &stdout, &stderr); exitCode != ExitInfeasible {
		t.Fatalf("expected infeasible overlap rejection, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
}

func TestCatalogCoverageSigningAuthorityBoundaryRejectsAmbiguousKeyRoleReuse(t *testing.T) {
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "coverage.yaml")
	createAuditPath := filepath.Join(temp, "create.audit.jsonl")
	var createOutput, createError bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(outputPath, createAuditPath), &createOutput, &createError); exitCode != ExitSuccess {
		t.Fatalf("create coverage failed: stdout=%s stderr=%s", createOutput.String(), createError.String())
	}
	_, trustPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate trust signer key: %v", err)
	}
	_, authPrivateOne, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate authorization issuer key 1: %v", err)
	}
	_, authPrivateTwo, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate authorization issuer key 2: %v", err)
	}
	trustPolicy := trustPolicyFixture(t, "gate-signer", trustPrivate.Public().(ed25519.PublicKey))
	trustPolicyPath := filepath.Join(temp, "trust-policy.yaml")
	writeCatalogCoverageYAMLFixture(t, trustPolicyPath, trustPolicy)
	authorizationOne := executionAuthorizationFixture(t, "deployment-issuer", authPrivateOne)
	authorizationTwo := executionAuthorizationFixture(t, "deployment-issuer", authPrivateTwo)
	authorizationOnePath := filepath.Join(temp, "authorization-one.yaml")
	authorizationTwoPath := filepath.Join(temp, "authorization-two.yaml")
	writeCatalogCoverageYAMLFixture(t, authorizationOnePath, authorizationOne)
	writeCatalogCoverageYAMLFixture(t, authorizationTwoPath, authorizationTwo)
	boundaryAuditPath := filepath.Join(temp, "boundary.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{
		"catalog", "coverage", "signing-authority-boundary",
		"--report", outputPath,
		"--trust-policy", trustPolicyPath,
		"--authorization", authorizationOnePath,
		"--authorization", authorizationTwoPath,
		"--audit-output", boundaryAuditPath,
	}, &stdout, &stderr); exitCode != ExitInfeasible {
		t.Fatalf("expected infeasible ambiguity rejection, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
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

func deterministicIntegrationResultFixtureForCLI(t *testing.T, catalogDigest string) resources.IntegrationTestResult {
	t.Helper()
	result := resources.IntegrationTestResult{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationTestResult",
		Metadata: resources.IntegrationTestResultMetadata{
			Name: "integration-cli-fixture",
		},
		Spec: resources.IntegrationTestResultSpec{
			Mode:          "component-smoke",
			Outcome:       "passed",
			CatalogDigest: catalogDigest,
			ComponentRefs: []string{"core.litellm@1.93.0"},
			Environment: resources.ContractTestEnvironment{
				Transport:       "local",
				ReferenceDigest: "sha256:" + strings.Repeat("a", 64),
				OperatingSystem: "linux",
				Architecture:    "amd64",
				Docker: resources.ContractTestDocker{
					Available: true, Version: "27.0.0", OperatingSystem: "linux", Architecture: "amd64",
				},
				Accelerators: []resources.ContractTestAccelerator{},
			},
			Checks: []resources.ContractTestCheck{
				{ID: "integration.cli.fixture", Status: "passed", EvidenceDigest: "sha256:" + strings.Repeat("b", 64)},
			},
			Limitations: []string{"integration fixture"},
		},
	}
	slices.Sort(result.Spec.ComponentRefs)
	slices.Sort(result.Spec.Limitations)
	result, err := result.AssignResultID()
	if err != nil {
		t.Fatalf("assign integration fixture id: %v", err)
	}
	return result
}

func trustPolicyFixture(t *testing.T, keyID string, publicKey ed25519.PublicKey) resources.AirgapGateTrustPolicy {
	t.Helper()
	recordedAt := "2026-07-20T12:00:00Z"
	trustPolicy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata:   resources.AirgapGateTrustPolicyMetadata{Name: "trust-policy"},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:            recordedAt,
			TargetReferenceDigest: "sha256:" + strings.Repeat("a", 64),
			TrustedSignerIdentities: []resources.AirgapTrustedSignerIdentity{
				{
					KeyID:           keyID,
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(publicKey),
					PublicKeyDigest: resources.PublicKeyDigest(publicKey),
					Status:          "active",
				},
			},
			Limitations: []string{
				"Trust policy fixture",
			},
		},
	}
	trustPolicy, err := trustPolicy.AssignPolicyID()
	if err != nil {
		t.Fatalf("assign trust policy id: %v", err)
	}
	return trustPolicy
}

func executionAuthorizationFixture(t *testing.T, keyID string, privateKey ed25519.PrivateKey) resources.ExecutionAuthorization {
	t.Helper()
	now := time.Now().UTC()
	authorization := resources.ExecutionAuthorization{
		APIVersion: resources.APIVersion,
		Kind:       "ExecutionAuthorization",
		Metadata: resources.ExecutionAuthorizationMetadata{
			Name: "authorization-fixture",
		},
		Spec: resources.ExecutionAuthorizationSpec{
			IssuedAt:          now.Format(time.RFC3339Nano),
			ExpiresAt:         now.Add(10 * time.Minute).Format(time.RFC3339Nano),
			PlanID:            "sha256:" + strings.Repeat("1", 64),
			BundleID:          "sha256:" + strings.Repeat("2", 64),
			PreflightResultID: "sha256:" + strings.Repeat("3", 64),
			ChangeSetID:       "sha256:" + strings.Repeat("4", 64),
			ApprovalID:        "sha256:" + strings.Repeat("5", 64),
			Target: resources.TargetIdentity{
				Type:            "kubernetes",
				ReferenceDigest: "sha256:" + strings.Repeat("6", 64),
				ServerVersion:   "v1.30.0",
			},
			Issuer: resources.ExecutionAuthorizationIssuer{
				KeyID: keyID,
			},
			Constraints: resources.ExecutionAuthorizationConstraints{
				AllowedActions:            []string{"create", "no-op", "update"},
				MaxOperations:             12,
				AllowDelete:               false,
				AllowActiveVerification:   true,
				AcceptedPreflightBlockers: []string{},
			},
			Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		},
	}
	slices.Sort(authorization.Spec.Constraints.AllowedActions)
	signed, err := authorization.Sign(privateKey)
	if err != nil {
		t.Fatalf("sign authorization fixture: %v", err)
	}
	return signed
}

func writeCatalogCoverageYAMLFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := yaml.Marshal(value)
	if err != nil {
		t.Fatalf("marshal yaml fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write yaml fixture: %v", err)
	}
}

func writeIntegrationAuditFixture(t *testing.T, path, catalogDigest, resultID, targetDigest, occurredAt string) {
	t.Helper()
	chain := audit.NewChain()
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "integration-started", OccurredAt: occurredAt},
		Spec: audit.Spec{
			CorrelationID: "integration-cli-fixture",
			Actor:         audit.Actor{ID: "local:runner", Type: "user", Assurance: "self-asserted-local"},
			Action:        "integration.component-smoke.started",
			Subjects:      []audit.Subject{{Kind: "CatalogSnapshot", Digest: catalogDigest}},
			Reason:        audit.Reason{Type: "user-request", Reference: "test"},
			Target:        "local:" + targetDigest,
			Outcome:       "started",
		},
	})
	if err != nil {
		t.Fatalf("append started integration audit: %v", err)
	}
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "integration-terminal", OccurredAt: occurredAt},
		Spec: audit.Spec{
			CorrelationID: "integration-cli-fixture",
			CausationID:   started.Metadata.ID,
			Actor:         audit.Actor{ID: "local:runner", Type: "user", Assurance: "self-asserted-local"},
			Action:        "integration.component-smoke.completed",
			Subjects: []audit.Subject{
				{Kind: "CatalogSnapshot", Digest: catalogDigest},
				{Kind: "IntegrationTestResult", Digest: resultID},
			},
			Reason:  audit.Reason{Type: "user-request", Reference: "test"},
			Target:  "local:" + targetDigest,
			Outcome: "success",
		},
	})
	if err != nil {
		t.Fatalf("append terminal integration audit: %v", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		t.Fatalf("encode integration audit fixture: %v", err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write integration audit fixture: %v", err)
	}
}
