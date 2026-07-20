package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
)

func TestPublicationChainRehearseWritesArtifactAndAudit(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(directory, "coverage.yaml")
	reportAuditPath := filepath.Join(directory, "coverage.audit.jsonl")
	var coverageStdout, coverageStderr bytes.Buffer
	if exit := Run(catalogCoverageArgs(reportPath, reportAuditPath), &coverageStdout, &coverageStderr); exit != ExitSuccess {
		t.Fatalf("create coverage for rehearsal test failed: exit=%d stdout=%s stderr=%s", exit, coverageStdout.String(), coverageStderr.String())
	}
	report, err := catalogcoverage.Load(reportPath)
	if err != nil {
		t.Fatalf("load generated rehearsal coverage: %v", err)
	}
	lifecycleApproval := lifecycleProofApprovalFixtureForRehearsal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-1*time.Hour), time.Now().UTC().Add(24*time.Hour))
	lifecycleApprovalPath := filepath.Join(directory, "lifecycle-proof-approval.yaml")
	writeYAMLFixture(t, lifecycleApprovalPath, lifecycleApproval)
	integrationAttestation := integrationPublicationAttestationFixtureForRehearsal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-1*time.Hour), time.Now().UTC().Add(24*time.Hour))
	integrationAttestationPath := filepath.Join(directory, "integration-publication-attestation.yaml")
	writeYAMLFixture(t, integrationAttestationPath, integrationAttestation)
	_, trustPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, authPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustPolicy := trustPolicyFixture(t, "gate-signer", trustPrivate.Public().(ed25519.PublicKey))
	trustPolicyPath := filepath.Join(directory, "trust-policy.yaml")
	writeYAMLFixture(t, trustPolicyPath, trustPolicy)
	authorization := executionAuthorizationFixture(t, "deployment-issuer", authPrivate)
	authorizationPath := filepath.Join(directory, "authorization.yaml")
	writeYAMLFixture(t, authorizationPath, authorization)
	boundaryAuditPath := filepath.Join(directory, "signing-boundary.audit.jsonl")
	writeSigningBoundaryAuditFixture(t, boundaryAuditPath, report.Metadata.ReportID, trustPolicy.Metadata.PolicyID, []string{authorization.Metadata.AuthorizationID}, time.Now().UTC().Add(-30*time.Minute))
	outputPath := filepath.Join(directory, "publication-chain-rehearsal.yaml")
	auditPath := filepath.Join(directory, "publication-chain-rehearsal.audit.jsonl")
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"publication", "chain", "rehearse",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--lifecycle-proof-approval", lifecycleApprovalPath,
		"--confirm-lifecycle-proof-approval", lifecycleApproval.Metadata.ApprovalID,
		"--integration-publication-attestation", integrationAttestationPath,
		"--confirm-integration-publication-attestation", integrationAttestation.Metadata.AttestationID,
		"--coverage-report", reportPath,
		"--confirm-coverage-report", report.Metadata.ReportID,
		"--trust-policy", trustPolicyPath,
		"--confirm-trust-policy", trustPolicy.Metadata.PolicyID,
		"--signing-boundary-audit", boundaryAuditPath,
		"--authorization", authorizationPath,
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-publication-chain-rehearsal-123",
		"--max-evidence-age", "720h",
		"--name", "publication-chain-rehearsal",
		"--output", outputPath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitSuccess {
		t.Fatalf("publication chain rehearse failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	rehearsal, err := resources.LoadPublicationChainRehearsal(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !rehearsal.Validate().Valid || rehearsal.Spec.CatalogDigest != catalogDigest || rehearsal.Spec.AssertionRef != "compat.vllm-qwen-coder-7b-awq-gb10" {
		t.Fatalf("unexpected publication chain rehearsal output: %#v", rehearsal.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "publication.chain.rehearse.completed" {
		t.Fatalf("terminal publication chain rehearsal audit missing: %#v", events)
	}
}

func TestPublicationChainRehearseRejectsStaleEvidence(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(directory, "coverage.yaml")
	reportAuditPath := filepath.Join(directory, "coverage.audit.jsonl")
	var coverageStdout, coverageStderr bytes.Buffer
	if exit := Run(catalogCoverageArgs(reportPath, reportAuditPath), &coverageStdout, &coverageStderr); exit != ExitSuccess {
		t.Fatalf("create coverage for rehearsal stale test failed: exit=%d stdout=%s stderr=%s", exit, coverageStdout.String(), coverageStderr.String())
	}
	report, err := catalogcoverage.Load(reportPath)
	if err != nil {
		t.Fatalf("load generated rehearsal coverage: %v", err)
	}
	lifecycleApproval := lifecycleProofApprovalFixtureForRehearsal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-48*time.Hour), time.Now().UTC().Add(24*time.Hour))
	lifecycleApprovalPath := filepath.Join(directory, "lifecycle-proof-approval.yaml")
	writeYAMLFixture(t, lifecycleApprovalPath, lifecycleApproval)
	integrationAttestation := integrationPublicationAttestationFixtureForRehearsal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-48*time.Hour), time.Now().UTC().Add(24*time.Hour))
	integrationAttestationPath := filepath.Join(directory, "integration-publication-attestation.yaml")
	writeYAMLFixture(t, integrationAttestationPath, integrationAttestation)
	_, trustPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, authPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustPolicy := trustPolicyFixture(t, "gate-signer", trustPrivate.Public().(ed25519.PublicKey))
	trustPolicyPath := filepath.Join(directory, "trust-policy.yaml")
	writeYAMLFixture(t, trustPolicyPath, trustPolicy)
	authorization := executionAuthorizationFixture(t, "deployment-issuer", authPrivate)
	authorizationPath := filepath.Join(directory, "authorization.yaml")
	writeYAMLFixture(t, authorizationPath, authorization)
	boundaryAuditPath := filepath.Join(directory, "signing-boundary.audit.jsonl")
	writeSigningBoundaryAuditFixture(t, boundaryAuditPath, report.Metadata.ReportID, trustPolicy.Metadata.PolicyID, []string{authorization.Metadata.AuthorizationID}, time.Now().UTC().Add(-48*time.Hour))
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"publication", "chain", "rehearse",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--lifecycle-proof-approval", lifecycleApprovalPath,
		"--confirm-lifecycle-proof-approval", lifecycleApproval.Metadata.ApprovalID,
		"--integration-publication-attestation", integrationAttestationPath,
		"--confirm-integration-publication-attestation", integrationAttestation.Metadata.AttestationID,
		"--coverage-report", reportPath,
		"--confirm-coverage-report", report.Metadata.ReportID,
		"--trust-policy", trustPolicyPath,
		"--confirm-trust-policy", trustPolicy.Metadata.PolicyID,
		"--signing-boundary-audit", boundaryAuditPath,
		"--authorization", authorizationPath,
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-publication-chain-rehearsal-stale",
		"--max-evidence-age", "1h",
		"--name", "publication-chain-rehearsal",
		"--output", filepath.Join(directory, "publication-chain-rehearsal.yaml"),
		"--audit-output", filepath.Join(directory, "publication-chain-rehearsal.audit.jsonl"),
	}, &stdout, &stderr)
	if exit != ExitInfeasible {
		t.Fatalf("stale publication-chain evidence should fail: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func lifecycleProofApprovalFixtureForRehearsal(t *testing.T, catalogDigest, assertionRef string, reviewedAt, expiresAt time.Time) resources.LifecycleProofApproval {
	t.Helper()
	approval := resources.LifecycleProofApproval{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofApproval",
		Metadata: resources.LifecycleProofApprovalMeta{
			Name: "lifecycle-proof-approval-rehearsal",
		},
		Spec: resources.LifecycleProofApprovalSpec{
			ReviewedAt:       reviewedAt.Format(time.RFC3339Nano),
			ExpiresAt:        expiresAt.Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     assertionRef,
			LedgerID:         "sha256:" + strings.Repeat("a", 64),
			SelectedEvidence: []string{"sha256:" + strings.Repeat("b", 64)},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-lifecycle-approval-rehearsal-123",
			MaxLedgerAge:     "720h",
			Limitations: []string{
				"Lifecycle proof approval fixture.",
			},
		},
	}
	slices.Sort(approval.Spec.Limitations)
	assigned, err := approval.AssignApprovalID()
	if err != nil {
		t.Fatalf("assign lifecycle-proof approval fixture id: %v", err)
	}
	return assigned
}

func integrationPublicationAttestationFixtureForRehearsal(t *testing.T, catalogDigest, assertionRef string, reviewedAt, expiresAt time.Time) resources.IntegrationPublicationAttestation {
	t.Helper()
	attestation := resources.IntegrationPublicationAttestation{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationPublicationAttestation",
		Metadata: resources.IntegrationPublicationAttestationMeta{
			Name: "integration-publication-attestation-rehearsal",
		},
		Spec: resources.IntegrationPublicationAttestationSpec{
			ReviewedAt:       reviewedAt.Format(time.RFC3339Nano),
			ExpiresAt:        expiresAt.Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     assertionRef,
			SelectedEvidence: []string{"sha256:" + strings.Repeat("c", 64)},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-integration-attestation-rehearsal-123",
			MaxEvidenceAge:   "720h",
			Limitations: []string{
				"Integration publication attestation fixture.",
			},
		},
	}
	slices.Sort(attestation.Spec.Limitations)
	assigned, err := attestation.AssignAttestationID()
	if err != nil {
		t.Fatalf("assign integration publication attestation fixture id: %v", err)
	}
	return assigned
}

func writeSigningBoundaryAuditFixture(t *testing.T, path, reportID, trustPolicyID string, authorizationIDs []string, occurredAt time.Time) {
	t.Helper()
	chain := audit.NewChain()
	at := occurredAt.UTC().Format(time.RFC3339Nano)
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "signing-boundary-started", OccurredAt: at},
		Spec: audit.Spec{
			CorrelationID: "signing-boundary-fixture",
			Actor:         audit.Actor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"},
			Action:        "catalog.coverage.signing-authority-boundary.started",
			Subjects: []audit.Subject{
				{Kind: catalogcoverage.Kind, Digest: reportID},
				{Kind: "AirgapGateTrustPolicy", Digest: trustPolicyID},
			},
			Reason:  audit.Reason{Type: "user-request", Reference: "test"},
			Target:  "catalog:test",
			Outcome: "started",
		},
	})
	if err != nil {
		t.Fatalf("append started signing-boundary audit: %v", err)
	}
	subjects := []audit.Subject{
		{Kind: catalogcoverage.Kind, Digest: reportID},
		{Kind: "AirgapGateTrustPolicy", Digest: trustPolicyID},
	}
	for _, authorizationID := range authorizationIDs {
		subjects = append(subjects, audit.Subject{Kind: "ExecutionAuthorization", Digest: authorizationID})
	}
	slices.SortFunc(subjects, func(left, right audit.Subject) int {
		if left.Kind != right.Kind {
			return strings.Compare(left.Kind, right.Kind)
		}
		return strings.Compare(left.Digest, right.Digest)
	})
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "signing-boundary-terminal", OccurredAt: at},
		Spec: audit.Spec{
			CorrelationID: "signing-boundary-fixture",
			CausationID:   started.Metadata.ID,
			Actor:         audit.Actor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"},
			Action:        "catalog.coverage.signing-authority-boundary.completed",
			Subjects:      subjects,
			Reason:        audit.Reason{Type: "user-request", Reference: "test"},
			Target:        "catalog:test",
			Outcome:       "success",
		},
	})
	if err != nil {
		t.Fatalf("append terminal signing-boundary audit: %v", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		t.Fatalf("encode signing-boundary audit fixture: %v", err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write signing-boundary audit fixture: %v", err)
	}
}
