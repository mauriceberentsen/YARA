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

func TestPromotionReviewRecordWritesReviewAndAudit(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	catalogDigest := "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241"
	rehearsal := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	rehearsalPath := filepath.Join(directory, "publication-chain-rehearsal.yaml")
	writeYAMLFixture(t, rehearsalPath, rehearsal)
	retentionAuditPath, retentionHead := publicationChainRetentionAuditFixture(t, catalogPath, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsalPath, directory)
	renewalReview := publicationChainRenewalReviewFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsal.Metadata.RehearsalID, retentionHead)
	renewalReviewPath := filepath.Join(directory, "publication-chain-renewal-review.yaml")
	writeYAMLFixture(t, renewalReviewPath, renewalReview)
	outputPath := filepath.Join(directory, "promotion-review.yaml")
	auditPath := filepath.Join(directory, "promotion-review.audit.jsonl")
	args := []string{
		"promotion", "review", "record",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--evidence", testCLIDigest('a'),
		"--evidence", rehearsal.Metadata.RehearsalID,
		"--evidence", retentionHead,
		"--evidence", renewalReview.Metadata.ReviewID,
		"--publication-chain-rehearsal", rehearsalPath,
		"--confirm-publication-chain-rehearsal", rehearsal.Metadata.RehearsalID,
		"--max-rehearsal-age", "720h",
		"--publication-chain-retention-audit", retentionAuditPath,
		"--confirm-publication-chain-retention-audit", retentionHead,
		"--max-retention-audit-age", "720h",
		"--publication-chain-renewal-review", renewalReviewPath,
		"--confirm-publication-chain-renewal-review", renewalReview.Metadata.ReviewID,
		"--max-renewal-review-age", "720h",
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-promotion-1",
		"--name", "gb10-promotion-review",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("promotion review record failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	review, err := resources.LoadPromotionReview(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if review.Spec.CatalogDigest != catalogDigest || review.Spec.Decision != resources.PromotionDecisionApproved {
		t.Fatalf("promotion review missing expected binding: %#v", review.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "promotion.review.completed" || events[1].Spec.Target != "catalog:"+catalogDigest {
		t.Fatalf("promotion review audit did not bind catalog target: %#v", events)
	}
	if !hasSubject(events[1].Spec.Subjects, "AuditChain", retentionHead) {
		t.Fatalf("promotion review audit did not bind retention diagnostics audit head: %#v", events[1].Spec.Subjects)
	}
}

func TestPromotionReviewRecordRejectsUnknownAssertionAndAuditsFailure(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	auditPath := filepath.Join(directory, "promotion-review.audit.jsonl")
	args := []string{
		"promotion", "review", "record",
		"--catalog", catalogPath,
		"--assertion", "compat.unknown",
		"--evidence", testCLIDigest('a'),
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-promotion-2",
		"--name", "invalid-promotion-review",
		"--output", filepath.Join(directory, "promotion-review.yaml"),
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("unknown assertion should fail invalid input: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "promotion.review.failed" || !slices.Contains(events[1].Spec.DiagnosticCodes, "YARA-PRM-102") {
		t.Fatalf("promotion review failure was not durably audited: %#v", events)
	}
}

func TestPromotionReviewRecordRejectsStalePublicationChainRehearsal(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	rehearsal := publicationChainRehearsalFixture(t, "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241", "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	rehearsalPath := filepath.Join(directory, "publication-chain-rehearsal.yaml")
	writeYAMLFixture(t, rehearsalPath, rehearsal)
	auditPath := filepath.Join(directory, "promotion-review.audit.jsonl")
	args := []string{
		"promotion", "review", "record",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--evidence", rehearsal.Metadata.RehearsalID,
		"--publication-chain-rehearsal", rehearsalPath,
		"--confirm-publication-chain-rehearsal", rehearsal.Metadata.RehearsalID,
		"--max-rehearsal-age", "1h",
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-promotion-stale",
		"--name", "stale-promotion-review",
		"--output", filepath.Join(directory, "promotion-review.yaml"),
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("stale rehearsal should fail infeasible: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestPromotionReviewRecordRejectsMissingRetentionAuditBinding(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	rehearsal := publicationChainRehearsalFixture(t, "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241", "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	rehearsalPath := filepath.Join(directory, "publication-chain-rehearsal.yaml")
	writeYAMLFixture(t, rehearsalPath, rehearsal)
	auditPath := filepath.Join(directory, "promotion-review.audit.jsonl")
	args := []string{
		"promotion", "review", "record",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--evidence", rehearsal.Metadata.RehearsalID,
		"--publication-chain-rehearsal", rehearsalPath,
		"--confirm-publication-chain-rehearsal", rehearsal.Metadata.RehearsalID,
		"--max-rehearsal-age", "720h",
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-promotion-retention-missing",
		"--name", "missing-retention-binding",
		"--output", filepath.Join(directory, "promotion-review.yaml"),
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("missing retention audit binding should fail invalid input: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestPromotionReviewRecordRejectsStaleRetentionAuditBinding(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	catalogDigest := "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241"
	rehearsal := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	rehearsalPath := filepath.Join(directory, "publication-chain-rehearsal.yaml")
	writeYAMLFixture(t, rehearsalPath, rehearsal)
	retentionAuditPath, retentionHead := publicationChainRetentionAuditFixture(t, catalogPath, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsalPath, directory)
	renewalReview := publicationChainRenewalReviewFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsal.Metadata.RehearsalID, retentionHead)
	renewalReviewPath := filepath.Join(directory, "publication-chain-renewal-review.yaml")
	writeYAMLFixture(t, renewalReviewPath, renewalReview)
	time.Sleep(10 * time.Millisecond)
	auditPath := filepath.Join(directory, "promotion-review.audit.jsonl")
	args := []string{
		"promotion", "review", "record",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--evidence", rehearsal.Metadata.RehearsalID,
		"--evidence", retentionHead,
		"--evidence", renewalReview.Metadata.ReviewID,
		"--publication-chain-rehearsal", rehearsalPath,
		"--confirm-publication-chain-rehearsal", rehearsal.Metadata.RehearsalID,
		"--max-rehearsal-age", "720h",
		"--publication-chain-retention-audit", retentionAuditPath,
		"--confirm-publication-chain-retention-audit", retentionHead,
		"--max-retention-audit-age", "1ns",
		"--publication-chain-renewal-review", renewalReviewPath,
		"--confirm-publication-chain-renewal-review", renewalReview.Metadata.ReviewID,
		"--max-renewal-review-age", "720h",
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-promotion-retention-stale",
		"--name", "stale-retention-binding",
		"--output", filepath.Join(directory, "promotion-review.yaml"),
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("stale retention audit binding should fail infeasible: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestPromotionReviewRecordRejectsMissingRenewalReviewBinding(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	catalogDigest := "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241"
	rehearsal := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	rehearsalPath := filepath.Join(directory, "publication-chain-rehearsal.yaml")
	writeYAMLFixture(t, rehearsalPath, rehearsal)
	retentionAuditPath, retentionHead := publicationChainRetentionAuditFixture(t, catalogPath, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsalPath, directory)
	auditPath := filepath.Join(directory, "promotion-review.audit.jsonl")
	args := []string{
		"promotion", "review", "record",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--evidence", rehearsal.Metadata.RehearsalID,
		"--evidence", retentionHead,
		"--publication-chain-rehearsal", rehearsalPath,
		"--confirm-publication-chain-rehearsal", rehearsal.Metadata.RehearsalID,
		"--max-rehearsal-age", "720h",
		"--publication-chain-retention-audit", retentionAuditPath,
		"--confirm-publication-chain-retention-audit", retentionHead,
		"--max-retention-audit-age", "720h",
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-promotion-renewal-missing",
		"--name", "missing-renewal-binding",
		"--output", filepath.Join(directory, "promotion-review.yaml"),
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("missing renewal review binding should fail invalid input: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func publicationChainRetentionAuditFixture(t *testing.T, catalogPath, assertionRef, rehearsalPath, directory string) (string, string) {
	t.Helper()
	retentionAuditPath := filepath.Join(directory, "publication-chain-retention.audit.jsonl")
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"publication", "chain", "retention-diagnostics",
		"--catalog", catalogPath,
		"--assertion", assertionRef,
		"--current-rehearsal", rehearsalPath,
		"--audit-output", retentionAuditPath,
	}, &stdout, &stderr)
	if exit != ExitSuccess {
		t.Fatalf("publication chain retention diagnostics fixture failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(retentionAuditPath)
	if err != nil {
		t.Fatalf("load retention audit fixture: %v", err)
	}
	head, err := audit.Verify(events)
	if err != nil {
		t.Fatalf("verify retention audit fixture: %v", err)
	}
	return retentionAuditPath, head
}

func publicationChainRehearsalFixture(t *testing.T, catalogDigest, assertionRef, rehearsedAt, decision string) resources.PublicationChainRehearsal {
	t.Helper()
	rehearsal := resources.PublicationChainRehearsal{
		APIVersion: resources.APIVersion,
		Kind:       "PublicationChainRehearsal",
		Metadata: resources.PublicationChainRehearsalMeta{
			Name: "promotion-rehearsal-fixture",
		},
		Spec: resources.PublicationChainRehearsalSpec{
			RehearsedAt:                         rehearsedAt,
			CatalogDigest:                       catalogDigest,
			AssertionRef:                        assertionRef,
			LifecycleProofApprovalID:            testCLIDigest('b'),
			IntegrationPublicationAttestationID: testCLIDigest('c'),
			CoverageReportID:                    testCLIDigest('d'),
			TrustPolicyID:                       testCLIDigest('e'),
			BoundaryAuditHead:                   testCLIDigest('f'),
			AuthorizationIDs:                    []string{testCLIDigest('1')},
			Reviewer: resources.ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			Decision:        decision,
			ReasonReference: "ticket-promotion-rehearsal-123",
			MaxEvidenceAge:  "720h",
			Limitations: []string{
				"Promotion review rehearsal fixture is non-mutating.",
			},
		},
	}
	assigned, err := rehearsal.AssignRehearsalID()
	if err != nil {
		t.Fatalf("assign promotion rehearsal id: %v", err)
	}
	return assigned
}

func publicationChainRenewalReviewFixture(t *testing.T, catalogDigest, assertionRef, rehearsalID, retentionAuditHead string) resources.PublicationChainRenewalReview {
	t.Helper()
	review := resources.PublicationChainRenewalReview{
		APIVersion: resources.APIVersion,
		Kind:       "PublicationChainRenewalReview",
		Metadata: resources.PublicationChainRenewalReviewMeta{
			Name: "promotion-renewal-review-fixture",
		},
		Spec: resources.PublicationChainRenewalReviewSpec{
			ReviewedAt:                          time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano),
			ExpiresAt:                           time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:                       catalogDigest,
			AssertionRef:                        assertionRef,
			PublicationChainRehearsalID:         rehearsalID,
			PublicationChainRetentionAuditHead:  retentionAuditHead,
			PromotionReviewID:                   testCLIDigest('7'),
			LifecycleProofApprovalID:            testCLIDigest('8'),
			IntegrationPublicationAttestationID: testCLIDigest('9'),
			SelectedEvidence:                    []string{rehearsalID, retentionAuditHead, testCLIDigest('7'), testCLIDigest('8'), testCLIDigest('9')},
			Reviewer: resources.ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			Decision:        resources.PromotionDecisionApproved,
			ReasonReference: "ticket-renewal-review-fixture-123",
			MaxEvidenceAge:  "720h",
			Limitations: []string{
				"Promotion review renewal fixture is non-mutating.",
			},
		},
	}
	slices.Sort(review.Spec.SelectedEvidence)
	slices.Sort(review.Spec.Limitations)
	assigned, err := review.AssignReviewID()
	if err != nil {
		t.Fatalf("assign renewal review fixture id: %v", err)
	}
	return assigned
}
