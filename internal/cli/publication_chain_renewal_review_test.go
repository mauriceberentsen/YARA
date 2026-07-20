package cli

import (
	"bytes"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestPublicationChainRenewalReviewWritesArtifactAndAudit(t *testing.T) {
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
	rehearsal := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	rehearsalPath := filepath.Join(directory, "publication-chain-rehearsal.yaml")
	writeYAMLFixture(t, rehearsalPath, rehearsal)
	retentionAuditPath, retentionHead := publicationChainRetentionAuditFixture(t, catalogPath, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsalPath, directory)
	promotionReview := promotionReviewFixtureForRenewal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsal.Metadata.RehearsalID, retentionHead)
	promotionReviewPath := filepath.Join(directory, "promotion-review.yaml")
	writeYAMLFixture(t, promotionReviewPath, promotionReview)
	lifecycleApproval := lifecycleProofApprovalFixtureForRehearsal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute), time.Now().UTC().Add(24*time.Hour))
	lifecycleApprovalPath := filepath.Join(directory, "lifecycle-proof-approval.yaml")
	writeYAMLFixture(t, lifecycleApprovalPath, lifecycleApproval)
	integrationAttestation := integrationPublicationAttestationFixtureForRehearsal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute), time.Now().UTC().Add(24*time.Hour))
	integrationAttestationPath := filepath.Join(directory, "integration-publication-attestation.yaml")
	writeYAMLFixture(t, integrationAttestationPath, integrationAttestation)
	outputPath := filepath.Join(directory, "publication-chain-renewal-review.yaml")
	auditPath := filepath.Join(directory, "publication-chain-renewal-review.audit.jsonl")
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"publication", "chain", "renewal-review",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--publication-chain-rehearsal", rehearsalPath,
		"--confirm-publication-chain-rehearsal", rehearsal.Metadata.RehearsalID,
		"--publication-chain-retention-audit", retentionAuditPath,
		"--confirm-publication-chain-retention-audit", retentionHead,
		"--promotion-review", promotionReviewPath,
		"--confirm-promotion-review", promotionReview.Metadata.ReviewID,
		"--lifecycle-proof-approval", lifecycleApprovalPath,
		"--confirm-lifecycle-proof-approval", lifecycleApproval.Metadata.ApprovalID,
		"--integration-publication-attestation", integrationAttestationPath,
		"--confirm-integration-publication-attestation", integrationAttestation.Metadata.AttestationID,
		"--evidence", rehearsal.Metadata.RehearsalID,
		"--evidence", retentionHead,
		"--evidence", promotionReview.Metadata.ReviewID,
		"--evidence", lifecycleApproval.Metadata.ApprovalID,
		"--evidence", integrationAttestation.Metadata.AttestationID,
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-renewal-review-123",
		"--max-evidence-age", "720h",
		"--name", "publication-chain-renewal-review",
		"--output", outputPath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitSuccess {
		t.Fatalf("publication chain renewal-review failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	review, err := resources.LoadPublicationChainRenewalReview(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !review.Validate().Valid || review.Spec.CatalogDigest != catalogDigest || review.Spec.PublicationChainRetentionAuditHead != retentionHead {
		t.Fatalf("unexpected publication-chain renewal review output: %#v", review.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "publication.chain.renewal-review.completed" {
		t.Fatalf("terminal publication-chain renewal review audit missing: %#v", events)
	}
}

func TestPublicationChainRenewalReviewRejectsStaleRetentionAudit(t *testing.T) {
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
	rehearsal := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	rehearsalPath := filepath.Join(directory, "publication-chain-rehearsal.yaml")
	writeYAMLFixture(t, rehearsalPath, rehearsal)
	retentionAuditPath, retentionHead := publicationChainRetentionAuditFixture(t, catalogPath, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsalPath, directory)
	promotionReview := promotionReviewFixtureForRenewal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", rehearsal.Metadata.RehearsalID, retentionHead)
	promotionReviewPath := filepath.Join(directory, "promotion-review.yaml")
	writeYAMLFixture(t, promotionReviewPath, promotionReview)
	lifecycleApproval := lifecycleProofApprovalFixtureForRehearsal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute), time.Now().UTC().Add(24*time.Hour))
	lifecycleApprovalPath := filepath.Join(directory, "lifecycle-proof-approval.yaml")
	writeYAMLFixture(t, lifecycleApprovalPath, lifecycleApproval)
	integrationAttestation := integrationPublicationAttestationFixtureForRehearsal(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-30*time.Minute), time.Now().UTC().Add(24*time.Hour))
	integrationAttestationPath := filepath.Join(directory, "integration-publication-attestation.yaml")
	writeYAMLFixture(t, integrationAttestationPath, integrationAttestation)
	time.Sleep(10 * time.Millisecond)
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"publication", "chain", "renewal-review",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--publication-chain-rehearsal", rehearsalPath,
		"--confirm-publication-chain-rehearsal", rehearsal.Metadata.RehearsalID,
		"--publication-chain-retention-audit", retentionAuditPath,
		"--confirm-publication-chain-retention-audit", retentionHead,
		"--promotion-review", promotionReviewPath,
		"--confirm-promotion-review", promotionReview.Metadata.ReviewID,
		"--lifecycle-proof-approval", lifecycleApprovalPath,
		"--confirm-lifecycle-proof-approval", lifecycleApproval.Metadata.ApprovalID,
		"--integration-publication-attestation", integrationAttestationPath,
		"--confirm-integration-publication-attestation", integrationAttestation.Metadata.AttestationID,
		"--evidence", rehearsal.Metadata.RehearsalID,
		"--evidence", retentionHead,
		"--evidence", promotionReview.Metadata.ReviewID,
		"--evidence", lifecycleApproval.Metadata.ApprovalID,
		"--evidence", integrationAttestation.Metadata.AttestationID,
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-renewal-review-stale",
		"--max-evidence-age", "1ns",
		"--name", "publication-chain-renewal-review",
		"--output", filepath.Join(directory, "publication-chain-renewal-review.yaml"),
		"--audit-output", filepath.Join(directory, "publication-chain-renewal-review.audit.jsonl"),
	}, &stdout, &stderr)
	if exit != ExitInfeasible {
		t.Fatalf("stale retention audit should fail renewal-review: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func promotionReviewFixtureForRenewal(t *testing.T, catalogDigest, assertionRef, rehearsalID, retentionAuditHead string) resources.PromotionReview {
	t.Helper()
	review := resources.PromotionReview{
		APIVersion: resources.APIVersion,
		Kind:       "PromotionReview",
		Metadata: resources.PromotionReviewMetadata{
			Name: "promotion-review-renewal",
		},
		Spec: resources.PromotionReviewSpec{
			CatalogDigest:    catalogDigest,
			AssertionRef:     assertionRef,
			SelectedEvidence: []string{rehearsalID, retentionAuditHead, testCLIDigest('1')},
			Reviewer: resources.ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			ReviewedAt:      time.Now().UTC().Add(-20 * time.Minute).Format(time.RFC3339Nano),
			Decision:        resources.PromotionDecisionApproved,
			ReasonReference: "ticket-renewal-review-prereq-123",
			Limitations: []string{
				"Promotion review fixture for publication-chain renewal review tests.",
			},
		},
	}
	slices.Sort(review.Spec.SelectedEvidence)
	slices.Sort(review.Spec.Limitations)
	assigned, err := review.AssignReviewID()
	if err != nil {
		t.Fatalf("assign promotion review fixture id: %v", err)
	}
	return assigned
}
