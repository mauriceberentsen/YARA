package resources

import (
	"slices"
	"testing"
)

func TestPublicationChainRenewalReviewIdentityAndValidation(t *testing.T) {
	first := validPublicationChainRenewalReview(t)
	second := validPublicationChainRenewalReview(t)
	if first.Metadata.ReviewID != second.Metadata.ReviewID {
		t.Fatalf("expected deterministic publication-chain renewal review identity, got %q and %q", first.Metadata.ReviewID, second.Metadata.ReviewID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid publication-chain renewal review: %#v", report.Diagnostics)
	}
	first.Spec.Decision = PromotionDecisionChangesRequired
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated publication-chain renewal review retained identity")
	}
}

func validPublicationChainRenewalReview(t *testing.T) PublicationChainRenewalReview {
	t.Helper()
	review := PublicationChainRenewalReview{
		APIVersion: APIVersion,
		Kind:       "PublicationChainRenewalReview",
		Metadata: PublicationChainRenewalReviewMeta{
			Name: "publication-chain-renewal-review",
		},
		Spec: PublicationChainRenewalReviewSpec{
			ReviewedAt:                          "2026-07-20T16:00:00Z",
			ExpiresAt:                           "2026-07-27T16:00:00Z",
			CatalogDigest:                       testDigest('a'),
			AssertionRef:                        "compat.vllm-qwen-coder-7b-awq-gb10",
			PublicationChainRehearsalID:         testDigest('b'),
			PublicationChainRetentionAuditHead:  testDigest('c'),
			PromotionReviewID:                   testDigest('d'),
			LifecycleProofApprovalID:            testDigest('e'),
			IntegrationPublicationAttestationID: testDigest('f'),
			SelectedEvidence:                    []string{testDigest('b'), testDigest('c'), testDigest('d'), testDigest('e'), testDigest('f')},
			Reviewer: ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			Decision:        PromotionDecisionApproved,
			ReasonReference: "ticket-publication-chain-renewal-123",
			MaxEvidenceAge:  "720h",
			Limitations: []string{
				"Publication-chain renewal review records immutable identity bindings only.",
				"Publication-chain renewal review is non-mutating and does not replace historical evidence.",
			},
		},
	}
	slices.Sort(review.Spec.Limitations)
	assigned, err := review.AssignReviewID()
	if err != nil {
		t.Fatalf("assign publication-chain renewal review identity: %v", err)
	}
	return assigned
}
