package resources

import (
	"testing"
	"time"
)

func TestPromotionReviewIdentityAndValidation(t *testing.T) {
	review := validPromotionReview(t)
	if report := review.Validate(); !report.Valid {
		t.Fatalf("expected valid promotion review: %#v", report.Diagnostics)
	}
	review.Spec.SelectedEvidence[0] = testDigest('f')
	if report := review.Validate(); report.Valid {
		t.Fatal("mutated content retained review identity")
	}
}

func TestPromotionReviewRejectsUnsortedEvidence(t *testing.T) {
	review := validPromotionReview(t)
	review.Spec.SelectedEvidence = []string{testDigest('b'), testDigest('a')}
	assertDiagnostic(t, review.Validate(), "YARA-PRM-012", "spec.selectedEvidence")
}

func validPromotionReview(t *testing.T) PromotionReview {
	t.Helper()
	review := PromotionReview{
		APIVersion: APIVersion,
		Kind:       "PromotionReview",
		Metadata: PromotionReviewMetadata{
			Name: "catalog-promotion-review",
		},
		Spec: PromotionReviewSpec{
			CatalogDigest:    testDigest('0'),
			AssertionRef:     "compat.vllm-qwen-coder-7b-awq-gb10",
			SelectedEvidence: []string{testDigest('1'), testDigest('2')},
			Reviewer: ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			ReviewedAt:      time.Now().UTC().Format(time.RFC3339Nano),
			Decision:        PromotionDecisionApproved,
			ReasonReference: "ticket-9001",
			Limitations: []string{
				"Review is bounded to catalog and selected evidence IDs only.",
			},
		},
	}
	assigned, err := review.AssignReviewID()
	if err != nil {
		t.Fatalf("assign review identity: %v", err)
	}
	return assigned
}
