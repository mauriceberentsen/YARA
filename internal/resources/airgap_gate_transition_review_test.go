package resources

import "testing"

func TestAirgapGateTransitionReviewIdentityAndValidation(t *testing.T) {
	first := validAirgapGateTransitionReview(t)
	second := validAirgapGateTransitionReview(t)
	if first.Metadata.ReviewID != second.Metadata.ReviewID {
		t.Fatalf("expected deterministic transition review identity, got %q and %q", first.Metadata.ReviewID, second.Metadata.ReviewID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid transition review: %#v", report.Diagnostics)
	}
	first.Spec.Decision = PromotionDecisionChangesRequired
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated transition review retained identity")
	}
}

func validAirgapGateTransitionReview(t *testing.T) AirgapGateTransitionReview {
	t.Helper()
	review := AirgapGateTransitionReview{
		APIVersion: APIVersion,
		Kind:       "AirgapGateTransitionReview",
		Metadata: AirgapGateTransitionReviewMetadata{
			Name: "airgap-gate-transition-review",
		},
		Spec: AirgapGateTransitionReviewSpec{
			RecordedAt:            "2026-07-20T10:00:00Z",
			PolicyDiffID:          testDigest('a'),
			FromPolicyID:          testDigest('b'),
			ToPolicyID:            testDigest('c'),
			TargetReferenceDigest: testDigest('d'),
			Reviewer: ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "platform-security",
				Assurance: "self-asserted-local",
			},
			Decision:        PromotionDecisionApproved,
			ReasonReference: "ticket-airgap-transition",
			Limitations:     []string{"Review is scoped to destructive trust-policy transitions only."},
		},
	}
	assigned, err := review.AssignReviewID()
	if err != nil {
		t.Fatalf("assign transition review identity: %v", err)
	}
	return assigned
}
