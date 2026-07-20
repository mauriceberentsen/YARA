package resources

import "testing"

func TestLifecycleProofApprovalIdentityAndValidation(t *testing.T) {
	first := validLifecycleProofApproval(t)
	second := validLifecycleProofApproval(t)
	if first.Metadata.ApprovalID != second.Metadata.ApprovalID {
		t.Fatalf("expected deterministic lifecycle-proof approval identity, got %q and %q", first.Metadata.ApprovalID, second.Metadata.ApprovalID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid lifecycle-proof approval: %#v", report.Diagnostics)
	}
	first.Spec.Decision = PromotionDecisionChangesRequired
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated lifecycle-proof approval retained identity")
	}
}

func validLifecycleProofApproval(t *testing.T) LifecycleProofApproval {
	t.Helper()
	approval := LifecycleProofApproval{
		APIVersion: APIVersion,
		Kind:       "LifecycleProofApproval",
		Metadata: LifecycleProofApprovalMeta{
			Name: "lifecycle-proof-approval",
		},
		Spec: LifecycleProofApprovalSpec{
			ReviewedAt:       "2026-07-20T12:00:00Z",
			ExpiresAt:        "2026-07-27T12:00:00Z",
			CatalogDigest:    testDigest('a'),
			AssertionRef:     "compat.vllm-qwen-coder-7b-awq-gb10",
			LedgerID:         testDigest('b'),
			SelectedEvidence: []string{testDigest('c')},
			Reviewer: ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			Decision:        PromotionDecisionApproved,
			ReasonReference: "ticket-lifecycle-approval-123",
			MaxLedgerAge:    "720h",
			Limitations: []string{
				"Lifecycle-proof approval binds one immutable lifecycle proof ledger identity.",
				"Lifecycle-proof approval records review metadata only and does not mutate catalog state.",
			},
		},
	}
	assigned, err := approval.AssignApprovalID()
	if err != nil {
		t.Fatalf("assign lifecycle-proof approval identity: %v", err)
	}
	return assigned
}
