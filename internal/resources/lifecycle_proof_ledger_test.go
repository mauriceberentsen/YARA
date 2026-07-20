package resources

import "testing"

func TestLifecycleProofLedgerIdentityAndValidation(t *testing.T) {
	first := validLifecycleProofLedger(t)
	second := validLifecycleProofLedger(t)
	if first.Metadata.LedgerID != second.Metadata.LedgerID {
		t.Fatalf("expected deterministic ledger identity, got %q and %q", first.Metadata.LedgerID, second.Metadata.LedgerID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid lifecycle proof ledger: %#v", report.Diagnostics)
	}
	first.Spec.Stages[2].Outcome = "failed"
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated lifecycle proof ledger retained identity")
	}
}

func validLifecycleProofLedger(t *testing.T) LifecycleProofLedger {
	t.Helper()
	ledger := LifecycleProofLedger{
		APIVersion: APIVersion,
		Kind:       "LifecycleProofLedger",
		Metadata: LifecycleProofLedgerMeta{
			Name: "lifecycle-proof-ledger",
		},
		Spec: LifecycleProofLedgerSpec{
			RecordedAt:            "2026-07-20T12:00:00Z",
			PlanID:                testDigest('a'),
			BundleID:              testDigest('b'),
			TargetReferenceDigest: testDigest('c'),
			Reviewer: ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "platform-security",
				Assurance: "self-asserted-local",
			},
			Decision:        PromotionDecisionApproved,
			ReasonReference: "ticket-lifecycle-proof-123",
			Stages: []LifecycleProofLedgerStage{
				{Stage: LifecycleStageApply, ReceiptID: testDigest('d'), ExecutionCorrelationID: "apply-corr", Outcome: "succeeded", CompletedAt: "2026-07-20T12:01:00Z"},
				{Stage: LifecycleStageRetire, ReceiptID: testDigest('e'), ExecutionCorrelationID: "retire-corr", Outcome: "succeeded", CompletedAt: "2026-07-20T12:02:00Z"},
				{Stage: LifecycleStageRollback, ReceiptID: testDigest('f'), ExecutionCorrelationID: "rollback-corr", Outcome: "succeeded", CompletedAt: "2026-07-20T12:03:00Z"},
			},
			Limitations: []string{
				"Lifecycle proof ledger does not execute mutations.",
				"Lifecycle proof ledger links immutable receipt identities only.",
			},
		},
	}
	assigned, err := ledger.AssignLedgerID()
	if err != nil {
		t.Fatalf("assign lifecycle proof ledger identity: %v", err)
	}
	return assigned
}
