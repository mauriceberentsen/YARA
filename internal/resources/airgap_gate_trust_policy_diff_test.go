package resources

import "testing"

func TestAirgapGateTrustPolicyDiffIdentityAndValidation(t *testing.T) {
	first := validAirgapGateTrustPolicyDiff(t)
	second := validAirgapGateTrustPolicyDiff(t)
	if first.Metadata.DiffID != second.Metadata.DiffID {
		t.Fatalf("expected deterministic trust-policy diff identity, got %q and %q", first.Metadata.DiffID, second.Metadata.DiffID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid trust-policy diff: %#v", report.Diagnostics)
	}
	first.Spec.Changes[0].Impact = "destructive"
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated contents retained trust-policy diff identity")
	}
}

func validAirgapGateTrustPolicyDiff(t *testing.T) AirgapGateTrustPolicyDiff {
	t.Helper()
	diff := AirgapGateTrustPolicyDiff{
		APIVersion: APIVersion,
		Kind:       "AirgapGateTrustPolicyDiff",
		Metadata: AirgapGateTrustPolicyDiffMetadata{
			Name: "airgap-gate-policy-diff",
		},
		Spec: AirgapGateTrustPolicyDiffSpec{
			RecordedAt:            "2026-07-20T10:00:00Z",
			FromPolicyID:          testDigest('a'),
			ToPolicyID:            testDigest('b'),
			TargetReferenceDigest: testDigest('c'),
			HighestImpact:         "review",
			Changes: []AirgapGateTrustPolicyChange{{
				ID:       "change-001",
				KeyID:    "operations-key-1",
				Digest:   testDigest('d'),
				Category: "validity-window-updated",
				Impact:   "review",
				Summary:  "Signer validity window updated.",
			}},
			Limitations: []string{"Diff excludes signer private keys and secret-bearing payloads."},
		},
	}
	assigned, err := diff.AssignDiffID()
	if err != nil {
		t.Fatalf("assign trust-policy diff identity: %v", err)
	}
	return assigned
}
