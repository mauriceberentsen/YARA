package resources

import "testing"

func TestPublicationChainRehearsalIdentityAndValidation(t *testing.T) {
	first := validPublicationChainRehearsal(t)
	second := validPublicationChainRehearsal(t)
	if first.Metadata.RehearsalID != second.Metadata.RehearsalID {
		t.Fatalf("expected deterministic publication-chain rehearsal identity, got %q and %q", first.Metadata.RehearsalID, second.Metadata.RehearsalID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid publication-chain rehearsal: %#v", report.Diagnostics)
	}
	first.Spec.Decision = PromotionDecisionChangesRequired
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated publication-chain rehearsal retained identity")
	}
}

func validPublicationChainRehearsal(t *testing.T) PublicationChainRehearsal {
	t.Helper()
	rehearsal := PublicationChainRehearsal{
		APIVersion: APIVersion,
		Kind:       "PublicationChainRehearsal",
		Metadata: PublicationChainRehearsalMeta{
			Name: "publication-chain-rehearsal",
		},
		Spec: PublicationChainRehearsalSpec{
			RehearsedAt:                         "2026-07-20T15:00:00Z",
			CatalogDigest:                       testDigest('a'),
			AssertionRef:                        "compat.vllm-qwen-coder-7b-awq-gb10",
			LifecycleProofApprovalID:            testDigest('b'),
			IntegrationPublicationAttestationID: testDigest('c'),
			CoverageReportID:                    testDigest('d'),
			TrustPolicyID:                       testDigest('e'),
			BoundaryAuditHead:                   testDigest('f'),
			AuthorizationIDs:                    []string{testDigest('1'), testDigest('2')},
			Reviewer: ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			Decision:        PromotionDecisionApproved,
			ReasonReference: "ticket-publication-chain-123",
			MaxEvidenceAge:  "720h",
			Limitations: []string{
				"Publication-chain rehearsal does not mutate deployment targets or catalog manifests.",
				"Publication-chain rehearsal records immutable readiness evidence only.",
			},
		},
	}
	assigned, err := rehearsal.AssignRehearsalID()
	if err != nil {
		t.Fatalf("assign publication-chain rehearsal identity: %v", err)
	}
	return assigned
}
