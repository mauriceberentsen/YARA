package resources

import "testing"

func TestIntegrationPublicationAttestationIdentityAndValidation(t *testing.T) {
	first := validIntegrationPublicationAttestation(t)
	second := validIntegrationPublicationAttestation(t)
	if first.Metadata.AttestationID != second.Metadata.AttestationID {
		t.Fatalf("expected deterministic integration publication attestation identity, got %q and %q", first.Metadata.AttestationID, second.Metadata.AttestationID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid integration publication attestation: %#v", report.Diagnostics)
	}
	first.Spec.Decision = PromotionDecisionChangesRequired
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated integration publication attestation retained identity")
	}
}

func validIntegrationPublicationAttestation(t *testing.T) IntegrationPublicationAttestation {
	t.Helper()
	attestation := IntegrationPublicationAttestation{
		APIVersion: APIVersion,
		Kind:       "IntegrationPublicationAttestation",
		Metadata: IntegrationPublicationAttestationMeta{
			Name: "integration-publication-attestation",
		},
		Spec: IntegrationPublicationAttestationSpec{
			ReviewedAt:       "2026-07-20T12:00:00Z",
			ExpiresAt:        "2026-07-27T12:00:00Z",
			CatalogDigest:    testDigest('a'),
			AssertionRef:     "compat.vllm-qwen-coder-7b-awq-gb10",
			SelectedEvidence: []string{testDigest('b')},
			Reviewer: ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			Decision:        PromotionDecisionApproved,
			ReasonReference: "ticket-integration-publication-123",
			MaxEvidenceAge:  "720h",
			Limitations: []string{
				"Integration publication attestation binds one assertion to immutable integration evidence identities.",
				"Integration publication attestation records review metadata and does not mutate catalog resources.",
			},
		},
	}
	assigned, err := attestation.AssignAttestationID()
	if err != nil {
		t.Fatalf("assign integration publication attestation identity: %v", err)
	}
	return assigned
}
