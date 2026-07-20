package resources

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestAirgapGateTrustPolicyIdentityAndValidation(t *testing.T) {
	first := validAirgapGateTrustPolicy(t)
	second := validAirgapGateTrustPolicy(t)
	if first.Metadata.PolicyID != second.Metadata.PolicyID {
		t.Fatalf("expected deterministic trust-policy identity, got %q and %q", first.Metadata.PolicyID, second.Metadata.PolicyID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid trust policy: %#v", report.Diagnostics)
	}
	first.Spec.TrustedSignerIdentities[0].Status = "revoked"
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated content retained trust-policy identity")
	}
}

func TestAirgapGateTrustPolicyRejectsUnsortedSigners(t *testing.T) {
	policy := validAirgapGateTrustPolicy(t)
	policy.Spec.TrustedSignerIdentities = []AirgapTrustedSignerIdentity{
		policy.Spec.TrustedSignerIdentities[1],
		policy.Spec.TrustedSignerIdentities[0],
	}
	assertDiagnostic(t, policy.Validate(), "YARA-AGT-013", "spec.trustedSignerIdentities[1]")
}

func TestAirgapGateTrustPolicyVerifiesGateResult(t *testing.T) {
	policy := validAirgapGateTrustPolicy(t)
	result := validAirgapGateResult(t)
	result.Spec.Target.ReferenceDigest = policy.Spec.TargetReferenceDigest
	result.Spec.Signer.KeyID = policy.Spec.TrustedSignerIdentities[0].KeyID
	result.Spec.Signer.PublicKeyDigest = policy.Spec.TrustedSignerIdentities[0].PublicKeyDigest
	key, _ := base64.StdEncoding.DecodeString(policy.Spec.TrustedSignerIdentities[0].PublicKey)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	if !bytes.Equal(private.Public().(ed25519.PublicKey), key) {
		t.Fatal("unexpected signer key fixture mismatch")
	}
	var err error
	result, err = result.Sign(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.VerifyGateResult(result, time.Date(2026, 7, 20, 10, 5, 0, 0, time.UTC)); err != nil {
		t.Fatalf("expected verification success, got %v", err)
	}
}

func validAirgapGateTrustPolicy(t *testing.T) AirgapGateTrustPolicy {
	t.Helper()
	privateA := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	privateB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	publicA := privateA.Public().(ed25519.PublicKey)
	publicB := privateB.Public().(ed25519.PublicKey)
	policy := AirgapGateTrustPolicy{
		APIVersion: APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata: AirgapGateTrustPolicyMetadata{
			Name: "airgap-gate-policy",
		},
		Spec: AirgapGateTrustPolicySpec{
			RecordedAt:            time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
			TargetReferenceDigest: testDigest('f'),
			TrustedSignerIdentities: []AirgapTrustedSignerIdentity{
				{
					KeyID:           "gate-key-a",
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(publicA),
					PublicKeyDigest: gateResultPublicKeyDigest(publicA),
					ValidFrom:       time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
					ValidUntil:      time.Date(2026, 7, 20, 11, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
					Status:          "active",
				},
				{
					KeyID:           "gate-key-b",
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(publicB),
					PublicKeyDigest: gateResultPublicKeyDigest(publicB),
					Status:          "revoked",
				},
			},
			Limitations: []string{
				"Trust policy contains only non-secret signer identities.",
			},
		},
	}
	assigned, err := policy.AssignPolicyID()
	if err != nil {
		t.Fatalf("assign trust-policy identity: %v", err)
	}
	return assigned
}
