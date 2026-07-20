package resources

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestExecutionAuthorizationRequiresTrustedSignatureAndFreshness(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	authorization := ExecutionAuthorization{
		APIVersion: APIVersion, Kind: "ExecutionAuthorization", Metadata: ExecutionAuthorizationMetadata{Name: "execution-auth"},
		Spec: ExecutionAuthorizationSpec{
			IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
			PlanID: testDigest('a'), BundleID: testDigest('b'), PreflightResultID: testDigest('c'), ChangeSetID: testDigest('d'), ApprovalID: testDigest('e'),
			Target:      TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('f'), ServerVersion: "v1.35.2"},
			Issuer:      ExecutionAuthorizationIssuer{KeyID: "operations-key-1"},
			Constraints: ExecutionAuthorizationConstraints{AllowedActions: []string{"create", "no-op"}, MaxOperations: 12, AllowActiveVerification: true, AcceptedPreflightBlockers: []string{"YARA-TPR-114"}},
		},
	}
	authorization, err = authorization.Sign(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if report := authorization.Validate(); !report.Valid {
		t.Fatalf("signed authorization invalid: %#v", report.Diagnostics)
	}
	if err := authorization.Verify(publicKey, now.Add(time.Minute)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := authorization.Verify(publicKey, now.Add(10*time.Minute)); err == nil {
		t.Fatal("expired authorization verified")
	}
	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := authorization.Verify(wrongPublic, now.Add(time.Minute)); err == nil {
		t.Fatal("untrusted key verified")
	}
	tampered := authorization
	tampered.Spec.Constraints.MaxOperations++
	if err := tampered.Verify(publicKey, now.Add(time.Minute)); err == nil {
		t.Fatal("tampered authorization verified")
	}
}

func TestExecutionAuthorizationRejectsInvalidDeleteAndLongValidity(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	authorization := ExecutionAuthorization{APIVersion: APIVersion, Kind: "ExecutionAuthorization", Metadata: ExecutionAuthorizationMetadata{Name: "execution-auth"}, Spec: ExecutionAuthorizationSpec{
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(16 * time.Minute).Format(time.RFC3339Nano), PlanID: testDigest('a'), BundleID: testDigest('b'), PreflightResultID: testDigest('c'), ChangeSetID: testDigest('d'), ApprovalID: testDigest('e'), Target: TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('f'), ServerVersion: "v1.35.2"}, Issuer: ExecutionAuthorizationIssuer{KeyID: "key"}, Constraints: ExecutionAuthorizationConstraints{AllowedActions: []string{"create"}, MaxOperations: 1, AllowDelete: true},
	}}
	authorization, _ = authorization.Sign(privateKey)
	assertDiagnostic(t, authorization.Validate(), "YARA-AUT-011", "spec.expiresAt")
	assertDiagnostic(t, authorization.Validate(), "YARA-AUT-015", "spec.constraints")
}

func TestExecutionAuthorizationAllowsDeleteOnlyRetirementProfile(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	authorization := ExecutionAuthorization{APIVersion: APIVersion, Kind: "ExecutionAuthorization", Metadata: ExecutionAuthorizationMetadata{Name: "retirement-auth"}, Spec: ExecutionAuthorizationSpec{
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano), PlanID: testDigest('a'), BundleID: testDigest('b'), PreflightResultID: testDigest('c'), ChangeSetID: testDigest('d'), ApprovalID: testDigest('e'), Target: TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('f'), ServerVersion: "v1.35.2"}, Issuer: ExecutionAuthorizationIssuer{KeyID: "key"}, Constraints: ExecutionAuthorizationConstraints{AllowedActions: []string{"delete"}, MaxOperations: 12, AllowDelete: true},
	}}
	authorization, _ = authorization.Sign(privateKey)
	if report := authorization.Validate(); !report.Valid {
		t.Fatalf("delete-only authorization should be valid: %#v", report.Diagnostics)
	}
}
