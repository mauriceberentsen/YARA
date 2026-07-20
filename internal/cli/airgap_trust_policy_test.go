package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestAirgapGateTrustPolicyRecordWritesPolicyAndAudit(t *testing.T) {
	directory := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, publicPath := writeAuthorizationKeys(t, directory, publicKey, privateKey)
	outputPath := filepath.Join(directory, "airgap-trust-policy.yaml")
	auditPath := filepath.Join(directory, "airgap-trust-policy.audit.jsonl")
	args := []string{
		"airgap", "gate-trust-policy", "record",
		"--target-reference-digest", testCLIDigest('c'),
		"--signer", "key-id=operations-key-1,public-key=" + publicPath + ",status=active",
		"--name", "airgap-trust-policy",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("record trust policy failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	policy, err := resources.LoadAirgapGateTrustPolicy(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Metadata.PolicyID == "" || len(policy.Spec.TrustedSignerIdentities) != 1 {
		t.Fatalf("trust policy missing expected signer identity: %#v", policy)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "airgap.gate-trust-policy.record.completed" {
		t.Fatalf("terminal trust-policy audit missing: %#v", events)
	}
}

func TestAirgapGateTrustPolicyRecordRejectsMalformedSigner(t *testing.T) {
	directory := t.TempDir()
	args := []string{
		"airgap", "gate-trust-policy", "record",
		"--target-reference-digest", testCLIDigest('c'),
		"--signer", "key-id=operations-key-1,status=active",
		"--name", "airgap-trust-policy",
		"--output", filepath.Join(directory, "airgap-trust-policy.yaml"),
		"--audit-output", filepath.Join(directory, "airgap-trust-policy.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("malformed signer input should fail invalid input: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestAirgapGateTrustPolicyDiffWritesArtifactAndAudit(t *testing.T) {
	directory := t.TempDir()
	keyA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = privA, privB
	fromPolicy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata:   resources.AirgapGateTrustPolicyMetadata{Name: "from-policy"},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:            "2026-07-20T10:00:00Z",
			TargetReferenceDigest: testCLIDigest('c'),
			TrustedSignerIdentities: []resources.AirgapTrustedSignerIdentity{{
				KeyID:           "operations-key-1",
				Algorithm:       "Ed25519",
				PublicKey:       base64.StdEncoding.EncodeToString(keyA),
				PublicKeyDigest: resources.PublicKeyDigest(keyA),
				Status:          "active",
			}},
			Limitations: []string{"from policy"},
		},
	}
	fromPolicy, err = fromPolicy.AssignPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	toPolicy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata:   resources.AirgapGateTrustPolicyMetadata{Name: "to-policy"},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:            "2026-07-20T10:05:00Z",
			TargetReferenceDigest: testCLIDigest('c'),
			TrustedSignerIdentities: []resources.AirgapTrustedSignerIdentity{
				{
					KeyID:           "operations-key-1",
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(keyA),
					PublicKeyDigest: resources.PublicKeyDigest(keyA),
					Status:          "active",
				},
				{
					KeyID:           "operations-key-2",
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(keyB),
					PublicKeyDigest: resources.PublicKeyDigest(keyB),
					Status:          "active",
				},
			},
			Limitations: []string{"to policy"},
		},
	}
	toPolicy, err = toPolicy.AssignPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	fromPath := filepath.Join(directory, "from-policy.yaml")
	toPath := filepath.Join(directory, "to-policy.yaml")
	writeYAMLFixture(t, fromPath, fromPolicy)
	writeYAMLFixture(t, toPath, toPolicy)
	outPath := filepath.Join(directory, "policy-diff.yaml")
	auditPath := filepath.Join(directory, "policy-diff.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"airgap", "gate-trust-policy", "diff", "--from-policy", fromPath, "--to-policy", toPath, "--name", "policy-diff", "--output", outPath, "--audit-output", auditPath}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("trust policy diff failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	diff, err := resources.LoadAirgapGateTrustPolicyDiff(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Metadata.DiffID == "" || diff.Spec.ToPolicyID != toPolicy.Metadata.PolicyID {
		t.Fatalf("unexpected trust-policy diff output: %#v", diff)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "airgap.gate-trust-policy.diff.completed" {
		t.Fatalf("terminal trust-policy diff audit missing: %#v", events)
	}
}

func TestAirgapGateTrustPolicyReviewTransitionWritesArtifactAndAudit(t *testing.T) {
	directory := t.TempDir()
	keyA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = privA, privB
	fromPolicy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata:   resources.AirgapGateTrustPolicyMetadata{Name: "from-policy"},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:            "2026-07-20T10:00:00Z",
			TargetReferenceDigest: testCLIDigest('c'),
			TrustedSignerIdentities: []resources.AirgapTrustedSignerIdentity{
				{
					KeyID:           "operations-key-1",
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(keyA),
					PublicKeyDigest: resources.PublicKeyDigest(keyA),
					Status:          "active",
				},
				{
					KeyID:           "operations-key-2",
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(keyB),
					PublicKeyDigest: resources.PublicKeyDigest(keyB),
					Status:          "active",
				},
			},
			Limitations: []string{"from policy"},
		},
	}
	fromPolicy, err = fromPolicy.AssignPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	toPolicy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata:   resources.AirgapGateTrustPolicyMetadata{Name: "to-policy"},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:            "2026-07-20T10:05:00Z",
			TargetReferenceDigest: testCLIDigest('c'),
			TrustedSignerIdentities: []resources.AirgapTrustedSignerIdentity{{
				KeyID:           "operations-key-1",
				Algorithm:       "Ed25519",
				PublicKey:       base64.StdEncoding.EncodeToString(keyA),
				PublicKeyDigest: resources.PublicKeyDigest(keyA),
				Status:          "active",
			}},
			Limitations: []string{"to policy"},
		},
	}
	toPolicy, err = toPolicy.AssignPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	fromPath := filepath.Join(directory, "from-policy.yaml")
	toPath := filepath.Join(directory, "to-policy.yaml")
	writeYAMLFixture(t, fromPath, fromPolicy)
	writeYAMLFixture(t, toPath, toPolicy)
	diffPath := filepath.Join(directory, "policy-diff.yaml")
	diffAuditPath := filepath.Join(directory, "policy-diff.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"airgap", "gate-trust-policy", "diff", "--from-policy", fromPath, "--to-policy", toPath, "--name", "policy-diff", "--output", diffPath, "--audit-output", diffAuditPath}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("trust policy diff failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	diff, err := resources.LoadAirgapGateTrustPolicyDiff(diffPath)
	if err != nil {
		t.Fatal(err)
	}
	reviewPath := filepath.Join(directory, "transition-review.yaml")
	reviewAuditPath := filepath.Join(directory, "transition-review.audit.jsonl")
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"airgap", "gate-trust-policy", "review-transition", "--policy-diff", diffPath, "--decision", "approved", "--reviewer-role", "platform-security", "--reason-reference", "ticket-transition", "--name", "transition-review", "--output", reviewPath, "--audit-output", reviewAuditPath}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("transition review failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	review, err := resources.LoadAirgapGateTransitionReview(reviewPath)
	if err != nil {
		t.Fatal(err)
	}
	if review.Spec.PolicyDiffID != diff.Metadata.DiffID || review.Spec.Decision != resources.PromotionDecisionApproved {
		t.Fatalf("unexpected transition review output: %#v", review.Spec)
	}
	events, err := audit.LoadJSONL(reviewAuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "airgap.gate-trust-policy.review-transition.completed" {
		t.Fatalf("terminal transition review audit missing: %#v", events)
	}
}
