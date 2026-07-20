package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
