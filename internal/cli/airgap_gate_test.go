package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestAirgapProvenanceGateEvaluateWritesResultAndAudit(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	gatePublicKey, gatePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gatePrivatePath, _ := writeAuthorizationKeys(t, directory, gatePublicKey, gatePrivateKey)
	args := []string{
		"airgap", "provenance-gate", "evaluate",
		"--bundle", valueForFlag(paths, "--bundle"),
		"--import-receipt", valueForFlag(paths, "--import-receipt"),
		"--transfer-receipt", valueForFlag(paths, "--transfer-receipt"),
		"--scan-receipt", valueForFlag(paths, "--scan-receipt"),
		"--private-key", gatePrivatePath,
		"--key-id", "operations-key-1",
		"--reason-reference", "ticket-gate-1",
		"--name", "airgap-gate",
		"--output", filepath.Join(directory, "airgap-gate.yaml"),
		"--audit-output", filepath.Join(directory, "airgap-gate.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("airgap gate evaluate failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	result, err := resources.LoadAirgapProvenanceGateResult(filepath.Join(directory, "airgap-gate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Spec.Outcome != "passed" || result.Metadata.GateResultID == "" {
		t.Fatalf("gate result missing expected successful binding: %#v", result.Spec)
	}
	events, err := audit.LoadJSONL(filepath.Join(directory, "airgap-gate.audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "airgap.provenance-gate.evaluate.completed" {
		t.Fatalf("terminal gate audit missing: %#v", events)
	}
	trustPolicy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata: resources.AirgapGateTrustPolicyMetadata{
			Name: "airgap-gate-trust-policy",
		},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:            now.Add(time.Minute).Format(time.RFC3339Nano),
			TargetReferenceDigest: result.Spec.Target.ReferenceDigest,
			TrustedSignerIdentities: []resources.AirgapTrustedSignerIdentity{{
				KeyID:           "operations-key-1",
				Algorithm:       "Ed25519",
				PublicKey:       base64.StdEncoding.EncodeToString(gatePublicKey),
				PublicKeyDigest: resources.PublicKeyDigest(gatePublicKey),
				ValidFrom:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
				ValidUntil:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
				Status:          "active",
			}},
			Limitations: []string{"Trust policy contains only non-secret signer material."},
		},
	}
	trustPolicy, err = trustPolicy.AssignPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(directory, "airgap-gate-policy.yaml")
	writeYAMLFixture(t, policyPath, trustPolicy)
	fromPolicy := trustPolicy
	fromPolicy.Metadata.Name = "airgap-gate-trust-policy-from"
	fromPolicy.Spec.TrustedSignerIdentities = append(fromPolicy.Spec.TrustedSignerIdentities, resources.AirgapTrustedSignerIdentity{
		KeyID:           "operations-key-2",
		Algorithm:       "Ed25519",
		PublicKey:       base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize)).Public().(ed25519.PublicKey)),
		PublicKeyDigest: resources.PublicKeyDigest(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize)).Public().(ed25519.PublicKey)),
		Status:          "active",
	})
	fromPolicy, err = fromPolicy.AssignPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	fromPolicyPath := filepath.Join(directory, "airgap-gate-policy-from.yaml")
	writeYAMLFixture(t, fromPolicyPath, fromPolicy)
	policyDiffPath := filepath.Join(directory, "airgap-gate-policy-diff.yaml")
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"airgap", "gate-trust-policy", "diff", "--from-policy", fromPolicyPath, "--to-policy", policyPath, "--name", "airgap-policy-diff", "--output", policyDiffPath, "--audit-output", filepath.Join(directory, "airgap-gate-policy-diff.audit.jsonl")}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("airgap trust-policy diff failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	diff, err := resources.LoadAirgapGateTrustPolicyDiff(policyDiffPath)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"airgap", "provenance-gate", "verify", "--gate-result", filepath.Join(directory, "airgap-gate.yaml"), "--trust-policy", policyPath, "--confirm-policy", trustPolicy.Metadata.PolicyID, "--policy-diff", policyDiffPath, "--confirm-policy-diff", diff.Metadata.DiffID}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("airgap gate verify failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestAirgapProvenanceGateEvaluateFailsOnBrokenScanChain(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	gatePublicKey, gatePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gatePrivatePath, _ := writeAuthorizationKeys(t, directory, gatePublicKey, gatePrivateKey)
	scanPath := valueForFlag(paths, "--scan-receipt")
	scanReceipt, err := resources.LoadArtifactScanReceipt(scanPath)
	if err != nil {
		t.Fatal(err)
	}
	scanReceipt.Spec.PriorReceiptIDs = []string{testCLIDigest('f')}
	scanReceipt, err = scanReceipt.AssignScanReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, scanPath, scanReceipt)
	args := []string{
		"airgap", "provenance-gate", "evaluate",
		"--bundle", valueForFlag(paths, "--bundle"),
		"--import-receipt", valueForFlag(paths, "--import-receipt"),
		"--transfer-receipt", valueForFlag(paths, "--transfer-receipt"),
		"--scan-receipt", valueForFlag(paths, "--scan-receipt"),
		"--private-key", gatePrivatePath,
		"--key-id", "operations-key-1",
		"--reason-reference", "ticket-gate-2",
		"--name", "airgap-gate",
		"--output", filepath.Join(directory, "airgap-gate.yaml"),
		"--audit-output", filepath.Join(directory, "airgap-gate.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("broken scan chain gate should be infeasible: exit=%d stdout=%s", exit, stdout.String())
	}
}

func TestAirgapProvenanceGateVerifyFailsForRevokedSigner(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	gatePublicKey, gatePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gatePrivatePath, _ := writeAuthorizationKeys(t, directory, gatePublicKey, gatePrivateKey)
	gatePath := filepath.Join(directory, "airgap-gate.yaml")
	args := []string{
		"airgap", "provenance-gate", "evaluate",
		"--bundle", valueForFlag(paths, "--bundle"),
		"--import-receipt", valueForFlag(paths, "--import-receipt"),
		"--transfer-receipt", valueForFlag(paths, "--transfer-receipt"),
		"--scan-receipt", valueForFlag(paths, "--scan-receipt"),
		"--private-key", gatePrivatePath,
		"--key-id", "operations-key-1",
		"--reason-reference", "ticket-gate-revoked",
		"--name", "airgap-gate",
		"--output", gatePath,
		"--audit-output", filepath.Join(directory, "airgap-gate.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("airgap gate evaluate failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	result, err := resources.LoadAirgapProvenanceGateResult(gatePath)
	if err != nil {
		t.Fatal(err)
	}
	trustPolicy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata: resources.AirgapGateTrustPolicyMetadata{
			Name: "airgap-gate-trust-policy-revoked",
		},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:            now.Add(time.Minute).Format(time.RFC3339Nano),
			TargetReferenceDigest: result.Spec.Target.ReferenceDigest,
			TrustedSignerIdentities: []resources.AirgapTrustedSignerIdentity{
				{
					KeyID:           "operations-key-0",
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize)).Public().(ed25519.PublicKey)),
					PublicKeyDigest: resources.PublicKeyDigest(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize)).Public().(ed25519.PublicKey)),
					Status:          "active",
				},
				{
					KeyID:           "operations-key-1",
					Algorithm:       "Ed25519",
					PublicKey:       base64.StdEncoding.EncodeToString(gatePublicKey),
					PublicKeyDigest: resources.PublicKeyDigest(gatePublicKey),
					Status:          "revoked",
				},
			},
			Limitations: []string{"Revoked signer policy test."},
		},
	}
	trustPolicy, err = trustPolicy.AssignPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(directory, "airgap-gate-policy-revoked.yaml")
	writeYAMLFixture(t, policyPath, trustPolicy)
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"airgap", "provenance-gate", "verify", "--gate-result", gatePath, "--trust-policy", policyPath, "--confirm-policy", trustPolicy.Metadata.PolicyID}, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("expected revoked signer verification failure: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestAirgapProvenanceGateVerifyRejectsPolicyConfirmationMismatch(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	gatePublicKey, gatePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gatePrivatePath, _ := writeAuthorizationKeys(t, directory, gatePublicKey, gatePrivateKey)
	args := []string{
		"airgap", "provenance-gate", "evaluate",
		"--bundle", valueForFlag(paths, "--bundle"),
		"--import-receipt", valueForFlag(paths, "--import-receipt"),
		"--transfer-receipt", valueForFlag(paths, "--transfer-receipt"),
		"--scan-receipt", valueForFlag(paths, "--scan-receipt"),
		"--private-key", gatePrivatePath,
		"--key-id", "operations-key-1",
		"--reason-reference", "ticket-gate-confirmation",
		"--name", "airgap-gate",
		"--output", filepath.Join(directory, "airgap-gate.yaml"),
		"--audit-output", filepath.Join(directory, "airgap-gate.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("airgap gate evaluate failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	result, err := resources.LoadAirgapProvenanceGateResult(filepath.Join(directory, "airgap-gate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	trustPolicy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata:   resources.AirgapGateTrustPolicyMetadata{Name: "airgap-gate-confirmation-policy"},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:            now.Add(time.Minute).Format(time.RFC3339Nano),
			TargetReferenceDigest: result.Spec.Target.ReferenceDigest,
			TrustedSignerIdentities: []resources.AirgapTrustedSignerIdentity{{
				KeyID:           "operations-key-1",
				Algorithm:       "Ed25519",
				PublicKey:       base64.StdEncoding.EncodeToString(gatePublicKey),
				PublicKeyDigest: resources.PublicKeyDigest(gatePublicKey),
				Status:          "active",
			}},
			Limitations: []string{"Confirmation mismatch test."},
		},
	}
	trustPolicy, err = trustPolicy.AssignPolicyID()
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(directory, "airgap-gate-confirmation-policy.yaml")
	writeYAMLFixture(t, policyPath, trustPolicy)
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"airgap", "provenance-gate", "verify", "--gate-result", filepath.Join(directory, "airgap-gate.yaml"), "--trust-policy", policyPath, "--confirm-policy", testCLIDigest('f')}, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("expected confirmation mismatch failure: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}
