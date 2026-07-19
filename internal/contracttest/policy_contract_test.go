package contracttest

import (
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestPolicyContractChecksPassHardenedServingState(t *testing.T) {
	checks, err := policyContractChecks(passingPolicyObservation(), 6<<30)
	if err != nil {
		t.Fatalf("evaluate policy checks: %v", err)
	}
	for _, item := range checks {
		if item.Status != "passed" || item.DiagnosticCode != "" {
			t.Fatalf("unexpected check: %#v", item)
		}
	}
}

func TestPolicyContractChecksFailPrivilegeControl(t *testing.T) {
	observation := passingPolicyObservation()
	observation.PrivilegesRestricted = false
	checks, err := policyContractChecks(observation, 6<<30)
	if err != nil {
		t.Fatalf("evaluate policy checks: %v", err)
	}
	assertCheck(t, checks, "policy.privileges-restricted", "failed", "YARA-CTR-166")
}

func TestPolicyContractChecksBlockDetailsWhenInspectionUnavailable(t *testing.T) {
	observation := passingPolicyObservation()
	observation.PolicyInspected = false
	observation.EgressBlocked = false
	checks, err := policyContractChecks(observation, 6<<30)
	if err != nil {
		t.Fatalf("evaluate policy checks: %v", err)
	}
	assertCheck(t, checks, "policy.inspect-state", "failed", "YARA-CTR-160")
	assertCheck(t, checks, "policy.egress-blocked", "blocked", "YARA-CTR-149")
}

func TestPolicyServingScriptPinsHardeningAndActiveInspection(t *testing.T) {
	script := modelServingScript("aW1hZ2U=", "cmVwbw==", "cmV2aXNpb24=", "W10=", "MQ==", 6<<30, modelServingProfile{
		ContextTokens: 1024, Concurrency: 1, MaxTokens: 8, RequestProgram: boundedInferenceProgram(8), InspectPolicy: true,
	})
	for _, required := range []string{
		"--security-opt no-new-privileges=true", "--cap-drop ALL", "VLLM_NO_USAGE_STATS=1",
		"VLLM_DO_NOT_TRACK=1", "DO_NOT_TRACK=1", `inspect_policy='true'`, `s.connect(("1.1.1.1",53))`,
		`cleanup_completed=true`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("policy script lacks %q", required)
		}
	}
}

func TestEvaluatePolicyContractProducesValidScopedEvidence(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GeForce RTX 4090", "amd64")
	evidence := "sha256:" + strings.Repeat("d", 64)
	artifactChecks := []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}
	policyChecks := []resources.ContractTestCheck{{ID: "policy.egress-blocked", Status: "passed", EvidenceDigest: evidence}}
	result, err := EvaluatePolicyContract("policy-contract", "sha256:"+strings.Repeat("a", 64), target, environment, artifactChecks, policyChecks)
	if err != nil {
		t.Fatalf("evaluate policy contract: %v", err)
	}
	if result.Spec.Mode != "policy-contract" || result.Spec.Outcome != "passed" {
		t.Fatalf("unexpected result: %#v", result.Spec)
	}
}

func passingPolicyObservation() modelInferenceObservation {
	return modelInferenceObservation{
		MemoryAvailableBytes: modelInferenceMemoryBytes, DiskAvailableBytes: 32 << 30,
		AcquisitionCompleted: true, ArtifactVerified: true, ServerStarted: true,
		NetworkMode: "none", HealthStatus: 200, InferenceStatus: 200, Model: "yara-contract",
		CompletionTokens: 3, ContentDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyInspected: true, EgressBlocked: true, PortsUnpublished: true, TelemetryDisabled: true,
		RootFilesystemReadOnly: true, TmpfsRestricted: true, MountsRestricted: true,
		DockerSocketAbsent: true, SensitiveEnvAbsent: true, PrivilegesRestricted: true, CleanupCompleted: true,
	}
}
