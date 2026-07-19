package contracttest

import (
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestLifecycleContractChecksPassRestartRecovery(t *testing.T) {
	checks, err := lifecycleContractChecks(passingLifecycleObservation(), 6<<30)
	if err != nil {
		t.Fatalf("evaluate lifecycle checks: %v", err)
	}
	for _, item := range checks {
		if item.Status != "passed" || item.DiagnosticCode != "" {
			t.Fatalf("unexpected check: %#v", item)
		}
	}
}

func TestLifecycleContractChecksDetectConfigurationDrift(t *testing.T) {
	observation := passingLifecycleObservation()
	observation.ConfigurationStable = false
	checks, err := lifecycleContractChecks(observation, 6<<30)
	if err != nil {
		t.Fatalf("evaluate lifecycle checks: %v", err)
	}
	assertCheck(t, checks, "lifecycle.configuration-stable", "failed", "YARA-CTR-174")
}

func TestLifecycleContractChecksBlockDetailsWhenRestartWasNotObserved(t *testing.T) {
	observation := passingLifecycleObservation()
	observation.LifecycleInspected = false
	observation.PostRestartHealthStatus = 0
	checks, err := lifecycleContractChecks(observation, 6<<30)
	if err != nil {
		t.Fatalf("evaluate lifecycle checks: %v", err)
	}
	assertCheck(t, checks, "lifecycle.inspect-state", "failed", "YARA-CTR-169")
	assertCheck(t, checks, "lifecycle.post-restart-health", "blocked", "YARA-CTR-149")
}

func TestLifecycleServingScriptRestartsAndComparesIdentity(t *testing.T) {
	script := modelServingScript("aW1hZ2U=", "cmVwbw==", "cmV2aXNpb24=", "W10=", "MQ==", 6<<30, modelServingProfile{
		ContextTokens: 1024, Concurrency: 1, MaxTokens: 8, RequestProgram: boundedInferenceProgram(8), TestLifecycle: true,
	})
	for _, required := range []string{
		`test_lifecycle='true'`, `docker restart "$server"`, `configurationDigest`, `containerIdentityStable`, `startedAtAdvanced`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("lifecycle script lacks %q", required)
		}
	}
}

func TestEvaluateLifecycleContractProducesValidScopedEvidence(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GeForce RTX 4090", "amd64")
	evidence := "sha256:" + strings.Repeat("d", 64)
	artifactChecks := []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}
	lifecycleChecks := []resources.ContractTestCheck{{ID: "lifecycle.restart-completed", Status: "passed", EvidenceDigest: evidence}}
	result, err := EvaluateLifecycleContract("lifecycle-contract", "sha256:"+strings.Repeat("a", 64), target, environment, artifactChecks, lifecycleChecks)
	if err != nil {
		t.Fatalf("evaluate lifecycle contract: %v", err)
	}
	if result.Spec.Mode != "lifecycle-contract" || result.Spec.Outcome != "passed" {
		t.Fatalf("unexpected result: %#v", result.Spec)
	}
}

func passingLifecycleObservation() modelInferenceObservation {
	observation := passingPolicyObservation()
	observation.LifecycleInspected = true
	observation.PreRestartHealthStatus = 200
	observation.PreRestartInference = 200
	observation.PreRestartModel = "yara-contract"
	observation.PreRestartContent = "sha256:" + strings.Repeat("b", 64)
	observation.PreRestartCompletion = 3
	observation.RestartCompleted = true
	observation.StartedAtAdvanced = true
	observation.ContainerIdentityStable = true
	observation.ConfigurationStable = true
	observation.PostRestartHealthStatus = 200
	return observation
}
