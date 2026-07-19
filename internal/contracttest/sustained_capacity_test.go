package contracttest

import (
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestSustainedCapacityChecksPassExactRepeatedEnvelope(t *testing.T) {
	checks, err := sustainedCapacityChecks(modelInferenceObservation{
		MemoryAvailableBytes:      modelInferenceMemoryBytes,
		DiskAvailableBytes:        32 << 30,
		AcquisitionCompleted:      true,
		ArtifactVerified:          true,
		ServerStarted:             true,
		NetworkMode:               "none",
		HealthStatus:              200,
		InferenceStatus:           200,
		Model:                     "yara-contract",
		FinishReason:              "stop",
		CompletionTokens:          3,
		ContentDigest:             "sha256:" + strings.Repeat("a", 64),
		GPUUtilizationPercent:     sustainedCapacityGPUPercent,
		SustainedAttempted:        sustainedCapacityRequests,
		SustainedCompleted:        sustainedCapacityRequests,
		SustainedPromptTokens:     256,
		SustainedCompletionTokens: 96,
		SustainedTotalTokens:      352,
	}, 6<<30)
	if err != nil {
		t.Fatalf("evaluate sustained checks: %v", err)
	}
	for _, item := range checks {
		if item.Status != "passed" || item.DiagnosticCode != "" {
			t.Fatalf("unexpected check: %#v", item)
		}
	}
	measurement := findCheck(t, checks, "capacity.sustained-requests").Measurements
	if measurement["expectedRequests"] != sustainedCapacityRequests || measurement["observedCompleted"] != sustainedCapacityRequests {
		t.Fatalf("sustained envelope is not reviewable: %#v", measurement)
	}
}

func TestSustainedCapacityChecksRejectPartialRun(t *testing.T) {
	observation := passingPolicyObservation()
	observation.SustainedAttempted = sustainedCapacityRequests
	observation.SustainedCompleted = sustainedCapacityRequests - 1
	observation.SustainedPromptTokens = 256
	observation.SustainedCompletionTokens = 93
	observation.SustainedTotalTokens = 349
	checks, err := sustainedCapacityChecks(observation, 6<<30)
	if err != nil {
		t.Fatalf("evaluate sustained checks: %v", err)
	}
	assertCheck(t, checks, "capacity.sustained-requests", "failed", "YARA-CTR-181")
}

func TestSustainedCapacityProgramDoesNotPersistRequestsOrResponses(t *testing.T) {
	program := sustainedCapacityProgram(sustainedCapacityRequests, sustainedCapacityMaxTokens)
	for _, required := range []string{"range(32)", `"sustainedRequestsCompleted"`, `"sustainedTotalTokens"`, "timeout=120"} {
		if !strings.Contains(program, required) {
			t.Fatalf("sustained program lacks %q", required)
		}
	}
	if strings.Contains(program, `"prompt":`) || strings.Contains(program, `"completion":`) {
		t.Fatal("sustained program persists raw prompt or completion")
	}
}

func TestEvaluateSustainedCapacityProducesNarrowEvidence(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GeForce RTX 4090", "amd64")
	evidence := "sha256:" + strings.Repeat("d", 64)
	artifactChecks := []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}
	capacityChecks := []resources.ContractTestCheck{{ID: "capacity.sustained-requests", Status: "passed", EvidenceDigest: evidence}}
	result, err := EvaluateSustainedCapacity("sustained-capacity", "sha256:"+strings.Repeat("a", 64), target, environment, artifactChecks, capacityChecks)
	if err != nil {
		t.Fatalf("evaluate sustained capacity: %v", err)
	}
	if result.Spec.Mode != "sustained-capacity" || result.Spec.Outcome != "passed" {
		t.Fatalf("unexpected result: %#v", result.Spec)
	}
	if !slicesContain(result.Spec.Limitations, "The contract records no latency, throughput, quality or service-level objective and makes no performance claim.") {
		t.Fatalf("sustained limitations overclaim support: %#v", result.Spec.Limitations)
	}
}
