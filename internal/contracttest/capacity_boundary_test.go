package contracttest

import (
	"context"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestCapacityBoundaryChecksPassExactAdvertisedContext(t *testing.T) {
	contextTokens := capacityBoundaryMaxContext
	checks, err := capacityBoundaryChecks(modelInferenceObservation{
		MemoryAvailableBytes: modelInferenceMemoryBytes,
		DiskAvailableBytes:   32 << 30,
		AcquisitionCompleted: true,
		ArtifactVerified:     true,
		ServerStarted:        true,
		NetworkMode:          "none",
		HealthStatus:         200,
		InferenceStatus:      200,
		Model:                "yara-contract",
		FinishReason:         "length",
		PromptTokens:         contextTokens - capacityBoundaryMaxTokens,
		CompletionTokens:     capacityBoundaryMaxTokens,
		TotalTokens:          contextTokens,
		ContentDigest:        "sha256:" + strings.Repeat("a", 64),
	}, 6<<30, contextTokens)
	if err != nil {
		t.Fatalf("evaluate boundary checks: %v", err)
	}
	for _, item := range checks {
		if item.Status != "passed" || item.DiagnosticCode != "" {
			t.Fatalf("unexpected check: %#v", item)
		}
	}
}

func TestCapacityBoundaryChecksRejectShortPromptObservation(t *testing.T) {
	contextTokens := capacityBoundaryMaxContext
	checks, err := capacityBoundaryChecks(modelInferenceObservation{
		MemoryAvailableBytes: modelInferenceMemoryBytes,
		DiskAvailableBytes:   32 << 30,
		AcquisitionCompleted: true,
		ArtifactVerified:     true,
		ServerStarted:        true,
		NetworkMode:          "none",
		HealthStatus:         200,
		InferenceStatus:      200,
		Model:                "yara-contract",
		PromptTokens:         contextTokens - capacityBoundaryMaxTokens - 1,
		CompletionTokens:     1,
		TotalTokens:          contextTokens - capacityBoundaryMaxTokens,
		ContentDigest:        "sha256:" + strings.Repeat("a", 64),
	}, 6<<30, contextTokens)
	if err != nil {
		t.Fatalf("evaluate boundary checks: %v", err)
	}
	assertCheck(t, checks, "capacity.context-boundary", "failed", "YARA-CTR-157")
}

func TestCapacityBoundaryProgramUsesServerSideTruncationWithoutPersistingPrompt(t *testing.T) {
	program := capacityBoundaryProgram(capacityBoundaryMaxContext, capacityBoundaryMaxTokens)
	for _, required := range []string{`"truncate_prompt_tokens":target`, `"promptTokens"`, `"totalTokens"`, `timeout=600`} {
		if !strings.Contains(program, required) {
			t.Fatalf("capacity request lacks %q", required)
		}
	}
	if strings.Contains(program, `"prompt":`) || strings.Contains(program, `"completion":`) {
		t.Fatal("capacity evidence program persists raw prompt or completion")
	}
}

func TestCapacityBoundaryRunnerRejectsCatalogContextAboveSafetyCap(t *testing.T) {
	target := testTarget()
	target.Conditions.MaximumContextTokens = capacityBoundaryMaxContext + 1
	if _, err := (SSHCapacityBoundaryRunner{}).Run(context.Background(), "tester@example", target); err == nil {
		t.Fatal("capacity runner accepted context above its safety cap")
	}
}

func TestEvaluateCapacityBoundaryProducesValidScopedEvidence(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GeForce RTX 4090", "amd64")
	evidence := "sha256:" + strings.Repeat("d", 64)
	artifactChecks := []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}
	capacityChecks := []resources.ContractTestCheck{{ID: "capacity.context-boundary", Status: "passed", EvidenceDigest: evidence}}
	result, err := EvaluateCapacityBoundary("capacity-boundary", "sha256:"+strings.Repeat("a", 64), target, environment, artifactChecks, capacityChecks)
	if err != nil {
		t.Fatalf("evaluate capacity boundary: %v", err)
	}
	if result.Spec.Mode != "capacity-boundary" || result.Spec.Outcome != "passed" {
		t.Fatalf("unexpected result: %#v", result.Spec)
	}
	if !slicesContain(result.Spec.Limitations, "The contract tests one request at concurrency 1 and makes no sustained-load, throughput or latency claim.") {
		t.Fatalf("capacity limitations overclaim support: %#v", result.Spec.Limitations)
	}
}

func slicesContain(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
