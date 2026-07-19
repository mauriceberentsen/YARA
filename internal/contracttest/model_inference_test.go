package contracttest

import (
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestModelInferenceChecksPassBoundedHealthyRequest(t *testing.T) {
	checks, err := modelInferenceChecks(modelInferenceObservation{
		MemoryAvailableBytes:  modelInferenceMemoryBytes,
		DiskAvailableBytes:    32 << 30,
		AcquisitionCompleted:  true,
		ArtifactVerified:      true,
		ServerStarted:         true,
		NetworkMode:           "none",
		HealthStatus:          200,
		InferenceStatus:       200,
		Model:                 "yara-contract",
		FinishReason:          "stop",
		CompletionTokens:      3,
		ContentDigest:         "sha256:" + strings.Repeat("a", 64),
		GPUUtilizationPercent: modelInferenceGPUPercent,
	}, 6<<30)
	if err != nil {
		t.Fatalf("evaluate checks: %v", err)
	}
	for _, item := range checks {
		if item.Status != "passed" || item.DiagnosticCode != "" {
			t.Fatalf("unexpected check: %#v", item)
		}
	}
	gpu := findCheck(t, checks, "model.gpu-memory-utilization")
	if gpu.Measurements["configuredPercent"] != modelInferenceGPUPercent || gpu.Measurements["expectedPercent"] != modelInferenceGPUPercent {
		t.Fatalf("GPU allocation is not reviewable: %#v", gpu.Measurements)
	}
}

func TestModelInferenceChecksBlockBeforeAcquisitionWhenCapacityIsLow(t *testing.T) {
	checks, err := modelInferenceChecks(modelInferenceObservation{
		FailureStage:         "capacity",
		MemoryAvailableBytes: modelInferenceMemoryBytes - 1,
		DiskAvailableBytes:   32 << 30,
	}, 6<<30)
	if err != nil {
		t.Fatalf("evaluate checks: %v", err)
	}
	assertCheck(t, checks, "capacity.memory-available", "blocked", "YARA-CTR-140")
	assertCheck(t, checks, "model.acquisition", "blocked", "YARA-CTR-149")
	assertCheck(t, checks, "model.server-started", "blocked", "YARA-CTR-149")
}

func TestModelInferenceChecksPreserveServerFailureAfterVerifiedAcquisition(t *testing.T) {
	checks, err := modelInferenceChecks(modelInferenceObservation{
		FailureStage:         "server",
		MemoryAvailableBytes: modelInferenceMemoryBytes,
		DiskAvailableBytes:   32 << 30,
	}, 6<<30)
	if err != nil {
		t.Fatalf("evaluate checks: %v", err)
	}
	assertCheck(t, checks, "model.acquisition", "passed", "")
	assertCheck(t, checks, "model.artifact-local", "passed", "")
	assertCheck(t, checks, "model.server-started", "failed", "YARA-CTR-143")
	assertCheck(t, checks, "model.health", "blocked", "YARA-CTR-149")
}

func TestModelInferenceChecksClassifyHealthFailureWithoutLeakingLogs(t *testing.T) {
	checks, err := modelInferenceChecks(modelInferenceObservation{
		FailureStage:         "health",
		FailureReason:        "unsupported-runtime",
		MemoryAvailableBytes: modelInferenceMemoryBytes,
		DiskAvailableBytes:   32 << 30,
		NetworkMode:          "none",
		ServerLogDigest:      "sha256:" + strings.Repeat("e", 64),
	}, 6<<30)
	if err != nil {
		t.Fatalf("evaluate checks: %v", err)
	}
	assertCheck(t, checks, "model.server-started", "passed", "")
	assertCheck(t, checks, "model.network-isolation", "passed", "")
	assertCheck(t, checks, "model.health", "failed", "YARA-CTR-154")
}

func TestModelInferenceChecksClassifyKVCacheCapacityFailure(t *testing.T) {
	checks, err := modelInferenceChecks(modelInferenceObservation{
		FailureStage:          "health",
		FailureReason:         "kv-cache-capacity",
		MemoryAvailableBytes:  modelInferenceMemoryBytes,
		DiskAvailableBytes:    32 << 30,
		NetworkMode:           "none",
		ServerLogDigest:       "sha256:" + strings.Repeat("f", 64),
		GPUUtilizationPercent: modelInferenceGPUPercent,
	}, 6<<30)
	if err != nil {
		t.Fatalf("evaluate checks: %v", err)
	}
	assertCheck(t, checks, "model.health", "failed", "YARA-CTR-179")
	assertCheck(t, checks, "model.gpu-memory-utilization", "passed", "")
}

func TestModelInferenceScriptPinsIsolationBoundsAndOwnedCleanup(t *testing.T) {
	script := modelInferenceScript("aW1hZ2U=", "cmVwbw==", "cmV2aXNpb24=", "W10=", "MQ==", 6<<30)
	for _, required := range []string{
		"--network none", "--read-only", "--memory 17179869184", "--memory-swap 17179869184",
		"--max-model-len 1024", "--max-num-seqs 1", "--gpu-memory-utilization 0.08",
		"--no-async-scheduling", "--no-enable-prefix-caching",
		"maximum number of tokens that can be stored in (the )?KV cache", `reason="kv-cache-capacity"`,
		`docker rm -f "$server" "$download"`, `docker volume rm "$volume"`,
		"HF_HUB_OFFLINE=1", "VLLM_NO_USAGE_STATS=1",
		"--tmpfs /tmp:rw,exec,nosuid,nodev", "--tmpfs /root/.cache:rw,exec,nosuid,nodev",
		"--tmpfs /root/.config:rw,noexec,nosuid,nodev", "--tmpfs /root/.triton:rw,exec,nosuid,nodev",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("model inference script lacks safety control %q", required)
		}
	}
	for _, forbidden := range []string{"docker stop", "docker system prune", "--privileged", "-p ", "--network host"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("model inference script contains unsafe operation %q", forbidden)
		}
	}
	if strings.Contains(script, "%!") {
		t.Fatal("model inference script contains an unresolved format directive")
	}
}

func TestEvaluateModelInferenceProducesValidBoundedEvidence(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GeForce RTX 4090", "amd64")
	evidence := "sha256:" + strings.Repeat("d", 64)
	artifactChecks := []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}
	modelChecks := []resources.ContractTestCheck{{ID: "model.inference-http", Status: "passed", EvidenceDigest: evidence}}
	result, err := EvaluateModelInference("model-inference", "sha256:"+strings.Repeat("a", 64), target, environment, artifactChecks, modelChecks)
	if err != nil {
		t.Fatalf("evaluate model inference: %v", err)
	}
	if result.Spec.Mode != "model-inference" || result.Spec.Outcome != "passed" {
		t.Fatalf("unexpected result: %#v", result.Spec)
	}
}

func TestModelArtifactBytesSumsVerifiedFiles(t *testing.T) {
	artifact := catalog.ArtifactReference{Files: []catalog.ArtifactFile{{SizeBytes: 10}, {SizeBytes: 20}}}
	if modelArtifactBytes(artifact) != 30 {
		t.Fatal("model artifact size was not summed")
	}
}
