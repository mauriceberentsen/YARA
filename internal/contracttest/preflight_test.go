package contracttest

import (
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestParseObservationNormalizesGB10Host(t *testing.T) {
	environment, err := parseObservation("tester@gpu-runner.example", []byte(strings.Join([]string{
		"os\tlinux", "arch\taarch64", "docker.available\ttrue", "docker.version\t29.2.1",
		"docker.os\tlinux", "docker.arch\taarch64", "docker.nvidia\ttrue",
		"gpu\tNVIDIA GB10, 580.142, 12.1", "",
	}, "\n")))
	if err != nil {
		t.Fatalf("parse observation: %v", err)
	}
	if environment.Architecture != "arm64" || environment.Docker.Architecture != "arm64" || len(environment.Accelerators) != 1 || environment.Accelerators[0].Model != "NVIDIA GB10" {
		t.Fatalf("unexpected environment: %#v", environment)
	}
	if !strings.HasPrefix(environment.ReferenceDigest, "sha256:") {
		t.Fatalf("target was not pseudonymized: %q", environment.ReferenceDigest)
	}
}

func TestEvaluateBlocksHardwareMismatchWithoutFailingPlatform(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GB10", "arm64")
	result, err := Evaluate("gb10-preflight", "sha256:"+strings.Repeat("a", 64), target, environment)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Spec.Outcome != "blocked" {
		t.Fatalf("expected blocked mismatch, got %q", result.Spec.Outcome)
	}
	assertCheck(t, result.Spec.Checks, "accelerator.identity", "blocked", "YARA-CTR-106")
	assertCheck(t, result.Spec.Checks, "accelerator.compute-capability", "blocked", "YARA-CTR-109")
	assertCheck(t, result.Spec.Checks, "runtime.platform", "passed", "")
	assertCheck(t, result.Spec.Checks, "accelerator.driver", "passed", "")
	assertCheck(t, result.Spec.Checks, "host.linux", "passed", "")
}

func TestEvaluatePassesMatchingRTX4090Preflight(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GeForce RTX 4090", "amd64")
	result, err := Evaluate("rtx4090-preflight", "sha256:"+strings.Repeat("a", 64), target, environment)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Spec.Outcome != "passed" || !result.Validate().Valid {
		t.Fatalf("expected valid passing result, got %#v / %#v", result, result.Validate().Diagnostics)
	}
}

func TestEvaluateSelectsMatchingAcceleratorFromHeterogeneousHost(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GB10", "amd64")
	environment.Accelerators = append(environment.Accelerators, resources.ContractTestAccelerator{
		Vendor: "nvidia", Model: "NVIDIA GeForce RTX 4090", DriverVersion: "580.142", ComputeCapability: "8.9",
	})
	result, err := Evaluate("heterogeneous-preflight", "sha256:"+strings.Repeat("a", 64), target, environment)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Spec.Outcome != "passed" {
		t.Fatalf("expected matching accelerator to pass, got %#v", result.Spec.Checks)
	}
}

func TestEvaluateRuntimeSmokeProducesValidBoundedEvidence(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GeForce RTX 4090", "amd64")
	evidence := "sha256:" + strings.Repeat("d", 64)
	artifactChecks := []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}
	runtimeChecks := []resources.ContractTestCheck{{ID: "runtime.cuda-tensor", Status: "passed", EvidenceDigest: evidence}}
	result, err := EvaluateRuntimeSmoke("runtime-smoke", "sha256:"+strings.Repeat("a", 64), target, environment, artifactChecks, runtimeChecks)
	if err != nil {
		t.Fatalf("evaluate runtime smoke: %v", err)
	}
	if result.Spec.Mode != "runtime-smoke" || result.Spec.Outcome != "passed" || !result.Validate().Valid {
		t.Fatalf("unexpected runtime result: %#v / %#v", result, result.Validate().Diagnostics)
	}
}

func TestRuntimeImagePinsDigestAndRemovesMutableTag(t *testing.T) {
	image, ok := runtimeImage([]catalog.ArtifactReference{{
		Type: "oci-image", Ref: "registry.example:5000/team/image:v1", Digest: "sha256:" + strings.Repeat("a", 64),
	}})
	if !ok || image != "registry.example:5000/team/image@sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("unexpected pinned image %q", image)
	}
}

func TestRuntimeSmokeScriptEnforcesIsolationAndOwnedCleanup(t *testing.T) {
	script := runtimeSmokeScript("aW1hZ2U=", "bmFtZQ==")
	for _, required := range []string{
		"--network none", "--read-only", "--pids-limit 256", "--memory 4294967296",
		`trap 'docker rm -f "$name"`, `grep -qx "$name"`, `docker image inspect "$image"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("runtime smoke script lacks safety control %q", required)
		}
	}
	for _, forbidden := range []string{"docker stop", "docker system prune", "-p ", "--volume", "-v "} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("runtime smoke script contains unsafe operation %q", forbidden)
		}
	}
}

func TestEvaluateFailsUnsupportedRuntimePlatform(t *testing.T) {
	target := testTarget()
	environment := testEnvironment("NVIDIA GeForce RTX 4090", "riscv64")
	result, err := Evaluate("unsupported-platform", "sha256:"+strings.Repeat("a", 64), target, environment)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Spec.Outcome != "failed" {
		t.Fatalf("expected failed platform, got %q", result.Spec.Outcome)
	}
	assertCheck(t, result.Spec.Checks, "runtime.platform", "failed", "YARA-CTR-103")
}

func TestSSHProbeRejectsUnsafeTarget(t *testing.T) {
	if _, err := (SSHProbe{}).Observe(t.Context(), "data@host; touch /tmp/nope"); err == nil {
		t.Fatal("expected unsafe target to be rejected")
	}
}

func testTarget() catalog.ContractTarget {
	return catalog.ContractTarget{
		AssertionID: "compat.test", RuntimeRef: "core.vllm@0.25.1", ModelRef: "models.qwen@1.0.0",
		HardwareProfileID: "hardware.rtx4090", HardwareVendor: "nvidia", HardwareModels: []string{"NVIDIA GeForce RTX 4090"},
		HardwareComputeCapability: "8.9",
		RuntimeArtifacts:          []catalog.ArtifactReference{{Type: "oci-image", Platforms: []string{"linux/amd64", "linux/arm64"}}},
		Conditions:                catalog.CompatibilityConditions{MinimumDriverVersion: "535"},
	}
}

func testEnvironment(model, architecture string) resources.ContractTestEnvironment {
	return resources.ContractTestEnvironment{
		Transport: "ssh", ReferenceDigest: "sha256:" + strings.Repeat("b", 64), OperatingSystem: "linux", Architecture: architecture,
		Docker:       resources.ContractTestDocker{Available: true, Version: "29.2.1", OperatingSystem: "linux", Architecture: architecture, NVIDIARuntime: true},
		Accelerators: []resources.ContractTestAccelerator{{Vendor: "nvidia", Model: model, DriverVersion: "580.142", ComputeCapability: computeCapability(model)}},
	}
}

func computeCapability(model string) string {
	if model == "NVIDIA GeForce RTX 4090" {
		return "8.9"
	}
	return "12.1"
}

func assertCheck(t *testing.T, checks []resources.ContractTestCheck, id, status, code string) {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			if check.Status != status || check.DiagnosticCode != code {
				t.Fatalf("unexpected %s check: %#v", id, check)
			}
			return
		}
	}
	t.Fatalf("missing check %q", id)
}
