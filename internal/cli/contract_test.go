package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type fixedContractProbe struct {
	environment resources.ContractTestEnvironment
	err         error
}

type fixedArtifactVerifier struct {
	checks []resources.ContractTestCheck
	err    error
}

func (v fixedArtifactVerifier) Verify(context.Context, catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	return v.checks, v.err
}

type fixedRuntimeSmokeRunner struct {
	checks []resources.ContractTestCheck
	err    error
	called *bool
}

type fixedModelInferenceRunner struct {
	checks []resources.ContractTestCheck
	err    error
	called *bool
}

type fixedCapacityBoundaryRunner struct {
	checks []resources.ContractTestCheck
	err    error
	called *bool
}

type fixedPolicyContractRunner struct {
	checks []resources.ContractTestCheck
	err    error
	called *bool
}

func (r fixedPolicyContractRunner) Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	if r.called != nil {
		*r.called = true
	}
	return r.checks, r.err
}

func (r fixedCapacityBoundaryRunner) Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	if r.called != nil {
		*r.called = true
	}
	return r.checks, r.err
}

func (r fixedModelInferenceRunner) Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	if r.called != nil {
		*r.called = true
	}
	return r.checks, r.err
}

func (r fixedRuntimeSmokeRunner) Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	if r.called != nil {
		*r.called = true
	}
	return r.checks, r.err
}

func (p fixedContractProbe) Observe(context.Context, string) (resources.ContractTestEnvironment, error) {
	return p.environment, p.err
}

func TestContractPreflightPersistsBlockedHardwareEvidenceAndRemoteAudit(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "result.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	args := contractArgs(outputPath, auditPath)
	var stdout, stderr bytes.Buffer
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInfeasible {
		t.Fatalf("expected infeasible exit, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var response map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["valid"] != true || response["outcome"] != "blocked" {
		t.Fatalf("unexpected response: %#v", response)
	}
	result, err := resources.LoadContractTestResult(outputPath)
	if err != nil {
		t.Fatalf("load result: %v", err)
	}
	if report := result.Validate(); !report.Valid {
		t.Fatalf("invalid result: %#v", report.Diagnostics)
	}
	if result.Spec.Outcome != "blocked" || result.Spec.Environment.Accelerators[0].Model != "NVIDIA GB10" {
		t.Fatalf("unexpected evidence: %#v", result.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "contract.preflight.blocked" || terminal.Spec.Outcome != "infeasible" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-CTR-106") {
		t.Fatalf("unexpected terminal event: %#v", terminal.Spec)
	}
	if terminal.Spec.Target != "ssh:"+result.Spec.Environment.ReferenceDigest || strings.Contains(string(mustReadFile(t, auditPath)), "gpu-runner.example") {
		t.Fatalf("remote identity was not pseudonymized: %#v", terminal.Spec)
	}
	if len(terminal.Spec.Subjects) != 2 || terminal.Spec.Subjects[1].Digest != result.Metadata.ResultID {
		t.Fatalf("result identity absent from audit: %#v", terminal.Spec.Subjects)
	}
}

func TestContractPreflightPassesMatchingEnvironmentAndValidatesResult(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GeForce RTX 4090", "amd64")})
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "result.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(contractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("expected success, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	result, err := resources.LoadContractTestResult(outputPath)
	if err != nil {
		t.Fatalf("load result: %v", err)
	}
	if result.Spec.Outcome != "passed" {
		t.Fatalf("unexpected outcome: %s", result.Spec.Outcome)
	}
	validationAudit := filepath.Join(temp, "validation-audit.jsonl")
	stdout.Reset()
	stderr.Reset()
	if exitCode := Run([]string{"contract", "validate", outputPath, "--audit-output", validationAudit}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("contract validation failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"valid\": true") {
		t.Fatalf("unexpected validation response: %s", stdout.String())
	}
	events, err := audit.LoadJSONL(validationAudit)
	if err != nil {
		t.Fatalf("load validation audit: %v", err)
	}
	terminal := events[len(events)-1]
	if len(terminal.Spec.Subjects) != 1 || terminal.Spec.Subjects[0].Digest != result.Metadata.ResultID {
		t.Fatalf("validation audit does not bind the semantic result ID: %#v", terminal.Spec.Subjects)
	}
}

func TestContractPreflightRollsBackResultWhenAuditCannotBeWritten(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GeForce RTX 4090", "amd64")})
	temp := t.TempDir()
	outputPath := filepath.Join(temp, "result.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("prepare audit: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(contractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: %s", exitCode, stdout.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("result must be rolled back after audit failure: %v", err)
	}
}

func TestContractRuntimeSmokePersistsArtifactRuntimeAndAuditEvidence(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	previousVerifier, previousRunner := runtimeSmokeArtifactVerifier, runtimeSmokeRunner
	runtimeSmokeArtifactVerifier = fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}}
	runtimeSmokeRunner = fixedRuntimeSmokeRunner{checks: []resources.ContractTestCheck{{ID: "runtime.cuda-tensor", Status: "passed", EvidenceDigest: evidence}}}
	t.Cleanup(func() {
		runtimeSmokeArtifactVerifier, runtimeSmokeRunner = previousVerifier, previousRunner
	})
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "runtime.yaml"), filepath.Join(temp, "audit.jsonl")
	args := []string{
		"contract", "runtime-smoke",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--target", "tester@gpu-runner.example", "--name", "gb10-runtime-smoke",
		"--output", outputPath, "--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("runtime smoke failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	result, err := resources.LoadContractTestResult(outputPath)
	if err != nil {
		t.Fatalf("load result: %v", err)
	}
	if result.Spec.Mode != "runtime-smoke" || result.Spec.Outcome != "passed" {
		t.Fatalf("unexpected runtime result: %#v", result.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "contract.runtime-smoke.completed" || terminal.Spec.Subjects[1].Digest != result.Metadata.ResultID {
		t.Fatalf("unexpected runtime audit: %#v", terminal.Spec)
	}
}

func TestContractRuntimeSmokeDoesNotStartWorkloadWhenArtifactGateFails(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	called := false
	setRuntimeSmokeDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "failed", DiagnosticCode: "YARA-CTR-120", EvidenceDigest: evidence}}},
		fixedRuntimeSmokeRunner{called: &called},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "runtime.yaml"), filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(runtimeContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInfeasible {
		t.Fatalf("expected failed gate, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if called {
		t.Fatal("runtime workload started after artifact verification failed")
	}
	result, err := resources.LoadContractTestResult(outputPath)
	if err != nil {
		t.Fatalf("load negative result: %v", err)
	}
	if result.Spec.Outcome != "failed" || !slices.Contains(result.Spec.Limitations, "Runtime container was not started because an earlier gate failed.") {
		t.Fatalf("unexpected failed-gate evidence: %#v", result.Spec)
	}
}

func TestContractRuntimeSmokeRollsBackResultWhenAuditCannotBeWritten(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	setRuntimeSmokeDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}},
		fixedRuntimeSmokeRunner{checks: []resources.ContractTestCheck{{ID: "runtime.cuda-tensor", Status: "passed", EvidenceDigest: evidence}}},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "runtime.yaml"), filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("prepare audit: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(runtimeContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("runtime result must be rolled back after audit failure: %v", err)
	}
}

func TestContractModelInferencePersistsBoundedResultAndAuditEvidence(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	setModelInferenceDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}},
		fixedModelInferenceRunner{checks: []resources.ContractTestCheck{{ID: "model.inference-http", Status: "passed", EvidenceDigest: evidence}}},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "model.yaml"), filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(modelContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("model inference failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	result, err := resources.LoadContractTestResult(outputPath)
	if err != nil {
		t.Fatalf("load model result: %v", err)
	}
	if result.Spec.Mode != "model-inference" || result.Spec.Outcome != "passed" {
		t.Fatalf("unexpected model result: %#v", result.Spec)
	}
	if result.Spec.Runner == nil || result.Spec.Runner.Version == "" || !strings.HasPrefix(result.Spec.Runner.BinaryDigest, "sha256:") {
		t.Fatalf("model result does not bind the runner executable: %#v", result.Spec.Runner)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "contract.model-inference.completed" || terminal.Spec.Subjects[1].Digest != result.Metadata.ResultID {
		t.Fatalf("unexpected model audit: %#v", terminal.Spec)
	}
}

func TestContractModelInferenceDoesNotStartWhenArtifactGateFails(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	called := false
	setModelInferenceDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "failed", DiagnosticCode: "YARA-CTR-120", EvidenceDigest: evidence}}},
		fixedModelInferenceRunner{called: &called},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "model.yaml"), filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(modelContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInfeasible {
		t.Fatalf("expected failed gate, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if called {
		t.Fatal("model workload started after artifact verification failed")
	}
	result, err := resources.LoadContractTestResult(outputPath)
	if err != nil {
		t.Fatalf("load negative model result: %v", err)
	}
	if result.Spec.Outcome != "failed" || !slices.Contains(result.Spec.Limitations, "Model workload was not started because an earlier gate failed.") {
		t.Fatalf("unexpected failed-gate evidence: %#v", result.Spec)
	}
}

func TestContractModelInferenceRollsBackResultWhenAuditCannotBeWritten(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	setModelInferenceDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}},
		fixedModelInferenceRunner{checks: []resources.ContractTestCheck{{ID: "model.inference-http", Status: "passed", EvidenceDigest: evidence}}},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "model.yaml"), filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("prepare audit: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(modelContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("model result must be rolled back after audit failure: %v", err)
	}
}

func TestContractCapacityBoundaryPersistsScopedResultAndAuditEvidence(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	setCapacityBoundaryDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}},
		fixedCapacityBoundaryRunner{checks: []resources.ContractTestCheck{{ID: "capacity.context-boundary", Status: "passed", EvidenceDigest: evidence}}},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "capacity.yaml"), filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(capacityContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("capacity boundary failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	result, err := resources.LoadContractTestResult(outputPath)
	if err != nil {
		t.Fatalf("load capacity result: %v", err)
	}
	if result.Spec.Mode != "capacity-boundary" || result.Spec.Outcome != "passed" || result.Spec.Runner == nil {
		t.Fatalf("unexpected capacity result: %#v", result.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "contract.capacity-boundary.completed" || terminal.Spec.Subjects[1].Digest != result.Metadata.ResultID {
		t.Fatalf("unexpected capacity audit: %#v", terminal.Spec)
	}
}

func TestContractCapacityBoundaryDoesNotStartWhenArtifactGateFails(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	called := false
	setCapacityBoundaryDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "failed", DiagnosticCode: "YARA-CTR-120", EvidenceDigest: evidence}}},
		fixedCapacityBoundaryRunner{called: &called},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "capacity.yaml"), filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(capacityContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInfeasible {
		t.Fatalf("expected failed gate, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if called {
		t.Fatal("capacity workload started after artifact verification failed")
	}
}

func TestContractCapacityBoundaryRollsBackResultWhenAuditCannotBeWritten(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	setCapacityBoundaryDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}},
		fixedCapacityBoundaryRunner{checks: []resources.ContractTestCheck{{ID: "capacity.context-boundary", Status: "passed", EvidenceDigest: evidence}}},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "capacity.yaml"), filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("prepare audit: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(capacityContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("capacity result must be rolled back after audit failure: %v", err)
	}
}

func TestContractPolicyPersistsScopedResultAndAuditEvidence(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	setPolicyContractDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}},
		fixedPolicyContractRunner{checks: []resources.ContractTestCheck{{ID: "policy.egress-blocked", Status: "passed", EvidenceDigest: evidence}}},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "policy.yaml"), filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(policyContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("policy contract failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	result, err := resources.LoadContractTestResult(outputPath)
	if err != nil {
		t.Fatalf("load policy result: %v", err)
	}
	if result.Spec.Mode != "policy-contract" || result.Spec.Outcome != "passed" || result.Spec.Runner == nil {
		t.Fatalf("unexpected policy result: %#v", result.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "contract.policy.completed" || terminal.Spec.Subjects[1].Digest != result.Metadata.ResultID {
		t.Fatalf("unexpected policy audit: %#v", terminal.Spec)
	}
}

func TestContractPolicyRollsBackResultWhenAuditCannotBeWritten(t *testing.T) {
	setContractProbe(t, fixedContractProbe{environment: contractEnvironment("NVIDIA GB10", "arm64")})
	evidence := "sha256:" + strings.Repeat("d", 64)
	setPolicyContractDependencies(t,
		fixedArtifactVerifier{checks: []resources.ContractTestCheck{{ID: "artifact.runtime.0.digest", Status: "passed", EvidenceDigest: evidence}}},
		fixedPolicyContractRunner{checks: []resources.ContractTestCheck{{ID: "policy.egress-blocked", Status: "passed", EvidenceDigest: evidence}}},
	)
	temp := t.TempDir()
	outputPath, auditPath := filepath.Join(temp, "policy.yaml"), filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("prepare audit: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(policyContractArgs(outputPath, auditPath), &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("policy result must be rolled back after audit failure: %v", err)
	}
}

func setRuntimeSmokeDependencies(t *testing.T, verifier fixedArtifactVerifier, runner fixedRuntimeSmokeRunner) {
	t.Helper()
	previousVerifier, previousRunner := runtimeSmokeArtifactVerifier, runtimeSmokeRunner
	runtimeSmokeArtifactVerifier, runtimeSmokeRunner = verifier, runner
	t.Cleanup(func() {
		runtimeSmokeArtifactVerifier, runtimeSmokeRunner = previousVerifier, previousRunner
	})
}

func runtimeContractArgs(outputPath, auditPath string) []string {
	return []string{
		"contract", "runtime-smoke",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--target", "tester@gpu-runner.example", "--name", "gb10-runtime-smoke",
		"--output", outputPath, "--audit-output", auditPath,
	}
}

func setModelInferenceDependencies(t *testing.T, verifier fixedArtifactVerifier, runner fixedModelInferenceRunner) {
	t.Helper()
	previousVerifier, previousRunner := runtimeSmokeArtifactVerifier, modelInferenceRunner
	runtimeSmokeArtifactVerifier, modelInferenceRunner = verifier, runner
	t.Cleanup(func() {
		runtimeSmokeArtifactVerifier, modelInferenceRunner = previousVerifier, previousRunner
	})
}

func modelContractArgs(outputPath, auditPath string) []string {
	return []string{
		"contract", "model-inference",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--target", "tester@gpu-runner.example", "--name", "gb10-model-inference",
		"--output", outputPath, "--audit-output", auditPath,
	}
}

func setCapacityBoundaryDependencies(t *testing.T, verifier fixedArtifactVerifier, runner fixedCapacityBoundaryRunner) {
	t.Helper()
	previousVerifier, previousRunner := runtimeSmokeArtifactVerifier, capacityBoundaryRunner
	runtimeSmokeArtifactVerifier, capacityBoundaryRunner = verifier, runner
	t.Cleanup(func() {
		runtimeSmokeArtifactVerifier, capacityBoundaryRunner = previousVerifier, previousRunner
	})
}

func capacityContractArgs(outputPath, auditPath string) []string {
	return []string{
		"contract", "capacity-boundary",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--target", "tester@gpu-runner.example", "--name", "gb10-capacity-boundary",
		"--output", outputPath, "--audit-output", auditPath,
	}
}

func setPolicyContractDependencies(t *testing.T, verifier fixedArtifactVerifier, runner fixedPolicyContractRunner) {
	t.Helper()
	previousVerifier, previousRunner := runtimeSmokeArtifactVerifier, policyContractRunner
	runtimeSmokeArtifactVerifier, policyContractRunner = verifier, runner
	t.Cleanup(func() {
		runtimeSmokeArtifactVerifier, policyContractRunner = previousVerifier, previousRunner
	})
}

func policyContractArgs(outputPath, auditPath string) []string {
	return []string{
		"contract", "policy",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--target", "tester@gpu-runner.example", "--name", "gb10-policy-contract",
		"--output", outputPath, "--audit-output", auditPath,
	}
}

func setContractProbe(t *testing.T, probe fixedContractProbe) {
	t.Helper()
	previous := contractProbe
	contractProbe = probe
	t.Cleanup(func() { contractProbe = previous })
}

func contractArgs(outputPath, auditPath string) []string {
	return []string{
		"contract", "preflight",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-rtx4090",
		"--target", "tester@gpu-runner.example",
		"--name", "rtx4090-preflight",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
}

func contractEnvironment(model, architecture string) resources.ContractTestEnvironment {
	return resources.ContractTestEnvironment{
		Transport: "ssh", ReferenceDigest: "sha256:" + strings.Repeat("c", 64),
		OperatingSystem: "linux", Architecture: architecture,
		Docker: resources.ContractTestDocker{
			Available: true, Version: "29.2.1", OperatingSystem: "linux",
			Architecture: architecture, NVIDIARuntime: true,
		},
		Accelerators: []resources.ContractTestAccelerator{{
			Vendor: "nvidia", Model: model, DriverVersion: "580.142", ComputeCapability: contractComputeCapability(model),
		}},
	}
}

func contractComputeCapability(model string) string {
	if model == "NVIDIA GeForce RTX 4090" {
		return "8.9"
	}
	return "12.1"
}
