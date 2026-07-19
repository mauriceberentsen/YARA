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
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type fixedContractProbe struct {
	environment resources.ContractTestEnvironment
	err         error
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
