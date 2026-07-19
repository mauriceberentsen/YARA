package resources

import (
	"strings"
	"testing"
)

func TestContractTestResultIdentityAndValidation(t *testing.T) {
	result := validContractTestResult(t)
	if report := result.Validate(); !report.Valid {
		t.Fatalf("valid contract result rejected: %#v", report.Diagnostics)
	}
	result.Spec.Environment.Accelerators[0].Model = "tampered"
	report := result.Validate()
	assertDiagnostic(t, report, "YARA-CTR-021", "metadata.resultId")
}

func TestContractTestResultOutcomeMustMatchChecks(t *testing.T) {
	result := validContractTestResult(t)
	result.Spec.Outcome = "passed"
	result, err := result.AssignResultID()
	if err != nil {
		t.Fatal(err)
	}
	report := result.Validate()
	assertDiagnostic(t, report, "YARA-CTR-019", "spec.outcome")
}

func TestContractTestResultRequiresExplicitLimitations(t *testing.T) {
	result := validContractTestResult(t)
	result.Spec.Limitations = nil
	result, err := result.AssignResultID()
	if err != nil {
		t.Fatalf("assign result ID: %v", err)
	}
	report := result.Validate()
	assertDiagnostic(t, report, "YARA-CTR-020", "spec.limitations")
}

func TestContractTestResultRejectsIncompleteAcceleratorFacts(t *testing.T) {
	result := validContractTestResult(t)
	result.Spec.Environment.Accelerators[0].ComputeCapability = ""
	result, err := result.AssignResultID()
	if err != nil {
		t.Fatalf("assign result ID: %v", err)
	}
	report := result.Validate()
	assertDiagnostic(t, report, "YARA-CTR-022", "spec.environment.accelerators[0]")
}

func validContractTestResult(t *testing.T) ContractTestResult {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	result := ContractTestResult{
		APIVersion: APIVersion, Kind: "ContractTestResult",
		Metadata: ContractTestResultMetadata{Name: "reference-preflight"},
		Spec: ContractTestResultSpec{
			Mode: "preflight", Outcome: "blocked", CatalogDigest: digest,
			AssertionRef: "compat.example",
			Target:       ContractTestTarget{RuntimeRef: "runtime@1", ModelRef: "model@1", HardwareProfileRef: "hardware.example"},
			Environment: ContractTestEnvironment{
				Transport: "ssh", ReferenceDigest: digest, OperatingSystem: "linux", Architecture: "arm64",
				Docker:       ContractTestDocker{Available: true, Version: "29.2.1", OperatingSystem: "linux", Architecture: "arm64", NVIDIARuntime: true},
				Accelerators: []ContractTestAccelerator{{Vendor: "nvidia", Model: "NVIDIA GB10", DriverVersion: "580.142", ComputeCapability: "12.1"}},
			},
			Checks: []ContractTestCheck{
				{ID: "accelerator.identity", Status: "blocked", DiagnosticCode: "YARA-CTR-102", EvidenceDigest: digest},
				{ID: "docker.available", Status: "passed", EvidenceDigest: digest},
			},
			Limitations: []string{"No workload was started."},
		},
	}
	result, err := result.AssignResultID()
	if err != nil {
		t.Fatalf("assign result ID: %v", err)
	}
	return result
}
