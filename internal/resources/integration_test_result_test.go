package resources

import "testing"

func TestIntegrationTestResultIdentityAndValidation(t *testing.T) {
	result := validIntegrationTestResult(t)
	if report := result.Validate(); !report.Valid {
		t.Fatalf("expected valid result: %#v", report.Diagnostics)
	}
	result.Spec.ComponentRefs[0] = "component.changed@1.0.0"
	if report := result.Validate(); report.Valid {
		t.Fatal("mutated content retained its identity")
	}
}

func TestIntegrationTestResultTopologyRequiresExactBindings(t *testing.T) {
	result := validIntegrationTestResult(t)
	result.Spec.TopologyRef = "core.invalid@1.0.0"
	if report := result.Validate(); report.Valid {
		t.Fatal("component-smoke result accepted a topology claim")
	}

	result = validIntegrationTestResult(t)
	result.Spec.Mode = "topology-end-to-end"
	result.Spec.TopologyRef = "core.local@1.0.0"
	result.Spec.ComponentRefs = []string{"component.only@1.0.0"}
	if report := result.Validate(); report.Valid {
		t.Fatal("topology result accepted fewer than two components")
	}
}

func TestIntegrationTestResultOutcomeMustMatchChecks(t *testing.T) {
	result := validIntegrationTestResult(t)
	result.Spec.Checks[0].Status = "failed"
	result.Spec.Checks[0].DiagnosticCode = "YARA-INT-101"
	if report := result.Validate(); report.Valid {
		t.Fatal("passing outcome accepted a failed check")
	}
}

func validIntegrationTestResult(t *testing.T) IntegrationTestResult {
	t.Helper()
	result := IntegrationTestResult{
		APIVersion: APIVersion,
		Kind:       "IntegrationTestResult",
		Metadata:   IntegrationTestResultMetadata{Name: "litellm-smoke"},
		Spec: IntegrationTestResultSpec{
			Mode:          "component-smoke",
			Outcome:       "passed",
			CatalogDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ComponentRefs: []string{"component.litellm@1.0.0"},
			Environment: ContractTestEnvironment{
				Transport:       "local",
				ReferenceDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				OperatingSystem: "linux",
				Architecture:    "amd64",
				Docker: ContractTestDocker{
					Available: true, Version: "27.0.0", OperatingSystem: "linux", Architecture: "amd64",
				},
				Accelerators: []ContractTestAccelerator{},
			},
			Checks: []ContractTestCheck{{
				ID: "api-health", Status: "passed",
				EvidenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			}},
			Limitations: []string{"No latency or throughput claim is made."},
		},
	}
	assigned, err := result.AssignResultID()
	if err != nil {
		t.Fatalf("assign identity: %v", err)
	}
	return assigned
}
