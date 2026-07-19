package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

func TestValidateIntegrationResultWritesValidationAudit(t *testing.T) {
	result := resources.IntegrationTestResult{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationTestResult",
		Metadata:   resources.IntegrationTestResultMetadata{Name: "component-smoke"},
		Spec: resources.IntegrationTestResultSpec{
			Mode:          "component-smoke",
			Outcome:       "passed",
			CatalogDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ComponentRefs: []string{"component.litellm@1.0.0"},
			Environment: resources.ContractTestEnvironment{
				Transport:       "local",
				ReferenceDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				OperatingSystem: "linux",
				Architecture:    "amd64",
				Docker: resources.ContractTestDocker{
					Available: true, Version: "27.0.0", OperatingSystem: "linux", Architecture: "amd64",
				},
				Accelerators: []resources.ContractTestAccelerator{},
			},
			Checks: []resources.ContractTestCheck{{
				ID: "health", Status: "passed",
				EvidenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			}},
			Limitations: []string{"No performance claim is made."},
		},
	}
	assigned, err := result.AssignResultID()
	if err != nil {
		t.Fatalf("assign result identity: %v", err)
	}
	data, err := yaml.Marshal(assigned)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	directory := t.TempDir()
	resultPath := filepath.Join(directory, "result.yaml")
	auditPath := filepath.Join(directory, "result.audit.jsonl")
	if err := os.WriteFile(resultPath, data, 0o600); err != nil {
		t.Fatalf("write result: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"integration", "validate", resultPath, "--audit-output", auditPath}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("validate integration result: exit=%d stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "integration.validate.completed" || terminal.Spec.Subjects[0].Kind != "IntegrationTestResult" || terminal.Spec.Subjects[0].Digest != assigned.Metadata.ResultID {
		t.Fatalf("validation audit does not bind result identity: %#v", terminal.Spec)
	}
}
