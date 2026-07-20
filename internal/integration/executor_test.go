package integration

import (
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestCatalogExecutorComponentSmokeProducesSortedChecks(t *testing.T) {
	snapshot, err := catalog.Load("../../catalog/v0.2/snapshot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	checks, limitations, err := CatalogExecutor{}.ComponentSmoke(t.Context(), snapshot, []string{"core.litellm@1.93.0"}, testEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) < 3 || len(limitations) == 0 {
		t.Fatalf("unexpected bounded integration result: checks=%d limitations=%d", len(checks), len(limitations))
	}
	for index := 1; index < len(checks); index++ {
		if checks[index-1].ID > checks[index].ID {
			t.Fatalf("checks not sorted: %s > %s", checks[index-1].ID, checks[index].ID)
		}
	}
}

func TestCatalogExecutorTopologyFailsMissingRoleCoverage(t *testing.T) {
	snapshot, err := catalog.Load("../../catalog/v0.2/snapshot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	checks, _, err := CatalogExecutor{}.TopologyEndToEnd(t.Context(), snapshot, "core.local-chat-coding-vllm@1.0.0", []string{"core.litellm@1.93.0", "core.open-webui@0.10.2"}, testEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	missingRoleFailed := false
	for _, check := range checks {
		if check.ID == "topology.role-coverage" && check.Status == "failed" && check.DiagnosticCode == "YARA-INT-103" {
			missingRoleFailed = true
			break
		}
	}
	if !missingRoleFailed {
		t.Fatalf("expected role-coverage failure from incomplete component set: %#v", checks)
	}
}

func testEnvironment() resources.ContractTestEnvironment {
	return resources.ContractTestEnvironment{
		Transport:       "local",
		ReferenceDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		OperatingSystem: "linux",
		Architecture:    "amd64",
		Docker: resources.ContractTestDocker{
			Available: true, Version: "27.0.0", OperatingSystem: "linux", Architecture: "amd64",
		},
	}
}
