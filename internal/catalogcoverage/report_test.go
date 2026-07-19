package catalogcoverage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
)

func TestBuildReportsExactV02EvidenceGaps(t *testing.T) {
	root := filepath.Join("..", "..")
	snapshot, err := catalog.Load(filepath.Join(root, "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	report, err := Build("catalog-v0-2-coverage", snapshot, filepath.Join(root, "catalog", "v0.2", "evidence"))
	if err != nil {
		t.Fatalf("build coverage: %v", err)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("validate coverage: %v", err)
	}
	if report.Spec.Complete || report.Spec.Summary.ManifestCount != 38 || report.Spec.Summary.AssertionCount != 8 || report.Spec.Summary.AcceptedEvidenceCount != 14 || report.Spec.Summary.VerifiedAuditChainCount != 14 {
		t.Fatalf("unexpected summary: %#v", report.Spec.Summary)
	}
	if report.Spec.Summary.PromotionEligibleAssertions != 0 {
		t.Fatalf("catalog must not be promotion eligible: %#v", report.Spec.Summary)
	}
	if len(report.Spec.Capabilities) != 13 || report.Spec.Capabilities[0].Coverage != "complete" || len(report.Spec.Topologies) != 1 || report.Spec.Topologies[0].Coverage != "none" {
		t.Fatalf("catalog categories are not fully enumerated: capabilities=%#v topologies=%#v", report.Spec.Capabilities, report.Spec.Topologies)
	}
	coder := findAssertion(t, report, "compat.vllm-qwen-coder-7b-awq-gb10")
	for _, mode := range requiredContractModes {
		gate := findGate(t, coder, mode)
		if gate.Status != "passed" {
			t.Fatalf("expected passed %s gate: %#v", mode, gate)
		}
	}
	if findGate(t, coder, "independent-promotion-review").Status != "missing" {
		t.Fatalf("completion blockers disappeared: %#v", coder.Gates)
	}
	ada := findAssertion(t, report, "compat.vllm-qwen-coder-7b-awq-rtx4090")
	if findGate(t, ada, "runtime-smoke").Status != "missing" || !contains(ada.Blockers, "external-target:no-observed-target-evidence") {
		t.Fatalf("unobserved Ada target was not explicit: %#v", ada)
	}
	qwen3 := findAssertion(t, report, "compat.vllm-qwen3-8b-awq-gb10")
	if findGate(t, qwen3, "capacity-boundary").Status != "passed" || findGate(t, qwen3, "model-inference").Status != "passed" || findGate(t, qwen3, "policy-contract").Status != "passed" || findGate(t, qwen3, "lifecycle-contract").Status != "passed" {
		t.Fatalf("Qwen3 mixed evidence was flattened: %#v", qwen3.Gates)
	}
	capacity := findGate(t, qwen3, "capacity-boundary")
	if len(capacity.ObservedEvidence) != 2 || capacity.ObservedEvidence[0].Outcome != "failed" || capacity.ObservedEvidence[1].Outcome != "passed" {
		t.Fatalf("Qwen3 capacity remediation history disappeared: %#v", capacity)
	}
}

func TestBuildRejectsEvidenceWithoutAdjacentAudit(t *testing.T) {
	snapshot, err := catalog.Load(filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	directory := t.TempDir()
	source := filepath.Join("..", "..", "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.yaml")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read evidence fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unbound.yaml"), data, 0o600); err != nil {
		t.Fatalf("write evidence fixture: %v", err)
	}
	if _, err := Build("coverage", snapshot, directory); err == nil {
		t.Fatal("evidence without adjacent audit was accepted")
	}
}

func findAssertion(t *testing.T, report Report, id string) AssertionCoverage {
	t.Helper()
	for _, item := range report.Spec.Assertions {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("missing assertion %s", id)
	return AssertionCoverage{}
}

func findGate(t *testing.T, assertion AssertionCoverage, id string) GateCoverage {
	t.Helper()
	for _, item := range assertion.Gates {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("missing gate %s", id)
	return GateCoverage{}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
