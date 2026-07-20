package catalogcoverage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
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
	if !contains(report.Spec.Topologies[0].Blockers, "no-topology-integration-evidence") {
		t.Fatalf("topology integration blocker disappeared: %#v", report.Spec.Topologies[0])
	}
	for _, component := range report.Spec.Components {
		if !contains(component.Blockers, "no-component-smoke-evidence") || !contains(component.Blockers, "no-topology-integration-evidence") {
			t.Fatalf("component integration blockers are incomplete: %#v", component)
		}
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

func TestIntegrationValidationAuditIsNotExecutionEvidence(t *testing.T) {
	result := resources.IntegrationTestResult{
		Metadata: resources.IntegrationTestResultMetadata{ResultID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Spec: resources.IntegrationTestResultSpec{
			Mode:          "component-smoke",
			Outcome:       "passed",
			CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Environment: resources.ContractTestEnvironment{
				Transport:       "local",
				ReferenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			},
		},
	}
	events := []audit.Event{{}, {Spec: audit.Spec{
		Action:  "integration.validate.completed",
		Outcome: "success",
		Target:  "local:" + result.Spec.Environment.ReferenceDigest,
		Subjects: []audit.Subject{
			{Kind: "CatalogSnapshot", Digest: result.Spec.CatalogDigest},
			{Kind: "IntegrationTestResult", Digest: result.Metadata.ResultID},
		},
	}}}
	if err := verifyIntegrationEvidenceAudit(events, result, result.Spec.CatalogDigest); err == nil {
		t.Fatal("validation-only audit was accepted as integration execution evidence")
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

func TestBuildBindsPromotionReviewGateFromAcceptedReview(t *testing.T) {
	root := filepath.Join("..", "..")
	snapshot, err := catalog.Load(filepath.Join(root, "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		t.Fatalf("catalog digest: %v", err)
	}
	directory := t.TempDir()
	sourceResult := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-7b-awq-runtime-smoke.yaml")
	sourceAudit := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-7b-awq-runtime-smoke.audit.jsonl")
	resultData, err := os.ReadFile(sourceResult)
	if err != nil {
		t.Fatalf("read source evidence: %v", err)
	}
	auditData, err := os.ReadFile(sourceAudit)
	if err != nil {
		t.Fatalf("read source audit: %v", err)
	}
	resultPath := filepath.Join(directory, "runtime-smoke.yaml")
	if err := os.WriteFile(resultPath, resultData, 0o600); err != nil {
		t.Fatalf("write runtime evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "runtime-smoke.audit.jsonl"), auditData, 0o600); err != nil {
		t.Fatalf("write runtime audit: %v", err)
	}
	contractResult, err := resources.LoadContractTestResult(sourceResult)
	if err != nil {
		t.Fatalf("load source contract result: %v", err)
	}
	review := resources.PromotionReview{
		APIVersion: resources.APIVersion,
		Kind:       "PromotionReview",
		Metadata: resources.PromotionReviewMetadata{
			Name: "gb10-qwen-coder-review",
		},
		Spec: resources.PromotionReviewSpec{
			CatalogDigest:    catalogDigest,
			AssertionRef:     contractResult.Spec.AssertionRef,
			SelectedEvidence: []string{contractResult.Metadata.ResultID},
			Reviewer: resources.ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "release-manager",
				Assurance: "self-asserted-local",
			},
			ReviewedAt:      time.Now().UTC().Format(time.RFC3339Nano),
			Decision:        resources.PromotionDecisionApproved,
			ReasonReference: "ticket-9021",
			Limitations: []string{
				"Promotion review remains bounded to immutable evidence identities.",
			},
		},
	}
	review, err = review.AssignReviewID()
	if err != nil {
		t.Fatalf("assign promotion review id: %v", err)
	}
	writeYAML(t, filepath.Join(directory, "promotion-review.yaml"), review)
	writePromotionReviewAudit(t, filepath.Join(directory, "promotion-review.audit.jsonl"), catalogDigest, review.Metadata.ReviewID)
	report, err := Build("coverage", snapshot, directory)
	if err != nil {
		t.Fatalf("build coverage with promotion review: %v", err)
	}
	assertion := findAssertion(t, report, contractResult.Spec.AssertionRef)
	gate := findGate(t, assertion, "independent-promotion-review")
	if gate.Status != "passed" || gate.SelectedResult != review.Metadata.ReviewID {
		t.Fatalf("promotion review gate was not bound: %#v", gate)
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

func writeYAML(t *testing.T, path string, value any) {
	t.Helper()
	data, err := yaml.Marshal(value)
	if err != nil {
		t.Fatalf("marshal YAML: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write YAML: %v", err)
	}
}

func writePromotionReviewAudit(t *testing.T, path, catalogDigest, reviewID string) {
	t.Helper()
	chain := audit.NewChain()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "promotion-started", OccurredAt: now},
		Spec: audit.Spec{
			CorrelationID: "promotion-review",
			Actor:         audit.Actor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"},
			Action:        "promotion.review.started",
			Subjects:      []audit.Subject{{Kind: "CatalogSnapshot", Digest: catalogDigest}},
			Reason:        audit.Reason{Type: "user-request", Reference: "test"},
			Target:        "catalog:" + catalogDigest,
			Outcome:       "started",
		},
	})
	if err != nil {
		t.Fatalf("append started promotion audit: %v", err)
	}
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "promotion-terminal", OccurredAt: now},
		Spec: audit.Spec{
			CorrelationID: "promotion-review",
			CausationID:   started.Metadata.ID,
			Actor:         audit.Actor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"},
			Action:        "promotion.review.completed",
			Subjects: []audit.Subject{
				{Kind: "CatalogSnapshot", Digest: catalogDigest},
				{Kind: "PromotionReview", Digest: reviewID},
			},
			Reason:  audit.Reason{Type: "user-request", Reference: "test"},
			Target:  "catalog:" + catalogDigest,
			Outcome: "success",
		},
	})
	if err != nil {
		t.Fatalf("append terminal promotion audit: %v", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		t.Fatalf("encode promotion audit: %v", err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write promotion audit: %v", err)
	}
}
