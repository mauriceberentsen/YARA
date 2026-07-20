package catalogcoverage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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
	if report.Spec.Summary.LifecyclePublicationReadyAssertions != 0 || report.Spec.Summary.LifecyclePublicationBlockedAssertions != report.Spec.Summary.AssertionCount {
		t.Fatalf("lifecycle publication readiness summary is inconsistent: %#v", report.Spec.Summary)
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

func TestBuildBindsLifecycleProofApprovalGate(t *testing.T) {
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
	sourceResult := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.yaml")
	sourceAudit := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.audit.jsonl")
	resultData, err := os.ReadFile(sourceResult)
	if err != nil {
		t.Fatalf("read source evidence: %v", err)
	}
	auditData, err := os.ReadFile(sourceAudit)
	if err != nil {
		t.Fatalf("read source audit: %v", err)
	}
	resultPath := filepath.Join(directory, "lifecycle-contract.yaml")
	if err := os.WriteFile(resultPath, resultData, 0o600); err != nil {
		t.Fatalf("write lifecycle evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "lifecycle-contract.audit.jsonl"), auditData, 0o600); err != nil {
		t.Fatalf("write lifecycle audit: %v", err)
	}
	lifecycleResult, err := resources.LoadContractTestResult(sourceResult)
	if err != nil {
		t.Fatalf("load source lifecycle result: %v", err)
	}
	ledger := resources.LifecycleProofLedger{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofLedger",
		Metadata:   resources.LifecycleProofLedgerMeta{Name: "lifecycle-proof"},
		Spec: resources.LifecycleProofLedgerSpec{
			RecordedAt:            time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano),
			PlanID:                "sha256:" + strings.Repeat("a", 64),
			BundleID:              "sha256:" + strings.Repeat("b", 64),
			TargetReferenceDigest: "sha256:" + strings.Repeat("c", 64),
			Reviewer:              resources.ReviewerRecord{Identity: "local:reviewer", Role: "platform-security", Assurance: "self-asserted-local"},
			Decision:              resources.PromotionDecisionApproved,
			ReasonReference:       "ticket-lifecycle-proof-123",
			Stages: []resources.LifecycleProofLedgerStage{
				{Stage: resources.LifecycleStageApply, ReceiptID: "sha256:" + strings.Repeat("d", 64), ExecutionCorrelationID: "apply", Outcome: "succeeded", CompletedAt: time.Now().UTC().Add(-100 * time.Minute).Format(time.RFC3339Nano)},
				{Stage: resources.LifecycleStageRetire, ReceiptID: "sha256:" + strings.Repeat("e", 64), ExecutionCorrelationID: "retire", Outcome: "succeeded", CompletedAt: time.Now().UTC().Add(-90 * time.Minute).Format(time.RFC3339Nano)},
				{Stage: resources.LifecycleStageRollback, ReceiptID: "sha256:" + strings.Repeat("f", 64), ExecutionCorrelationID: "rollback", Outcome: "succeeded", CompletedAt: time.Now().UTC().Add(-80 * time.Minute).Format(time.RFC3339Nano)},
			},
			Limitations: []string{
				"Lifecycle proof ledger does not execute mutations.",
				"Lifecycle proof ledger links immutable receipt identities only.",
			},
		},
	}
	ledger, err = ledger.AssignLedgerID()
	if err != nil {
		t.Fatalf("assign ledger id: %v", err)
	}
	approval := resources.LifecycleProofApproval{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofApproval",
		Metadata:   resources.LifecycleProofApprovalMeta{Name: "lifecycle-proof-approval"},
		Spec: resources.LifecycleProofApprovalSpec{
			ReviewedAt:       time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
			ExpiresAt:        time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     lifecycleResult.Spec.AssertionRef,
			LedgerID:         ledger.Metadata.LedgerID,
			SelectedEvidence: []string{lifecycleResult.Metadata.ResultID},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-lifecycle-approval-123",
			MaxLedgerAge:     "720h",
			Limitations: []string{
				"Lifecycle-proof approval binds one immutable lifecycle proof ledger identity.",
				"Lifecycle-proof approval records review metadata only and does not mutate catalog state.",
			},
		},
	}
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatalf("assign lifecycle approval id: %v", err)
	}
	writeYAML(t, filepath.Join(directory, "lifecycle-proof-approval.yaml"), approval)
	writeLifecycleProofApprovalAudit(t, filepath.Join(directory, "lifecycle-proof-approval.audit.jsonl"), catalogDigest, ledger.Metadata.LedgerID, approval.Metadata.ApprovalID)
	report, err := Build("coverage", snapshot, directory)
	if err != nil {
		t.Fatalf("build coverage with lifecycle proof approval: %v", err)
	}
	assertion := findAssertion(t, report, lifecycleResult.Spec.AssertionRef)
	gate := findGate(t, assertion, "lifecycle-proof-publication-approval")
	if gate.Status != "passed" || gate.SelectedResult != approval.Metadata.ApprovalID {
		t.Fatalf("lifecycle proof approval gate was not bound: %#v", gate)
	}
}

func TestBuildRejectsStaleLifecycleProofApproval(t *testing.T) {
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
	sourceResult := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.yaml")
	sourceAudit := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.audit.jsonl")
	resultData, err := os.ReadFile(sourceResult)
	if err != nil {
		t.Fatalf("read source evidence: %v", err)
	}
	auditData, err := os.ReadFile(sourceAudit)
	if err != nil {
		t.Fatalf("read source audit: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "lifecycle-contract.yaml"), resultData, 0o600); err != nil {
		t.Fatalf("write lifecycle evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "lifecycle-contract.audit.jsonl"), auditData, 0o600); err != nil {
		t.Fatalf("write lifecycle audit: %v", err)
	}
	lifecycleResult, err := resources.LoadContractTestResult(sourceResult)
	if err != nil {
		t.Fatalf("load source lifecycle result: %v", err)
	}
	approval := resources.LifecycleProofApproval{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofApproval",
		Metadata:   resources.LifecycleProofApprovalMeta{Name: "lifecycle-proof-approval-stale"},
		Spec: resources.LifecycleProofApprovalSpec{
			ReviewedAt:       time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano),
			ExpiresAt:        time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     lifecycleResult.Spec.AssertionRef,
			LedgerID:         "sha256:" + strings.Repeat("a", 64),
			SelectedEvidence: []string{lifecycleResult.Metadata.ResultID},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-lifecycle-approval-stale",
			MaxLedgerAge:     "720h",
			Limitations: []string{
				"Lifecycle-proof approval binds one immutable lifecycle proof ledger identity.",
				"Lifecycle-proof approval records review metadata only and does not mutate catalog state.",
			},
		},
	}
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatalf("assign lifecycle approval id: %v", err)
	}
	writeYAML(t, filepath.Join(directory, "lifecycle-proof-approval.yaml"), approval)
	writeLifecycleProofApprovalAudit(t, filepath.Join(directory, "lifecycle-proof-approval.audit.jsonl"), catalogDigest, approval.Spec.LedgerID, approval.Metadata.ApprovalID)
	report, err := Build("coverage", snapshot, directory)
	if err != nil {
		t.Fatalf("build coverage with stale lifecycle proof approval: %v", err)
	}
	assertion := findAssertion(t, report, lifecycleResult.Spec.AssertionRef)
	gate := findGate(t, assertion, "lifecycle-proof-publication-approval")
	if gate.Status != "failed" || gate.Blocker != "selected-approval-expired-for-lifecycle-evidence|remediation:renew-lifecycle-proof-approval" {
		t.Fatalf("stale lifecycle proof approval was not rejected: %#v", gate)
	}
}

func TestBuildRejectsLifecycleProofApprovalWithMalformedAuditAction(t *testing.T) {
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
	sourceResult := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.yaml")
	sourceAudit := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.audit.jsonl")
	resultData, err := os.ReadFile(sourceResult)
	if err != nil {
		t.Fatalf("read source evidence: %v", err)
	}
	auditData, err := os.ReadFile(sourceAudit)
	if err != nil {
		t.Fatalf("read source audit: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "lifecycle-contract.yaml"), resultData, 0o600); err != nil {
		t.Fatalf("write lifecycle evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "lifecycle-contract.audit.jsonl"), auditData, 0o600); err != nil {
		t.Fatalf("write lifecycle audit: %v", err)
	}
	lifecycleResult, err := resources.LoadContractTestResult(sourceResult)
	if err != nil {
		t.Fatalf("load source lifecycle result: %v", err)
	}
	approval := resources.LifecycleProofApproval{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofApproval",
		Metadata:   resources.LifecycleProofApprovalMeta{Name: "lifecycle-proof-approval-malformed"},
		Spec: resources.LifecycleProofApprovalSpec{
			ReviewedAt:       time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
			ExpiresAt:        time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     lifecycleResult.Spec.AssertionRef,
			LedgerID:         "sha256:" + strings.Repeat("c", 64),
			SelectedEvidence: []string{lifecycleResult.Metadata.ResultID},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-lifecycle-approval-malformed",
			MaxLedgerAge:     "720h",
			Limitations: []string{
				"Lifecycle-proof approval binds one immutable lifecycle proof ledger identity.",
				"Lifecycle-proof approval records review metadata only and does not mutate catalog state.",
			},
		},
	}
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatalf("assign lifecycle approval id: %v", err)
	}
	writeYAML(t, filepath.Join(directory, "lifecycle-proof-approval.yaml"), approval)
	writeLifecycleProofApprovalAuditCustom(t, filepath.Join(directory, "lifecycle-proof-approval.audit.jsonl"), catalogDigest, approval.Spec.LedgerID, approval.Metadata.ApprovalID, "lifecycle.proof.approve-publication.validate", true)
	if _, err := Build("coverage", snapshot, directory); err == nil {
		t.Fatal("malformed lifecycle proof approval audit action was accepted")
	}
}

func TestBuildRejectsLifecycleProofApprovalWithLedgerSubjectDrift(t *testing.T) {
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
	sourceResult := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.yaml")
	sourceAudit := filepath.Join(root, "catalog", "v0.2", "evidence", "gb10", "qwen-coder-lifecycle-passed.audit.jsonl")
	resultData, err := os.ReadFile(sourceResult)
	if err != nil {
		t.Fatalf("read source evidence: %v", err)
	}
	auditData, err := os.ReadFile(sourceAudit)
	if err != nil {
		t.Fatalf("read source audit: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "lifecycle-contract.yaml"), resultData, 0o600); err != nil {
		t.Fatalf("write lifecycle evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "lifecycle-contract.audit.jsonl"), auditData, 0o600); err != nil {
		t.Fatalf("write lifecycle audit: %v", err)
	}
	lifecycleResult, err := resources.LoadContractTestResult(sourceResult)
	if err != nil {
		t.Fatalf("load source lifecycle result: %v", err)
	}
	approval := resources.LifecycleProofApproval{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofApproval",
		Metadata:   resources.LifecycleProofApprovalMeta{Name: "lifecycle-proof-approval-subject-drift"},
		Spec: resources.LifecycleProofApprovalSpec{
			ReviewedAt:       time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
			ExpiresAt:        time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     lifecycleResult.Spec.AssertionRef,
			LedgerID:         "sha256:" + strings.Repeat("d", 64),
			SelectedEvidence: []string{lifecycleResult.Metadata.ResultID},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-lifecycle-approval-drift",
			MaxLedgerAge:     "720h",
			Limitations: []string{
				"Lifecycle-proof approval binds one immutable lifecycle proof ledger identity.",
				"Lifecycle-proof approval records review metadata only and does not mutate catalog state.",
			},
		},
	}
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatalf("assign lifecycle approval id: %v", err)
	}
	writeYAML(t, filepath.Join(directory, "lifecycle-proof-approval.yaml"), approval)
	writeLifecycleProofApprovalAuditCustom(t, filepath.Join(directory, "lifecycle-proof-approval.audit.jsonl"), catalogDigest, approval.Spec.LedgerID, approval.Metadata.ApprovalID, "lifecycle.proof.approve-publication.completed", false)
	if _, err := Build("coverage", snapshot, directory); err == nil {
		t.Fatal("lifecycle proof approval audit with ledger-subject drift was accepted")
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

func writeLifecycleProofApprovalAudit(t *testing.T, path, catalogDigest, ledgerID, approvalID string) {
	writeLifecycleProofApprovalAuditCustom(t, path, catalogDigest, ledgerID, approvalID, "lifecycle.proof.approve-publication.completed", true)
}

func writeLifecycleProofApprovalAuditCustom(t *testing.T, path, catalogDigest, ledgerID, approvalID, terminalAction string, includeLedgerSubject bool) {
	t.Helper()
	chain := audit.NewChain()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "lifecycle-proof-approval-started", OccurredAt: now},
		Spec: audit.Spec{
			CorrelationID: "lifecycle-proof-approval",
			Actor:         audit.Actor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"},
			Action:        "lifecycle.proof.approve-publication.started",
			Subjects: []audit.Subject{
				{Kind: "CatalogSnapshot", Digest: catalogDigest},
				{Kind: "LifecycleProofLedger", Digest: ledgerID},
			},
			Reason:  audit.Reason{Type: "user-request", Reference: "test"},
			Target:  "catalog:" + catalogDigest,
			Outcome: "started",
		},
	})
	if err != nil {
		t.Fatalf("append started lifecycle-proof approval audit: %v", err)
	}
	subjects := []audit.Subject{{Kind: "CatalogSnapshot", Digest: catalogDigest}}
	if includeLedgerSubject {
		subjects = append(subjects, audit.Subject{Kind: "LifecycleProofLedger", Digest: ledgerID})
	}
	subjects = append(subjects, audit.Subject{Kind: "LifecycleProofApproval", Digest: approvalID})
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "lifecycle-proof-approval-terminal", OccurredAt: now},
		Spec: audit.Spec{
			CorrelationID: "lifecycle-proof-approval",
			CausationID:   started.Metadata.ID,
			Actor:         audit.Actor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"},
			Action:        terminalAction,
			Subjects:      subjects,
			Reason:        audit.Reason{Type: "user-request", Reference: "test"},
			Target:        "catalog:" + catalogDigest,
			Outcome:       "success",
		},
	})
	if err != nil {
		t.Fatalf("append terminal lifecycle-proof approval audit: %v", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		t.Fatalf("encode lifecycle-proof approval audit: %v", err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write lifecycle-proof approval audit: %v", err)
	}
}
