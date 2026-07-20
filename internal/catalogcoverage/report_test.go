package catalogcoverage

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
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

func TestBuildDeduplicatesEquivalentIntegrationEvidenceByResultIdentity(t *testing.T) {
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
	result := deterministicIntegrationResultFixture(t, catalogDigest)
	writeYAML(t, filepath.Join(directory, "integration-one.yaml"), result)
	writeYAML(t, filepath.Join(directory, "integration-two.yaml"), result)
	writeIntegrationExecutionAudit(t, filepath.Join(directory, "integration-one.audit.jsonl"), catalogDigest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, "2026-07-20T12:15:00Z")
	writeIntegrationExecutionAudit(t, filepath.Join(directory, "integration-two.audit.jsonl"), catalogDigest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, "2026-07-20T12:15:00Z")
	report, err := Build("coverage", snapshot, directory)
	if err != nil {
		t.Fatalf("build coverage with duplicate integration evidence: %v", err)
	}
	if report.Spec.Summary.AcceptedEvidenceCount != 1 || report.Spec.Summary.VerifiedAuditChainCount != 1 {
		t.Fatalf("duplicate integration evidence inflated coverage summary counts: %#v", report.Spec.Summary)
	}
}

func TestBuildRejectsIntegrationEvidenceIdentityReuseWithAuditBindingDrift(t *testing.T) {
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
	result := deterministicIntegrationResultFixture(t, catalogDigest)
	writeYAML(t, filepath.Join(directory, "integration-one.yaml"), result)
	writeYAML(t, filepath.Join(directory, "integration-two.yaml"), result)
	writeIntegrationExecutionAudit(t, filepath.Join(directory, "integration-one.audit.jsonl"), catalogDigest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, "2026-07-20T12:20:00Z")
	writeIntegrationExecutionAudit(t, filepath.Join(directory, "integration-two.audit.jsonl"), catalogDigest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, "2026-07-20T12:21:00Z")
	if _, err := Build("coverage", snapshot, directory); err == nil {
		t.Fatal("integration evidence identity reuse with audit-binding drift was accepted")
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

func TestBuildBindsIntegrationPublicationAttestationGate(t *testing.T) {
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
	result := deterministicIntegrationResultForAssertion(t, catalogDigest, "core.vllm@0.25.1")
	writeYAML(t, filepath.Join(directory, "integration.yaml"), result)
	writeIntegrationExecutionAudit(t, filepath.Join(directory, "integration.audit.jsonl"), catalogDigest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, "2026-07-20T12:15:00Z")
	attestation := resources.IntegrationPublicationAttestation{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationPublicationAttestation",
		Metadata: resources.IntegrationPublicationAttestationMeta{
			Name: "integration-publication-attestation",
		},
		Spec: resources.IntegrationPublicationAttestationSpec{
			ReviewedAt:       time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
			ExpiresAt:        time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     "compat.vllm-qwen-coder-7b-awq-gb10",
			SelectedEvidence: []string{result.Metadata.ResultID},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-integration-publication-123",
			MaxEvidenceAge:   "720h",
			Limitations: []string{
				"Integration publication attestation binds one assertion to immutable integration evidence identities only.",
				"Integration publication attestation records reviewer intent without mutating catalog manifests.",
			},
		},
	}
	attestation, err = attestation.AssignAttestationID()
	if err != nil {
		t.Fatalf("assign integration publication attestation id: %v", err)
	}
	writeYAML(t, filepath.Join(directory, "integration-publication-attestation.yaml"), attestation)
	writeIntegrationPublicationAttestationAudit(t, filepath.Join(directory, "integration-publication-attestation.audit.jsonl"), catalogDigest, attestation.Metadata.AttestationID, attestation.Spec.SelectedEvidence)
	report, err := Build("coverage", snapshot, directory)
	if err != nil {
		t.Fatalf("build coverage with integration publication attestation: %v", err)
	}
	assertion := findAssertion(t, report, "compat.vllm-qwen-coder-7b-awq-gb10")
	gate := findGate(t, assertion, "integration-publication-attestation")
	if gate.Status != "passed" || gate.SelectedResult != attestation.Metadata.AttestationID {
		t.Fatalf("integration publication attestation gate was not bound: %#v", gate)
	}
}

func TestBuildLifecyclePublicationReadinessRequiresRenewalReviewForIntegrationPublicationAssertions(t *testing.T) {
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
		t.Fatalf("read source lifecycle evidence: %v", err)
	}
	auditData, err := os.ReadFile(sourceAudit)
	if err != nil {
		t.Fatalf("read source lifecycle audit: %v", err)
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
	ledger := resources.LifecycleProofLedger{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofLedger",
		Metadata:   resources.LifecycleProofLedgerMeta{Name: "lifecycle-proof-for-renewal-gate"},
		Spec: resources.LifecycleProofLedgerSpec{
			RecordedAt:            time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano),
			PlanID:                "sha256:" + strings.Repeat("a", 64),
			BundleID:              "sha256:" + strings.Repeat("b", 64),
			TargetReferenceDigest: "sha256:" + strings.Repeat("c", 64),
			Reviewer:              resources.ReviewerRecord{Identity: "local:reviewer", Role: "platform-security", Assurance: "self-asserted-local"},
			Decision:              resources.PromotionDecisionApproved,
			ReasonReference:       "ticket-lifecycle-proof-renewal-gate-123",
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
		t.Fatalf("assign lifecycle ledger id: %v", err)
	}
	approval := resources.LifecycleProofApproval{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofApproval",
		Metadata:   resources.LifecycleProofApprovalMeta{Name: "lifecycle-proof-approval-for-renewal-gate"},
		Spec: resources.LifecycleProofApprovalSpec{
			ReviewedAt:       time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
			ExpiresAt:        time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     lifecycleResult.Spec.AssertionRef,
			LedgerID:         ledger.Metadata.LedgerID,
			SelectedEvidence: []string{lifecycleResult.Metadata.ResultID},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-lifecycle-approval-renewal-gate-123",
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
	integrationResult := deterministicIntegrationResultForAssertion(t, catalogDigest, "core.vllm@0.25.1")
	writeYAML(t, filepath.Join(directory, "integration.yaml"), integrationResult)
	writeIntegrationExecutionAudit(t, filepath.Join(directory, "integration.audit.jsonl"), catalogDigest, integrationResult.Metadata.ResultID, integrationResult.Spec.Environment.ReferenceDigest, "2026-07-20T12:15:00Z")
	attestation := resources.IntegrationPublicationAttestation{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationPublicationAttestation",
		Metadata: resources.IntegrationPublicationAttestationMeta{
			Name: "integration-publication-attestation-for-renewal-gate",
		},
		Spec: resources.IntegrationPublicationAttestationSpec{
			ReviewedAt:       time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
			ExpiresAt:        time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     lifecycleResult.Spec.AssertionRef,
			SelectedEvidence: []string{integrationResult.Metadata.ResultID},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-integration-publication-renewal-gate-123",
			MaxEvidenceAge:   "720h",
			Limitations: []string{
				"Integration publication attestation binds one assertion to immutable integration evidence identities only.",
				"Integration publication attestation records reviewer intent without mutating catalog manifests.",
			},
		},
	}
	attestation, err = attestation.AssignAttestationID()
	if err != nil {
		t.Fatalf("assign integration publication attestation id: %v", err)
	}
	writeYAML(t, filepath.Join(directory, "integration-publication-attestation.yaml"), attestation)
	writeIntegrationPublicationAttestationAudit(t, filepath.Join(directory, "integration-publication-attestation.audit.jsonl"), catalogDigest, attestation.Metadata.AttestationID, attestation.Spec.SelectedEvidence)
	report, err := Build("coverage", snapshot, directory)
	if err != nil {
		t.Fatalf("build coverage with lifecycle and integration publication evidence: %v", err)
	}
	assertion := findAssertion(t, report, lifecycleResult.Spec.AssertionRef)
	lifecycleGate := findGate(t, assertion, "lifecycle-proof-publication-approval")
	if lifecycleGate.Status != "passed" {
		t.Fatalf("expected lifecycle publication gate to pass: %#v", lifecycleGate)
	}
	integrationGate := findGate(t, assertion, "integration-publication-attestation")
	if integrationGate.Status != "passed" {
		t.Fatalf("expected integration publication gate to pass: %#v", integrationGate)
	}
	renewalGate := findGate(t, assertion, "publication-chain-renewal-review")
	if renewalGate.Status != "missing" || renewalGate.Blocker != "publication-chain-renewal-review-not-recorded" {
		t.Fatalf("expected renewal-review gate to fail closed as missing: %#v", renewalGate)
	}
	if assertion.LifecyclePublicationReady {
		t.Fatalf("expected lifecycle publication readiness to be blocked without renewal review: %#v", assertion)
	}
	if assertion.LifecyclePublicationBlocker != "publication-chain-renewal-review-not-recorded|remediation:record-publication-chain-renewal-review" {
		t.Fatalf("unexpected lifecycle publication blocker without renewal review: %q", assertion.LifecyclePublicationBlocker)
	}
}

func TestBuildRejectsIntegrationPublicationAttestationWithMalformedAuditAction(t *testing.T) {
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
	result := deterministicIntegrationResultForAssertion(t, catalogDigest, "core.vllm@0.25.1")
	writeYAML(t, filepath.Join(directory, "integration.yaml"), result)
	writeIntegrationExecutionAudit(t, filepath.Join(directory, "integration.audit.jsonl"), catalogDigest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, "2026-07-20T12:15:00Z")
	attestation := resources.IntegrationPublicationAttestation{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationPublicationAttestation",
		Metadata: resources.IntegrationPublicationAttestationMeta{
			Name: "integration-publication-attestation-malformed",
		},
		Spec: resources.IntegrationPublicationAttestationSpec{
			ReviewedAt:       time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
			ExpiresAt:        time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     "compat.vllm-qwen-coder-7b-awq-gb10",
			SelectedEvidence: []string{result.Metadata.ResultID},
			Reviewer:         resources.ReviewerRecord{Identity: "local:reviewer", Role: "release-manager", Assurance: "self-asserted-local"},
			Decision:         resources.PromotionDecisionApproved,
			ReasonReference:  "ticket-integration-publication-malformed",
			MaxEvidenceAge:   "720h",
			Limitations: []string{
				"Integration publication attestation binds one assertion to immutable integration evidence identities only.",
				"Integration publication attestation records reviewer intent without mutating catalog manifests.",
			},
		},
	}
	attestation, err = attestation.AssignAttestationID()
	if err != nil {
		t.Fatalf("assign integration publication attestation id: %v", err)
	}
	writeYAML(t, filepath.Join(directory, "integration-publication-attestation.yaml"), attestation)
	writeIntegrationPublicationAttestationAuditCustom(t, filepath.Join(directory, "integration-publication-attestation.audit.jsonl"), catalogDigest, attestation.Metadata.AttestationID, attestation.Spec.SelectedEvidence, "integration.publish.attestation.validate")
	if _, err := Build("coverage", snapshot, directory); err == nil {
		t.Fatal("malformed integration publication attestation audit action was accepted")
	}
}

func TestCatalogCoverageValidationRejectsMalformedLifecyclePublicationBlockerEncoding(t *testing.T) {
	root := filepath.Join("..", "..")
	snapshot, err := catalog.Load(filepath.Join(root, "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	report, err := Build("coverage", snapshot, filepath.Join(root, "catalog", "v0.2", "evidence"))
	if err != nil {
		t.Fatalf("build coverage: %v", err)
	}
	report.Spec.Assertions[0].LifecyclePublicationReady = false
	report.Spec.Assertions[0].LifecyclePublicationBlocker = "malformed-blocker"
	report, err = report.AssignReportID()
	if err != nil {
		t.Fatalf("assign report id: %v", err)
	}
	if err := report.Validate(); err == nil {
		t.Fatal("malformed lifecycle publication blocker encoding was accepted")
	}
}

func TestCatalogCoverageValidationRejectsLifecyclePublicationSummaryDrift(t *testing.T) {
	root := filepath.Join("..", "..")
	snapshot, err := catalog.Load(filepath.Join(root, "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	report, err := Build("coverage", snapshot, filepath.Join(root, "catalog", "v0.2", "evidence"))
	if err != nil {
		t.Fatalf("build coverage: %v", err)
	}
	report.Spec.Summary.LifecyclePublicationBlockedAssertions++
	report, err = report.AssignReportID()
	if err != nil {
		t.Fatalf("assign report id: %v", err)
	}
	if err := report.Validate(); err == nil {
		t.Fatal("lifecycle publication summary drift was accepted")
	}
}

func TestLifecyclePublicationBlockerTaxonomyHasCanonicalMappings(t *testing.T) {
	taxonomy := LifecyclePublicationBlockerTaxonomy()
	if len(taxonomy) == 0 {
		t.Fatal("lifecycle publication blocker taxonomy is empty")
	}
	seenCodes := map[string]struct{}{}
	for _, definition := range taxonomy {
		if definition.Code == "" || definition.Remediation == "" {
			t.Fatalf("taxonomy entry must include code and remediation: %#v", definition)
		}
		if _, exists := seenCodes[definition.Code]; exists {
			t.Fatalf("taxonomy contains duplicate blocker code: %s", definition.Code)
		}
		seenCodes[definition.Code] = struct{}{}
		blocker := lifecyclePublicationBlocker(definition.Code)
		parsed, err := ParseLifecyclePublicationBlocker(blocker)
		if err != nil {
			t.Fatalf("taxonomy blocker %q did not round-trip: %v", blocker, err)
		}
		if parsed.Code != definition.Code || parsed.Remediation != definition.Remediation {
			t.Fatalf("taxonomy mapping drifted for %s: parsed=%#v expected=%#v", definition.Code, parsed, definition)
		}
	}
}

func TestParseLifecyclePublicationBlockerRejectsAmbiguousOrUnknownTaxonomy(t *testing.T) {
	if _, err := ParseLifecyclePublicationBlocker("selected-approval-expiry-invalid|remediation:first|remediation:second"); err == nil {
		t.Fatal("ambiguous lifecycle publication blocker encoding was accepted")
	}
	if _, err := ParseLifecyclePublicationBlocker("unknown-code|remediation:unknown-action"); err == nil {
		t.Fatal("unknown lifecycle publication blocker taxonomy code was accepted")
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

func deterministicIntegrationResultFixture(t *testing.T, catalogDigest string) resources.IntegrationTestResult {
	t.Helper()
	result := resources.IntegrationTestResult{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationTestResult",
		Metadata: resources.IntegrationTestResultMetadata{
			Name: "integration-identity-fixture",
		},
		Spec: resources.IntegrationTestResultSpec{
			Mode:          "component-smoke",
			Outcome:       "passed",
			CatalogDigest: catalogDigest,
			ComponentRefs: []string{"core.litellm@1.93.0"},
			Environment: resources.ContractTestEnvironment{
				Transport:       "local",
				ReferenceDigest: "sha256:" + strings.Repeat("a", 64),
				OperatingSystem: "linux",
				Architecture:    "amd64",
				Docker: resources.ContractTestDocker{
					Available: true, Version: "27.0.0", OperatingSystem: "linux", Architecture: "amd64",
				},
				Accelerators: []resources.ContractTestAccelerator{},
			},
			Checks: []resources.ContractTestCheck{
				{ID: "integration.fixture.check", Status: "passed", EvidenceDigest: "sha256:" + strings.Repeat("b", 64)},
			},
			Limitations: []string{"bounded integration fixture"},
		},
	}
	slices.Sort(result.Spec.ComponentRefs)
	slices.Sort(result.Spec.Limitations)
	result, err := result.AssignResultID()
	if err != nil {
		t.Fatalf("assign integration fixture result id: %v", err)
	}
	return result
}

func deterministicIntegrationResultForAssertion(t *testing.T, catalogDigest, componentRef string) resources.IntegrationTestResult {
	t.Helper()
	result := deterministicIntegrationResultFixture(t, catalogDigest)
	result.Spec.ComponentRefs = []string{componentRef}
	assigned, err := result.AssignResultID()
	if err != nil {
		t.Fatalf("assign integration fixture for assertion: %v", err)
	}
	return assigned
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

func writeIntegrationPublicationAttestationAudit(t *testing.T, path, catalogDigest, attestationID string, selectedEvidence []string) {
	writeIntegrationPublicationAttestationAuditCustom(t, path, catalogDigest, attestationID, selectedEvidence, "integration.publish.attestation.completed")
}

func writeIntegrationPublicationAttestationAuditCustom(t *testing.T, path, catalogDigest, attestationID string, selectedEvidence []string, terminalAction string) {
	t.Helper()
	chain := audit.NewChain()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "integration-publication-attestation-started", OccurredAt: now},
		Spec: audit.Spec{
			CorrelationID: "integration-publication-attestation",
			Actor:         audit.Actor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"},
			Action:        "integration.publish.attestation.started",
			Subjects:      []audit.Subject{{Kind: "CatalogSnapshot", Digest: catalogDigest}},
			Reason:        audit.Reason{Type: "user-request", Reference: "test"},
			Target:        "catalog:" + catalogDigest,
			Outcome:       "started",
		},
	})
	if err != nil {
		t.Fatalf("append started integration publication attestation audit: %v", err)
	}
	subjects := []audit.Subject{
		{Kind: "CatalogSnapshot", Digest: catalogDigest},
		{Kind: "IntegrationPublicationAttestation", Digest: attestationID},
	}
	for _, selected := range selectedEvidence {
		subjects = append(subjects, audit.Subject{Kind: "IntegrationTestResult", Digest: selected})
	}
	slices.SortFunc(subjects, func(left, right audit.Subject) int {
		if cmp := strings.Compare(left.Kind, right.Kind); cmp != 0 {
			return cmp
		}
		return strings.Compare(left.Digest, right.Digest)
	})
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "integration-publication-attestation-terminal", OccurredAt: now},
		Spec: audit.Spec{
			CorrelationID: "integration-publication-attestation",
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
		t.Fatalf("append terminal integration publication attestation audit: %v", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		t.Fatalf("encode integration publication attestation audit: %v", err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write integration publication attestation audit: %v", err)
	}
}

func writeIntegrationExecutionAudit(t *testing.T, path, catalogDigest, resultID, targetDigest, occurredAt string) {
	t.Helper()
	chain := audit.NewChain()
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "integration-started", OccurredAt: occurredAt},
		Spec: audit.Spec{
			CorrelationID: "integration-execution",
			Actor:         audit.Actor{ID: "local:runner", Type: "user", Assurance: "self-asserted-local"},
			Action:        "integration.component-smoke.started",
			Subjects:      []audit.Subject{{Kind: "CatalogSnapshot", Digest: catalogDigest}},
			Reason:        audit.Reason{Type: "user-request", Reference: "test"},
			Target:        "local:" + targetDigest,
			Outcome:       "started",
		},
	})
	if err != nil {
		t.Fatalf("append started integration audit: %v", err)
	}
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "integration-terminal", OccurredAt: occurredAt},
		Spec: audit.Spec{
			CorrelationID: "integration-execution",
			CausationID:   started.Metadata.ID,
			Actor:         audit.Actor{ID: "local:runner", Type: "user", Assurance: "self-asserted-local"},
			Action:        "integration.component-smoke.completed",
			Subjects: []audit.Subject{
				{Kind: "CatalogSnapshot", Digest: catalogDigest},
				{Kind: "IntegrationTestResult", Digest: resultID},
			},
			Reason:  audit.Reason{Type: "user-request", Reference: "test"},
			Target:  "local:" + targetDigest,
			Outcome: "success",
		},
	})
	if err != nil {
		t.Fatalf("append terminal integration audit: %v", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		t.Fatalf("encode integration audit: %v", err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write integration audit: %v", err)
	}
}
