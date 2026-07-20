package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestLifecycleProofApprovePublicationWritesArtifactAndAudit(t *testing.T) {
	directory := t.TempDir()
	ledgerPath, ledgerID := writeLifecycleProofLedgerForApprovalTest(t, directory, time.Now().UTC().Add(-30*time.Minute))
	outputPath := filepath.Join(directory, "lifecycle-proof-approval.yaml")
	auditPath := filepath.Join(directory, "lifecycle-proof-approval.audit.jsonl")
	args := []string{
		"lifecycle", "proof", "approve-publication",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--lifecycle-proof-ledger", ledgerPath,
		"--confirm-lifecycle-proof-ledger", ledgerID,
		"--evidence", "sha256:" + strings.Repeat("a", 64),
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-lifecycle-approval-123",
		"--max-ledger-age", "720h",
		"--name", "lifecycle-proof-approval",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("lifecycle proof approval failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	approval, err := resources.LoadLifecycleProofApproval(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !approval.Validate().Valid || approval.Spec.LedgerID != ledgerID || approval.Spec.Decision != resources.PromotionDecisionApproved {
		t.Fatalf("unexpected lifecycle proof approval output: %#v", approval.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "lifecycle.proof.approve-publication.completed" {
		t.Fatalf("terminal lifecycle proof approval audit missing: %#v", events)
	}
}

func TestLifecycleProofApprovePublicationRejectsStaleLedger(t *testing.T) {
	directory := t.TempDir()
	ledgerPath, ledgerID := writeLifecycleProofLedgerForApprovalTest(t, directory, time.Now().UTC().Add(-48*time.Hour))
	args := []string{
		"lifecycle", "proof", "approve-publication",
		"--catalog", filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--lifecycle-proof-ledger", ledgerPath,
		"--confirm-lifecycle-proof-ledger", ledgerID,
		"--evidence", "sha256:" + strings.Repeat("a", 64),
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-lifecycle-approval-123",
		"--max-ledger-age", "1h",
		"--name", "lifecycle-proof-approval",
		"--output", filepath.Join(directory, "lifecycle-proof-approval.yaml"),
		"--audit-output", filepath.Join(directory, "lifecycle-proof-approval.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("stale lifecycle ledger should fail: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func writeLifecycleProofLedgerForApprovalTest(t *testing.T, directory string, recordedAt time.Time) (string, string) {
	t.Helper()
	ledger := resources.LifecycleProofLedger{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofLedger",
		Metadata:   resources.LifecycleProofLedgerMeta{Name: "lifecycle-proof-ledger"},
		Spec: resources.LifecycleProofLedgerSpec{
			RecordedAt:            recordedAt.Format(time.RFC3339Nano),
			PlanID:                "sha256:" + strings.Repeat("1", 64),
			BundleID:              "sha256:" + strings.Repeat("2", 64),
			TargetReferenceDigest: "sha256:" + strings.Repeat("3", 64),
			Reviewer: resources.ReviewerRecord{
				Identity:  "local:reviewer",
				Role:      "platform-security",
				Assurance: "self-asserted-local",
			},
			Decision:        resources.PromotionDecisionApproved,
			ReasonReference: "ticket-lifecycle-proof-123",
			Stages: []resources.LifecycleProofLedgerStage{
				{Stage: resources.LifecycleStageApply, ReceiptID: "sha256:" + strings.Repeat("4", 64), ExecutionCorrelationID: "apply", Outcome: "succeeded", CompletedAt: recordedAt.Add(time.Minute).Format(time.RFC3339Nano)},
				{Stage: resources.LifecycleStageRetire, ReceiptID: "sha256:" + strings.Repeat("5", 64), ExecutionCorrelationID: "retire", Outcome: "succeeded", CompletedAt: recordedAt.Add(2 * time.Minute).Format(time.RFC3339Nano)},
				{Stage: resources.LifecycleStageRollback, ReceiptID: "sha256:" + strings.Repeat("6", 64), ExecutionCorrelationID: "rollback", Outcome: "succeeded", CompletedAt: recordedAt.Add(3 * time.Minute).Format(time.RFC3339Nano)},
			},
			Limitations: []string{
				"Lifecycle proof ledger does not execute mutations.",
				"Lifecycle proof ledger links immutable receipt identities only.",
			},
		},
	}
	var err error
	ledger, err = ledger.AssignLedgerID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "lifecycle-proof-ledger.yaml")
	writeYAMLFixture(t, path, ledger)
	return path, ledger.Metadata.LedgerID
}
