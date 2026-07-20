package cli

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestLifecycleProofRecordWritesLedgerAndAudit(t *testing.T) {
	directory := t.TempDir()
	applyPath, retirePath, rollbackPath := writeLifecycleProofReceiptFixtures(t, directory, time.Now().UTC().Add(-10*time.Minute), true, false)
	outputPath := filepath.Join(directory, "lifecycle-proof-ledger.yaml")
	auditPath := filepath.Join(directory, "lifecycle-proof-ledger.audit.jsonl")
	args := []string{
		"lifecycle", "proof", "record",
		"--apply-receipt", applyPath,
		"--retirement-receipt", retirePath,
		"--rollback-receipt", rollbackPath,
		"--reviewer-role", "platform-security",
		"--decision", "approved",
		"--reason-reference", "ticket-lifecycle-proof-123",
		"--name", "lifecycle-proof-ledger",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("lifecycle proof record failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	ledger, err := resources.LoadLifecycleProofLedger(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ledger.Validate().Valid || ledger.Spec.Stages[0].Stage != resources.LifecycleStageApply || ledger.Spec.Stages[2].Stage != resources.LifecycleStageRollback {
		t.Fatalf("unexpected lifecycle ledger output: %#v", ledger.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "lifecycle.proof.record.completed" {
		t.Fatalf("terminal lifecycle proof audit missing: %#v", events)
	}
}

func TestLifecycleProofRecordRejectsForeignChain(t *testing.T) {
	directory := t.TempDir()
	applyPath, retirePath, rollbackPath := writeLifecycleProofReceiptFixtures(t, directory, time.Now().UTC().Add(-10*time.Minute), false, false)
	args := []string{
		"lifecycle", "proof", "record",
		"--apply-receipt", applyPath,
		"--retirement-receipt", retirePath,
		"--rollback-receipt", rollbackPath,
		"--reviewer-role", "platform-security",
		"--decision", "approved",
		"--reason-reference", "ticket-lifecycle-proof-foreign",
		"--name", "lifecycle-proof-ledger",
		"--output", filepath.Join(directory, "lifecycle-proof-ledger.yaml"),
		"--audit-output", filepath.Join(directory, "lifecycle-proof-ledger.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("foreign lifecycle chain should fail: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestLifecycleProofRecordRejectsStaleAndIncompleteChain(t *testing.T) {
	directory := t.TempDir()
	applyPath, retirePath, rollbackPath := writeLifecycleProofReceiptFixtures(t, directory, time.Now().UTC().Add(-48*time.Hour), true, true)
	args := []string{
		"lifecycle", "proof", "record",
		"--apply-receipt", applyPath,
		"--retirement-receipt", retirePath,
		"--rollback-receipt", rollbackPath,
		"--reviewer-role", "platform-security",
		"--decision", "approved",
		"--reason-reference", "ticket-lifecycle-proof-stale",
		"--name", "lifecycle-proof-ledger",
		"--output", filepath.Join(directory, "lifecycle-proof-ledger.yaml"),
		"--audit-output", filepath.Join(directory, "lifecycle-proof-ledger.audit.jsonl"),
		"--max-receipt-age", "1h",
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("stale or incomplete lifecycle chain should fail: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func writeLifecycleProofReceiptFixtures(t *testing.T, directory string, base time.Time, sameTarget bool, incomplete bool) (string, string, string) {
	t.Helper()
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('a'), ServerVersion: "v1.35.2"}
	retireTarget := target
	if !sameTarget {
		retireTarget.ReferenceDigest = testCLIDigest('b')
	}
	apply := resources.DeploymentReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "DeploymentReceipt",
		Metadata:   resources.DeploymentReceiptMetadata{Name: "apply-receipt"},
		Spec: resources.DeploymentReceiptSpec{
			Outcome:                "succeeded",
			StartedAt:              base.Format(time.RFC3339Nano),
			CompletedAt:            base.Add(time.Minute).Format(time.RFC3339Nano),
			ExecutionCorrelationID: "apply-correlation",
			PlanID:                 testCLIDigest('c'),
			BundleID:               testCLIDigest('d'),
			PreflightResultID:      testCLIDigest('e'),
			ChangeSetID:            testCLIDigest('f'),
			ApprovalID:             testCLIDigest('0'),
			AuthorizationID:        testCLIDigest('1'),
			ImportReceiptID:        testCLIDigest('2'),
			Target:                 target,
			Executor: resources.DeploymentExecutorIdentity{
				Name:         "yara-executor",
				Version:      "0.1.0",
				BinaryDigest: testCLIDigest('3'),
			},
			Operations: []resources.DeploymentOperationReceipt{{
				Resource: resources.KubernetesObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "litellm"},
				Action:   "update",
				Outcome:  "applied",
			}},
			Postflight: []resources.DeploymentPostflightCheck{{
				ID:             "workloads.available",
				Status:         "passed",
				EvidenceDigest: testCLIDigest('4'),
			}},
			Limitations: []string{"Apply receipt fixture."},
		},
	}
	apply, err := apply.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	retire := resources.RetirementReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "RetirementReceipt",
		Metadata:   resources.RetirementReceiptMetadata{Name: "retire-receipt"},
		Spec: resources.RetirementReceiptSpec{
			Outcome:                "succeeded",
			StartedAt:              base.Add(2 * time.Minute).Format(time.RFC3339Nano),
			CompletedAt:            base.Add(3 * time.Minute).Format(time.RFC3339Nano),
			ExecutionCorrelationID: "retire-correlation",
			PlanID:                 testCLIDigest('c'),
			BundleID:               testCLIDigest('d'),
			PreflightResultID:      testCLIDigest('e'),
			ChangeSetID:            testCLIDigest('f'),
			ApprovalID:             testCLIDigest('0'),
			AuthorizationID:        testCLIDigest('5'),
			Target:                 retireTarget,
			Executor: resources.DeploymentExecutorIdentity{
				Name:         "yara-executor",
				Version:      "0.1.0",
				BinaryDigest: testCLIDigest('3'),
			},
			Operations: []resources.RetirementOperationReceipt{{
				Resource: resources.KubernetesObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "litellm"},
				Action:   "delete",
				Outcome:  "deleted",
			}},
			Limitations: []string{"Retirement receipt fixture."},
		},
	}
	retire, err = retire.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	rollbackOutcome := "succeeded"
	rollbackOpOutcome := "reverted"
	if incomplete {
		rollbackOutcome = "partial"
		rollbackOpOutcome = "skipped"
	}
	rollback := resources.RollbackReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "RollbackReceipt",
		Metadata:   resources.RollbackReceiptMetadata{Name: "rollback-receipt"},
		Spec: resources.RollbackReceiptSpec{
			Outcome:                rollbackOutcome,
			StartedAt:              base.Add(4 * time.Minute).Format(time.RFC3339Nano),
			CompletedAt:            base.Add(5 * time.Minute).Format(time.RFC3339Nano),
			ExecutionCorrelationID: "rollback-correlation",
			PlanID:                 testCLIDigest('c'),
			BundleID:               testCLIDigest('d'),
			PreflightResultID:      testCLIDigest('e'),
			ChangeSetID:            testCLIDigest('f'),
			ApprovalID:             testCLIDigest('0'),
			AuthorizationID:        testCLIDigest('6'),
			Target:                 target,
			Executor: resources.DeploymentExecutorIdentity{
				Name:         "yara-executor",
				Version:      "0.1.0",
				BinaryDigest: testCLIDigest('3'),
			},
			Operations: []resources.RollbackOperationReceipt{{
				Resource: resources.KubernetesObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "litellm"},
				Action:   "update",
				Outcome:  rollbackOpOutcome,
			}},
			Limitations: []string{"Rollback receipt fixture."},
		},
	}
	rollback, err = rollback.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	applyPath := filepath.Join(directory, "apply-receipt.yaml")
	retirePath := filepath.Join(directory, "retire-receipt.yaml")
	rollbackPath := filepath.Join(directory, "rollback-receipt.yaml")
	writeYAMLFixture(t, applyPath, apply)
	writeYAMLFixture(t, retirePath, retire)
	writeYAMLFixture(t, rollbackPath, rollback)
	return applyPath, retirePath, rollbackPath
}
