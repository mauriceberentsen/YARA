package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/executor"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestDeploymentRollbackDurablyAuditsBeforeMutationAndBindsReceipt(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	args, authorization := writeRollbackInputs(t, directory, now)
	receiptPath, auditPath := filepath.Join(directory, "rollback-receipt.yaml"), filepath.Join(directory, "rollback.audit.jsonl")
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	called := false
	newKubernetesExecutor = func(kubeconfig, contextName string) (kubernetesExecutor, error) {
		if kubeconfig != "/secret/kubeconfig" || contextName != "admin-context" {
			t.Fatal("ephemeral connection options not forwarded")
		}
		return fixedKubernetesExecutor{
			rollback: func(_ context.Context, _ resources.DeploymentBundle, changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, started time.Time) (executor.RollbackResult, error) {
				called = true
				events, err := audit.LoadJSONL(auditPath)
				if err != nil || len(events) != 1 || events[0].Spec.Action != "deployment.rollback.started" {
					t.Fatalf("rollback was not preceded by durable start audit: %#v %v", events, err)
				}
				operations := []resources.RollbackOperationReceipt{{
					Resource:     changeSet.Spec.Operations[1].Resource,
					Action:       changeSet.Spec.Operations[1].Action,
					Outcome:      "reverted",
					BeforeDigest: changeSet.Spec.Operations[1].CurrentDigest,
					AfterDigest:  changeSet.Spec.Operations[1].DesiredDigest,
				}}
				return executor.RollbackResult{
					StartedAt:       started,
					CompletedAt:     started.Add(time.Minute),
					Target:          authorization.Spec.Target,
					MutationStarted: true,
					Operations:      operations,
					Limitations:     []string{"Test rollback executor."},
				}, nil
			},
		}, nil
	}
	allArgs := append(args, "--confirm-authorization", authorization.Metadata.AuthorizationID, "--name", "reference-rollback", "--receipt-output", receiptPath, "--audit-output", auditPath, "--kubeconfig", "/secret/kubeconfig", "--context", "admin-context")
	var stdout, stderr bytes.Buffer
	if exit := rollbackKubernetesDeploymentAt(allArgs, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitSuccess {
		t.Fatalf("rollback exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if !called {
		t.Fatal("rollback executor was not called")
	}
	receipt, err := resources.LoadRollbackReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Spec.AuthorizationID != authorization.Metadata.AuthorizationID || receipt.Spec.Outcome != "succeeded" {
		t.Fatalf("rollback receipt missing execution binding: %#v", receipt.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Subjects[len(events[1].Spec.Subjects)-1].Digest != receipt.Metadata.ReceiptID {
		t.Fatalf("terminal rollback audit does not bind receipt: %#v", events)
	}
}

func TestDeploymentRollbackRejectsWrongConfirmationBeforeExecutor(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	args, _ := writeRollbackInputs(t, directory, now)
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("rollback executor reached after wrong confirmation")
		return nil, nil
	}
	allArgs := append(args, "--confirm-authorization", testCLIDigest('9'), "--name", "rollback", "--receipt-output", filepath.Join(directory, "rollback-receipt.yaml"), "--audit-output", filepath.Join(directory, "rollback.audit.jsonl"))
	var stdout, stderr bytes.Buffer
	if exit := rollbackKubernetesDeploymentAt(allArgs, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("wrong rollback confirmation exit=%d stdout=%s", exit, stdout.String())
	}
	events, err := audit.LoadJSONL(filepath.Join(directory, "rollback.audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !slices.Contains(events[1].Spec.DiagnosticCodes, "YARA-RBK-110") {
		t.Fatalf("rejected rollback attempt was not audited: %#v", events)
	}
}

func writeRollbackInputs(t *testing.T, directory string, now time.Time) ([]string, resources.ExecutionAuthorization) {
	t.Helper()
	bundlePath := writeKubernetesBundle(t, directory)
	bundle, _ := resources.LoadDeploymentBundle(bundlePath)
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('c'), ServerVersion: "v1.35.2"}
	preflightPath := writeFreshPreflight(t, directory, bundle, target, now)
	preflight, _ := resources.LoadTargetPreflightResult(preflightPath)
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		t.Fatal(err)
	}
	changeSet := resources.KubernetesChangeSet{
		APIVersion: resources.APIVersion,
		Kind:       "KubernetesChangeSet",
		Metadata: resources.KubernetesChangeSetMetadata{
			Name: "rollback-change-set",
		},
		Spec: resources.KubernetesChangeSetSpec{
			Outcome:           "review-required",
			ObservedAt:        now.Add(time.Minute).Format(time.RFC3339Nano),
			BundleID:          bundle.Metadata.BundleID,
			PlanID:            bundle.Spec.PlanID,
			PreflightResultID: preflight.Metadata.ResultID,
			Observer:          resources.TargetPreflightObserver{Name: "observer", Version: "0.2.0", Mode: "read-only"},
			Target:            target,
			Operations:        rollbackOperationsFromDesired(desired),
			Summary: resources.KubernetesChangeSummary{
				Creates: len(desired) - 1,
				NoOps:   1,
			},
			Limitations: []string{"Rollback baseline fixture."},
		},
	}
	changeSet, err = changeSet.AssignChangeSetID()
	if err != nil {
		t.Fatal(err)
	}
	changeSetPath := filepath.Join(directory, "rollback-change-set.yaml")
	writeYAMLFixture(t, changeSetPath, changeSet)
	approval := resources.DeploymentApproval{
		APIVersion: resources.APIVersion,
		Kind:       "DeploymentApproval",
		Metadata: resources.DeploymentApprovalMetadata{
			Name: "rollback-approval",
		},
		Spec: resources.DeploymentApprovalSpec{
			Decision:          "approved",
			Effect:            "review-only",
			RecordedAt:        now.Add(time.Minute).Format(time.RFC3339Nano),
			ExpiresAt:         now.Add(time.Hour).Format(time.RFC3339Nano),
			PlanID:            bundle.Spec.PlanID,
			BundleID:          bundle.Metadata.BundleID,
			PreflightResultID: preflight.Metadata.ResultID,
			ChangeSetID:       changeSet.Metadata.ChangeSetID,
			Target:            target,
			Actor:             resources.ApprovalActor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"},
			Reason:            resources.ApprovalReason{Type: "user-review", Reference: "ticket-rollback"},
			Limitations:       []string{"Rollback review only."},
		},
	}
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatal(err)
	}
	approvalPath := filepath.Join(directory, "rollback-approval.yaml")
	writeYAMLFixture(t, approvalPath, approval)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	_, publicPath := writeAuthorizationKeys(t, directory, publicKey, privateKey)
	authorization := resources.ExecutionAuthorization{
		APIVersion: resources.APIVersion,
		Kind:       "ExecutionAuthorization",
		Metadata: resources.ExecutionAuthorizationMetadata{
			Name: "rollback-authorization",
		},
		Spec: resources.ExecutionAuthorizationSpec{
			IssuedAt:          now.Add(2 * time.Minute).Format(time.RFC3339Nano),
			ExpiresAt:         now.Add(12 * time.Minute).Format(time.RFC3339Nano),
			PlanID:            bundle.Spec.PlanID,
			BundleID:          bundle.Metadata.BundleID,
			PreflightResultID: preflight.Metadata.ResultID,
			ChangeSetID:       changeSet.Metadata.ChangeSetID,
			ApprovalID:        approval.Metadata.ApprovalID,
			Target:            target,
			Issuer:            resources.ExecutionAuthorizationIssuer{KeyID: "operations-key-1"},
			Constraints: resources.ExecutionAuthorizationConstraints{
				AllowedActions:            []string{"create", "no-op"},
				MaxOperations:             len(changeSet.Spec.Operations),
				AllowDelete:               false,
				AllowActiveVerification:   false,
				AcceptedPreflightBlockers: []string{},
			},
		},
	}
	authorization, err = authorization.Sign(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	authorizationPath := filepath.Join(directory, "rollback-authorization.yaml")
	writeYAMLFixture(t, authorizationPath, authorization)
	return []string{"--bundle", bundlePath, "--preflight", preflightPath, "--change-set", changeSetPath, "--approval", approvalPath, "--authorization", authorizationPath, "--public-key", publicPath}, authorization
}

func rollbackOperationsFromDesired(desired []changeset.DesiredObject) []resources.KubernetesChangeOperation {
	ops := make([]resources.KubernetesChangeOperation, 0, len(desired))
	for _, object := range desired {
		action, current, ownership := "create", "", "absent"
		if object.Reference.Kind == "Namespace" {
			action, current, ownership = "no-op", object.Digest, "owned"
		}
		ops = append(ops, resources.KubernetesChangeOperation{
			Resource:      object.Reference,
			Action:        action,
			Ownership:     ownership,
			DesiredDigest: object.Digest,
			CurrentDigest: current,
			RiskClasses:   []string{"workload"},
		})
	}
	return ops
}
