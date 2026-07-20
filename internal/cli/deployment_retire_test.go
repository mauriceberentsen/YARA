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

func TestDeploymentRetireDurablyAuditsBeforeMutationAndBindsReceipt(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	args, authorization := writeRetirementInputs(t, directory, now)
	receiptPath, auditPath := filepath.Join(directory, "retirement-receipt.yaml"), filepath.Join(directory, "retirement.audit.jsonl")
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	called := false
	newKubernetesExecutor = func(kubeconfig, contextName string) (kubernetesExecutor, error) {
		if kubeconfig != "/secret/kubeconfig" || contextName != "admin-context" {
			t.Fatal("ephemeral connection options not forwarded")
		}
		return fixedKubernetesExecutor{
			retire: func(_ context.Context, bundle resources.DeploymentBundle, changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, started time.Time) (executor.RetirementResult, error) {
				called = true
				events, err := audit.LoadJSONL(auditPath)
				if err != nil || len(events) != 1 || events[0].Spec.Action != "deployment.retire.started" {
					t.Fatalf("retirement was not preceded by durable start audit: %#v %v", events, err)
				}
				operations := []resources.RetirementOperationReceipt{
					{
						Resource:     changeSet.Spec.Operations[1].Resource,
						Action:       "delete",
						Outcome:      "deleted",
						BeforeDigest: changeSet.Spec.Operations[1].DesiredDigest,
					},
				}
				return executor.RetirementResult{
					StartedAt:       started,
					CompletedAt:     started.Add(time.Minute),
					Target:          authorization.Spec.Target,
					MutationStarted: true,
					Operations:      operations,
					Limitations:     []string{"Test retirement executor."},
				}, nil
			},
		}, nil
	}
	allArgs := append(args, "--confirm-authorization", authorization.Metadata.AuthorizationID, "--name", "reference-retirement", "--receipt-output", receiptPath, "--audit-output", auditPath, "--kubeconfig", "/secret/kubeconfig", "--context", "admin-context")
	var stdout, stderr bytes.Buffer
	if exit := retireKubernetesDeploymentAt(allArgs, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitSuccess {
		t.Fatalf("retire exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if !called {
		t.Fatal("retirement executor was not called")
	}
	receipt, err := resources.LoadRetirementReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Spec.AuthorizationID != authorization.Metadata.AuthorizationID || receipt.Spec.Outcome != "succeeded" {
		t.Fatalf("retirement receipt missing execution binding: %#v", receipt.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Subjects[len(events[1].Spec.Subjects)-1].Digest != receipt.Metadata.ReceiptID {
		t.Fatalf("terminal retirement audit does not bind receipt: %#v", events)
	}
}

func TestDeploymentRetireRejectsWrongConfirmationBeforeExecutor(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	args, _ := writeRetirementInputs(t, directory, now)
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("retirement executor reached after wrong confirmation")
		return nil, nil
	}
	allArgs := append(args, "--confirm-authorization", testCLIDigest('9'), "--name", "retirement", "--receipt-output", filepath.Join(directory, "retirement-receipt.yaml"), "--audit-output", filepath.Join(directory, "retirement.audit.jsonl"))
	var stdout, stderr bytes.Buffer
	if exit := retireKubernetesDeploymentAt(allArgs, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("wrong confirmation exit=%d stdout=%s", exit, stdout.String())
	}
	events, err := audit.LoadJSONL(filepath.Join(directory, "retirement.audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !slices.Contains(events[1].Spec.DiagnosticCodes, "YARA-RET-110") {
		t.Fatalf("rejected retirement attempt was not audited: %#v", events)
	}
}

func writeRetirementInputs(t *testing.T, directory string, now time.Time) ([]string, resources.ExecutionAuthorization) {
	t.Helper()
	bundlePath := writeKubernetesBundle(t, directory)
	bundle, _ := resources.LoadDeploymentBundle(bundlePath)
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('c'), ServerVersion: "v1.35.2"}
	preflightPath := writeFreshPreflight(t, directory, bundle, target, now)
	preflight, _ := resources.LoadTargetPreflightResult(preflightPath)
	changeSetPath := filepath.Join(directory, "change-set.yaml")
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		t.Fatal(err)
	}
	changeSet := resources.KubernetesChangeSet{
		APIVersion: resources.APIVersion,
		Kind:       "KubernetesChangeSet",
		Metadata: resources.KubernetesChangeSetMetadata{
			Name: "retire-change-set",
		},
		Spec: resources.KubernetesChangeSetSpec{
			Outcome:           "review-required",
			ObservedAt:        now.Add(time.Minute).Format(time.RFC3339Nano),
			BundleID:          bundle.Metadata.BundleID,
			PlanID:            bundle.Spec.PlanID,
			PreflightResultID: preflight.Metadata.ResultID,
			Observer:          resources.TargetPreflightObserver{Name: "observer", Version: "0.2.0", Mode: "read-only"},
			Target:            target,
			Operations:        retirementOperationsFromDesired(desired),
			Summary: resources.KubernetesChangeSummary{
				NoOps: len(desired),
			},
			Limitations: []string{"Retirement baseline fixture."},
		},
	}
	changeSet, err = changeSet.AssignChangeSetID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, changeSetPath, changeSet)
	approval := resources.DeploymentApproval{
		APIVersion: resources.APIVersion,
		Kind:       "DeploymentApproval",
		Metadata: resources.DeploymentApprovalMetadata{
			Name: "retire-approval",
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
			Reason:            resources.ApprovalReason{Type: "user-review", Reference: "ticket-retire"},
			Limitations:       []string{"Retirement review only."},
		},
	}
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatal(err)
	}
	approvalPath := filepath.Join(directory, "approval.yaml")
	writeYAMLFixture(t, approvalPath, approval)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	_, publicPath := writeAuthorizationKeys(t, directory, publicKey, privateKey)
	authorization := resources.ExecutionAuthorization{
		APIVersion: resources.APIVersion,
		Kind:       "ExecutionAuthorization",
		Metadata: resources.ExecutionAuthorizationMetadata{
			Name: "retire-authorization",
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
				AllowedActions:            []string{"delete"},
				MaxOperations:             len(changeSet.Spec.Operations) - 1,
				AllowDelete:               true,
				AllowActiveVerification:   false,
				AcceptedPreflightBlockers: []string{},
			},
		},
	}
	authorization, err = authorization.Sign(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	authorizationPath := filepath.Join(directory, "authorization.yaml")
	writeYAMLFixture(t, authorizationPath, authorization)
	return []string{"--bundle", bundlePath, "--preflight", preflightPath, "--change-set", changeSetPath, "--approval", approvalPath, "--authorization", authorizationPath, "--public-key", publicPath}, authorization
}

func retirementOperationsFromDesired(desired []changeset.DesiredObject) []resources.KubernetesChangeOperation {
	ops := make([]resources.KubernetesChangeOperation, 0, len(desired))
	for _, object := range desired {
		ops = append(ops, resources.KubernetesChangeOperation{
			Resource:      object.Reference,
			Action:        "no-op",
			Ownership:     "owned",
			DesiredDigest: object.Digest,
			CurrentDigest: object.Digest,
			RiskClasses:   []string{"workload"},
		})
	}
	return ops
}
