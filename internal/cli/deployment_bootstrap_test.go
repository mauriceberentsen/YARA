package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/executor"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestDeploymentBootstrapWritesReceiptAndAudit(t *testing.T) {
	directory := t.TempDir()
	receiptPath := filepath.Join(directory, "bootstrap-receipt.yaml")
	auditPath := filepath.Join(directory, "bootstrap.audit.jsonl")
	now := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	targetDigest := testCLIDigest('a')
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(kubeconfig, contextName string) (kubernetesExecutor, error) {
		if kubeconfig != "/tmp/bootstrap-kubeconfig" || contextName != "bootstrap-context" {
			t.Fatalf("bootstrap did not forward ephemeral kube options: kubeconfig=%q context=%q", kubeconfig, contextName)
		}
		return fixedKubernetesExecutor{
			bootstrap: func(_ context.Context, config executor.BootstrapConfig, started time.Time) (executor.BootstrapResult, error) {
				if config.TargetReferenceDigest != targetDigest || config.Namespace != "yara-reference" || config.ModelPVC != "yara-model" || config.StorageClass != "local-path" || config.Size != "200Gi" {
					t.Fatalf("unexpected bootstrap config: %#v", config)
				}
				events, err := audit.LoadJSONL(auditPath)
				if err != nil || len(events) != 1 || events[0].Spec.Action != "deployment.bootstrap.started" {
					t.Fatalf("mutation was not preceded by durable start audit: %#v %v", events, err)
				}
				return executor.BootstrapResult{
					StartedAt:       started,
					CompletedAt:     started.Add(8 * time.Second),
					Target:          resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: targetDigest, ServerVersion: "v1.35.6"},
					MutationStarted: true,
					Operations: []resources.BootstrapOperationReceipt{
						{
							Resource: resources.KubernetesObjectReference{APIVersion: "v1", Kind: "Namespace", Name: "yara-reference"},
							Action:   "create",
							Outcome:  "created",
						},
						{
							Resource: resources.KubernetesObjectReference{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: "yara-reference", Name: "yara-model"},
							Action:   "create",
							Outcome:  "created",
						},
					},
					Limitations: []string{
						"Bootstrap creates only one YARA-owned namespace and one model PVC.",
						"Bootstrap does not import artifacts or execute apply, retirement or rollback workflows.",
						"Bootstrap never adopts, updates, prunes or deletes existing resources.",
					},
				}, nil
			},
		}, nil
	}
	args := []string{
		"--name", "reference-bootstrap",
		"--namespace", "yara-reference",
		"--model-pvc", "yara-model",
		"--storage-class", "local-path",
		"--size", "200Gi",
		"--target", targetDigest,
		"--receipt-output", receiptPath,
		"--audit-output", auditPath,
		"--kubeconfig", "/tmp/bootstrap-kubeconfig",
		"--context", "bootstrap-context",
	}
	var stdout, stderr bytes.Buffer
	if exit := bootstrapKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now }); exit != ExitSuccess {
		t.Fatalf("bootstrap exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	receipt, err := resources.LoadBootstrapReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if report := receipt.Validate(); !report.Valid {
		t.Fatalf("receipt invalid: %#v", report.Diagnostics)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Outcome != "success" || events[1].Spec.Subjects[len(events[1].Spec.Subjects)-1].Digest != receipt.Metadata.ReceiptID {
		t.Fatalf("terminal bootstrap audit does not bind receipt: %#v", events)
	}
}

func TestDeploymentBootstrapRejectsInvalidFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := bootstrapKubernetesDeployment([]string{
		"--name", "reference-bootstrap",
		"--namespace", "yara-reference",
		"--model-pvc", "yara-model",
		"--storage-class", "local-path",
		"--size", "0Gi",
		"--target", "sha256:not-a-digest",
		"--receipt-output", "receipt.yaml",
		"--audit-output", "audit.jsonl",
	}, &stdout, &stderr)
	if exit != ExitInvalidInput {
		t.Fatalf("expected invalid input, got exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestDeploymentBootstrapAuditsFailureWhenTargetConfirmationDrifts(t *testing.T) {
	directory := t.TempDir()
	receiptPath := filepath.Join(directory, "bootstrap-receipt.yaml")
	auditPath := filepath.Join(directory, "bootstrap.audit.jsonl")
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		return fixedKubernetesExecutor{
			bootstrap: func(_ context.Context, _ executor.BootstrapConfig, started time.Time) (executor.BootstrapResult, error) {
				return executor.BootstrapResult{
					StartedAt:       started,
					Target:          resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('f'), ServerVersion: "v1.35.6"},
					MutationStarted: false,
				}, errors.New("target identity does not match explicit bootstrap confirmation")
			},
		}, nil
	}
	args := []string{
		"--name", "reference-bootstrap",
		"--namespace", "yara-reference",
		"--model-pvc", "yara-model",
		"--storage-class", "local-path",
		"--size", "200Gi",
		"--target", testCLIDigest('a'),
		"--receipt-output", receiptPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := bootstrapKubernetesDeployment(args, &stdout, &stderr); exit != ExitInfeasible {
		t.Fatalf("expected infeasible, got exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Outcome != "failed" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-BST-114") {
		t.Fatalf("unexpected terminal diagnostic codes: %#v", terminal.Spec)
	}
}
