package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/executor"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestDeploymentImportWritesReceiptAndAudit(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	bundle, err := resources.LoadDeploymentBundle(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := resources.LoadTargetPreflightResult(preflightPath)
	if err != nil {
		t.Fatal(err)
	}
	modelArtifact := testModelArtifact(t, bundle)
	outputPath := filepath.Join(directory, "deployment-import-receipt.yaml")
	auditPath := filepath.Join(directory, "deployment-import.audit.jsonl")
	originalFactory := newKubernetesExecutor
	originalVerify := verifyLocalImportPayload
	t.Cleanup(func() {
		newKubernetesExecutor = originalFactory
		verifyLocalImportPayload = originalVerify
	})
	verifyLocalImportPayload = func(string, resources.ImportedModelArtifact) error { return nil }
	newKubernetesExecutor = func(kubeconfig, contextName string) (kubernetesExecutor, error) {
		if kubeconfig != "/tmp/import-kubeconfig" || contextName != "import-context" {
			t.Fatalf("import did not forward ephemeral kube options: kubeconfig=%q context=%q", kubeconfig, contextName)
		}
		return fixedKubernetesExecutor{
			importFn: func(_ context.Context, config executor.ImportConfig, started time.Time) (executor.ImportResult, error) {
				events, err := audit.LoadJSONL(auditPath)
				if err != nil || len(events) != 1 || events[0].Spec.Action != "deployment.import.started" {
					t.Fatalf("mutation was not preceded by durable start audit: %#v %v", events, err)
				}
				return executor.ImportResult{
					StartedAt:       started,
					CompletedAt:     started.Add(10 * time.Second),
					Target:          preflight.Spec.Target,
					MutationStarted: true,
					Artifact:        config.Artifact,
					Limitations: []string{
						"Import command stages only one explicitly selected model artifact into an existing YARA-owned PVC.",
						"Import command does not create, delete, prune or adopt Kubernetes resources.",
						"Import command does not execute deployment, retirement or rollback workflows.",
					},
				}, nil
			},
		}, nil
	}
	args := []string{
		"--bundle", bundlePath,
		"--confirm-bundle", bundle.Metadata.BundleID,
		"--preflight", preflightPath,
		"--target", preflight.Spec.Target.ReferenceDigest,
		"--artifact-ref", modelArtifact.Ref,
		"--source-dir", filepath.Join(directory, "source"),
		"--internal-root", "model",
		"--namespace", "yara-reference",
		"--model-pvc", "yara-model",
		"--name", "reference-import",
		"--output", outputPath,
		"--audit-output", auditPath,
		"--kubeconfig", "/tmp/import-kubeconfig",
		"--context", "import-context",
	}
	var stdout, stderr bytes.Buffer
	if exit := importKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now }); exit != ExitSuccess {
		t.Fatalf("import exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	importReceipt, err := resources.LoadArtifactImportReceipt(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if report := importReceipt.Validate(); !report.Valid {
		t.Fatalf("import receipt invalid: %#v", report.Diagnostics)
	}
	if len(importReceipt.Spec.ModelArtifacts) != 1 || importReceipt.Spec.ModelArtifacts[0].Ref != modelArtifact.Ref {
		t.Fatalf("import receipt does not bind selected artifact: %#v", importReceipt.Spec.ModelArtifacts)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "deployment.import.completed" || events[1].Spec.Outcome != "success" {
		t.Fatalf("unexpected terminal import audit: %#v", events)
	}
}

func TestDeploymentImportRejectsTargetConfirmationMismatch(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	bundle, err := resources.LoadDeploymentBundle(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	modelArtifact := testModelArtifact(t, bundle)
	originalFactory := newKubernetesExecutor
	originalVerify := verifyLocalImportPayload
	t.Cleanup(func() {
		newKubernetesExecutor = originalFactory
		verifyLocalImportPayload = originalVerify
	})
	verifyLocalImportPayload = func(string, resources.ImportedModelArtifact) error { return nil }
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("executor reached after target confirmation mismatch")
		return nil, nil
	}
	args := []string{
		"--bundle", bundlePath,
		"--confirm-bundle", bundle.Metadata.BundleID,
		"--preflight", preflightPath,
		"--target", testCLIDigest('f'),
		"--artifact-ref", modelArtifact.Ref,
		"--source-dir", filepath.Join(directory, "source"),
		"--namespace", "yara-reference",
		"--model-pvc", "yara-model",
		"--name", "reference-import",
		"--output", filepath.Join(directory, "import.yaml"),
		"--audit-output", filepath.Join(directory, "import.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := importKubernetesDeployment(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("expected invalid input, got exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestDeploymentImportRejectsDigestMismatchBeforeExecutor(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	bundlePath := valueForFlag(paths, "--bundle")
	preflightPath := valueForFlag(paths, "--preflight")
	bundle, err := resources.LoadDeploymentBundle(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := resources.LoadTargetPreflightResult(preflightPath)
	if err != nil {
		t.Fatal(err)
	}
	modelArtifact := testModelArtifact(t, bundle)
	originalFactory := newKubernetesExecutor
	originalVerify := verifyLocalImportPayload
	t.Cleanup(func() {
		newKubernetesExecutor = originalFactory
		verifyLocalImportPayload = originalVerify
	})
	verifyLocalImportPayload = func(string, resources.ImportedModelArtifact) error {
		return errors.New("source model file digest does not match expected bundle identity")
	}
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("executor reached after local digest mismatch")
		return nil, nil
	}
	args := []string{
		"--bundle", bundlePath,
		"--confirm-bundle", bundle.Metadata.BundleID,
		"--preflight", preflightPath,
		"--target", preflight.Spec.Target.ReferenceDigest,
		"--artifact-ref", modelArtifact.Ref,
		"--source-dir", filepath.Join(directory, "source"),
		"--namespace", "yara-reference",
		"--model-pvc", "yara-model",
		"--name", "reference-import",
		"--output", filepath.Join(directory, "import.yaml"),
		"--audit-output", filepath.Join(directory, "import.audit.jsonl"),
	}
	var stdout, stderr bytes.Buffer
	if exit := importKubernetesDeployment(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("expected invalid input, got exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}
