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
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/executor"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type fixedKubernetesExecutor struct {
	execute  func(context.Context, resources.DeploymentBundle, resources.KubernetesChangeSet, resources.ExecutionAuthorization, resources.ArtifactImportReceipt, time.Time) (executor.ExecutionResult, error)
	retire   func(context.Context, resources.DeploymentBundle, resources.KubernetesChangeSet, resources.ExecutionAuthorization, time.Time) (executor.RetirementResult, error)
	rollback func(context.Context, resources.DeploymentBundle, resources.KubernetesChangeSet, resources.ExecutionAuthorization, time.Time) (executor.RollbackResult, error)
}

func (f fixedKubernetesExecutor) Execute(ctx context.Context, bundle resources.DeploymentBundle, changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, importReceipt resources.ArtifactImportReceipt, started time.Time) (executor.ExecutionResult, error) {
	return f.execute(ctx, bundle, changeSet, authorization, importReceipt, started)
}

func (f fixedKubernetesExecutor) Retire(ctx context.Context, bundle resources.DeploymentBundle, changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, started time.Time) (executor.RetirementResult, error) {
	if f.retire == nil {
		return executor.RetirementResult{}, nil
	}
	return f.retire(ctx, bundle, changeSet, authorization, started)
}

func (f fixedKubernetesExecutor) Rollback(ctx context.Context, bundle resources.DeploymentBundle, changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, started time.Time) (executor.RollbackResult, error) {
	if f.rollback == nil {
		return executor.RollbackResult{}, nil
	}
	return f.rollback(ctx, bundle, changeSet, authorization, started)
}

func TestDeploymentApplyDurablyAuditsBeforeMutationAndBindsReceipt(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, directory, now)
	receiptPath, auditPath := filepath.Join(directory, "receipt.yaml"), filepath.Join(directory, "apply.audit.jsonl")
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	called := false
	newKubernetesExecutor = func(kubeconfig, contextName string) (kubernetesExecutor, error) {
		if kubeconfig != "/secret/kubeconfig" || contextName != "admin-context" {
			t.Fatal("ephemeral connection options not forwarded")
		}
		return fixedKubernetesExecutor{execute: func(_ context.Context, bundle resources.DeploymentBundle, changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, importReceipt resources.ArtifactImportReceipt, started time.Time) (executor.ExecutionResult, error) {
			called = true
			events, err := audit.LoadJSONL(auditPath)
			if err != nil || len(events) != 1 || events[0].Spec.Action != "deployment.apply.started" {
				t.Fatalf("mutation was not preceded by durable start audit: %#v %v", events, err)
			}
			if importReceipt.Metadata.ImportReceiptID == "" {
				t.Fatal("executor did not receive import receipt")
			}
			operations := make([]resources.DeploymentOperationReceipt, 0, len(changeSet.Spec.Operations))
			for _, operation := range changeSet.Spec.Operations {
				operations = append(operations, resources.DeploymentOperationReceipt{Resource: operation.Resource, Action: operation.Action, Outcome: "applied", AfterDigest: operation.DesiredDigest})
			}
			evidence, _ := canonical.Digest(struct{ Passed bool }{true})
			return executor.ExecutionResult{StartedAt: started, CompletedAt: started.Add(time.Minute), Target: authorization.Spec.Target, MutationStarted: true, Operations: operations, Postflight: []resources.DeploymentPostflightCheck{{ID: "workloads.available", Status: "passed", EvidenceDigest: evidence}}, Limitations: []string{"Test executor."}}, nil
		}}, nil
	}
	args := append(paths, "--confirm-authorization", authorization.Metadata.AuthorizationID, "--name", "reference-receipt", "--receipt-output", receiptPath, "--audit-output", auditPath, "--kubeconfig", "/secret/kubeconfig", "--context", "admin-context")
	var stdout, stderr bytes.Buffer
	if exit := applyKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitSuccess {
		t.Fatalf("apply exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if !called {
		t.Fatal("executor was not called")
	}
	receipt, err := resources.LoadDeploymentReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Spec.AuthorizationID != authorization.Metadata.AuthorizationID || receipt.Spec.Outcome != "succeeded" {
		t.Fatalf("receipt missing execution binding: %#v", receipt.Spec)
	}
	if receipt.Spec.ImportReceiptID == "" {
		t.Fatalf("receipt missing import receipt binding: %#v", receipt.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Subjects[len(events[1].Spec.Subjects)-1].Digest != receipt.Metadata.ReceiptID {
		t.Fatalf("terminal audit does not bind receipt: %#v", events)
	}
	durable := string(mustReadFile(t, receiptPath)) + string(mustReadFile(t, auditPath))
	for _, forbidden := range []string{"/secret/kubeconfig", "admin-context"} {
		if bytes.Contains([]byte(durable), []byte(forbidden)) {
			t.Fatalf("durable evidence leaked %q", forbidden)
		}
	}
}

func TestDeploymentApplyRejectsWrongConfirmationBeforeExecutor(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, directory, now)
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("executor reached after wrong confirmation")
		return nil, nil
	}
	args := append(paths, "--confirm-authorization", testCLIDigest('0'), "--name", "receipt", "--receipt-output", filepath.Join(directory, "receipt.yaml"), "--audit-output", filepath.Join(directory, "apply.audit.jsonl"))
	var stdout, stderr bytes.Buffer
	if exit := applyKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("wrong confirmation exit=%d stdout=%s", exit, stdout.String())
	}
	events, err := audit.LoadJSONL(filepath.Join(directory, "apply.audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Outcome != "failed" || !slices.Contains(events[1].Spec.DiagnosticCodes, "YARA-EXE-110") {
		t.Fatalf("rejected attempt was not audited: %#v", events)
	}
}

func TestDeploymentApplyRejectsMismatchedImportReceiptBeforeExecutor(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, directory, now)
	receiptPath := filepath.Join(directory, "import-receipt.yaml")
	importReceipt, err := resources.LoadArtifactImportReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	importReceipt.Spec.BundleID = testCLIDigest('f')
	importReceipt, err = importReceipt.AssignImportReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, receiptPath, importReceipt)
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("executor reached after mismatched import receipt")
		return nil, nil
	}
	args := append(paths, "--confirm-authorization", authorization.Metadata.AuthorizationID, "--name", "receipt", "--receipt-output", filepath.Join(directory, "receipt.yaml"), "--audit-output", filepath.Join(directory, "apply.audit.jsonl"))
	var stdout, stderr bytes.Buffer
	if exit := applyKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("mismatched import receipt exit=%d stdout=%s", exit, stdout.String())
	}
}

func TestDeploymentApplyRejectsMissingTransferReceiptForAirGappedBundle(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, directory, now)
	paths = removeFlag(paths, "--transfer-receipt")
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("executor reached without transfer receipt chain")
		return nil, nil
	}
	args := append(paths, "--confirm-authorization", authorization.Metadata.AuthorizationID, "--name", "receipt", "--receipt-output", filepath.Join(directory, "receipt.yaml"), "--audit-output", filepath.Join(directory, "apply.audit.jsonl"))
	var stdout, stderr bytes.Buffer
	if exit := applyKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("missing transfer receipt exit=%d stdout=%s", exit, stdout.String())
	}
}

func TestDeploymentApplyRejectsTransferReceiptWithoutImportLink(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, directory, now)
	transferPath := valueForFlag(paths, "--transfer-receipt")
	transferReceipt, err := resources.LoadArtifactTransferReceipt(transferPath)
	if err != nil {
		t.Fatal(err)
	}
	transferReceipt.Spec.PriorReceiptIDs = []string{testCLIDigest('f')}
	transferReceipt, err = transferReceipt.AssignTransferReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, transferPath, transferReceipt)
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("executor reached with invalid transfer receipt chain")
		return nil, nil
	}
	args := append(paths, "--confirm-authorization", authorization.Metadata.AuthorizationID, "--name", "receipt", "--receipt-output", filepath.Join(directory, "receipt.yaml"), "--audit-output", filepath.Join(directory, "apply.audit.jsonl"))
	var stdout, stderr bytes.Buffer
	if exit := applyKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("broken transfer chain exit=%d stdout=%s", exit, stdout.String())
	}
}

func TestDeploymentApplyRejectsMissingScanReceiptForAirGappedBundle(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, directory, now)
	paths = removeFlag(paths, "--scan-receipt")
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("executor reached without scan receipt chain")
		return nil, nil
	}
	args := append(paths, "--confirm-authorization", authorization.Metadata.AuthorizationID, "--name", "receipt", "--receipt-output", filepath.Join(directory, "receipt.yaml"), "--audit-output", filepath.Join(directory, "apply.audit.jsonl"))
	var stdout, stderr bytes.Buffer
	if exit := applyKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("missing scan receipt exit=%d stdout=%s", exit, stdout.String())
	}
}

func TestDeploymentApplyRejectsScanReceiptWithoutTransferLink(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, directory, now)
	scanPath := valueForFlag(paths, "--scan-receipt")
	scanReceipt, err := resources.LoadArtifactScanReceipt(scanPath)
	if err != nil {
		t.Fatal(err)
	}
	scanReceipt.Spec.PriorReceiptIDs = []string{testCLIDigest('f')}
	scanReceipt, err = scanReceipt.AssignScanReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, scanPath, scanReceipt)
	originalFactory := newKubernetesExecutor
	t.Cleanup(func() { newKubernetesExecutor = originalFactory })
	newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
		t.Fatal("executor reached with invalid scan receipt chain")
		return nil, nil
	}
	args := append(paths, "--confirm-authorization", authorization.Metadata.AuthorizationID, "--name", "receipt", "--receipt-output", filepath.Join(directory, "receipt.yaml"), "--audit-output", filepath.Join(directory, "apply.audit.jsonl"))
	var stdout, stderr bytes.Buffer
	if exit := applyKubernetesDeploymentAt(args, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("broken scan chain exit=%d stdout=%s", exit, stdout.String())
	}
}

func writeExecutionInputs(t *testing.T, directory string, now time.Time) ([]string, resources.ExecutionAuthorization) {
	t.Helper()
	bundlePath := writeKubernetesBundle(t, directory)
	bundle, _ := resources.LoadDeploymentBundle(bundlePath)
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('c'), ServerVersion: "v1.35.2"}
	preflightPath := writeFreshPreflight(t, directory, bundle, target, now)
	preflight, _ := resources.LoadTargetPreflightResult(preflightPath)
	desired, _ := changeset.DesiredObjects(bundle)
	observation := changeset.Observation{Target: target}
	for _, object := range desired {
		observation.Objects = append(observation.Objects, changeset.ObjectObservation{Reference: object.Reference, Readable: true})
	}
	changeSet, err := changeset.Evaluate("reference-change-set", bundle, preflight, observation, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	changeSetPath := filepath.Join(directory, "change-set.yaml")
	writeYAMLFixture(t, changeSetPath, changeSet)
	approval := resources.DeploymentApproval{APIVersion: resources.APIVersion, Kind: "DeploymentApproval", Metadata: resources.DeploymentApprovalMetadata{Name: "reference-approval"}, Spec: resources.DeploymentApprovalSpec{Decision: "approved", Effect: "review-only", RecordedAt: now.Add(time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), PlanID: bundle.Spec.PlanID, BundleID: bundle.Metadata.BundleID, PreflightResultID: preflight.Metadata.ResultID, ChangeSetID: changeSet.Metadata.ChangeSetID, Target: target, Actor: resources.ApprovalActor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"}, Reason: resources.ApprovalReason{Type: "user-review", Reference: "ticket-123"}, Limitations: []string{"Review only."}}}
	approval, _ = approval.AssignApprovalID()
	approvalPath := filepath.Join(directory, "approval.yaml")
	writeYAMLFixture(t, approvalPath, approval)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	_, publicPath := writeAuthorizationKeys(t, directory, publicKey, privateKey)
	blockers, err := acceptedActiveVerificationBlockers(preflight)
	if err != nil {
		t.Fatal(err)
	}
	authorization := resources.ExecutionAuthorization{APIVersion: resources.APIVersion, Kind: "ExecutionAuthorization", Metadata: resources.ExecutionAuthorizationMetadata{Name: "reference-authorization"}, Spec: resources.ExecutionAuthorizationSpec{IssuedAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(12 * time.Minute).Format(time.RFC3339Nano), PlanID: bundle.Spec.PlanID, BundleID: bundle.Metadata.BundleID, PreflightResultID: preflight.Metadata.ResultID, ChangeSetID: changeSet.Metadata.ChangeSetID, ApprovalID: approval.Metadata.ApprovalID, Target: target, Issuer: resources.ExecutionAuthorizationIssuer{KeyID: "operations-key-1"}, Constraints: resources.ExecutionAuthorizationConstraints{AllowedActions: []string{"create"}, MaxOperations: len(changeSet.Spec.Operations), AllowActiveVerification: true, AcceptedPreflightBlockers: blockers}}}
	authorization, err = authorization.Sign(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	authorizationPath := filepath.Join(directory, "authorization.yaml")
	writeYAMLFixture(t, authorizationPath, authorization)
	modelArtifact := testModelArtifact(t, bundle)
	importReceipt := resources.ArtifactImportReceipt{APIVersion: resources.APIVersion, Kind: "ArtifactImportReceipt", Metadata: resources.ArtifactImportReceiptMetadata{Name: "reference-import"}, Spec: resources.ArtifactImportReceiptSpec{
		RecordedAt: now.Add(time.Minute).Format(time.RFC3339Nano), PlanID: bundle.Spec.PlanID, BundleID: bundle.Metadata.BundleID, Target: target,
		Importer: resources.ImporterIdentity{Name: "yara-importer", Version: "0.1.0"},
		Verification: resources.ImportVerificationStatus{
			DigestVerified: true,
			SizeVerified:   true,
			CompleteSet:    true,
		},
		ModelArtifacts: []resources.ImportedModelArtifact{{
			Ref:      modelArtifact.Ref,
			Revision: modelArtifact.Revision,
			Files: []resources.ImportedModelArtifactBinding{
				{Path: modelArtifact.Files[0].Path, Digest: modelArtifact.Files[0].Digest, SizeBytes: modelArtifact.Files[0].SizeBytes, InternalPath: "model/" + modelArtifact.Files[0].Path},
				{Path: modelArtifact.Files[1].Path, Digest: modelArtifact.Files[1].Digest, SizeBytes: modelArtifact.Files[1].SizeBytes, InternalPath: "model/" + modelArtifact.Files[1].Path},
			},
		}},
		Limitations: []string{"Import verification recorded before apply."},
	}}
	importReceipt, err = importReceipt.AssignImportReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	importPath := filepath.Join(directory, "import-receipt.yaml")
	writeYAMLFixture(t, importPath, importReceipt)
	transferReceipt := resources.ArtifactTransferReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "ArtifactTransferReceipt",
		Metadata: resources.ArtifactTransferReceiptMetadata{
			Name: "reference-transfer",
		},
		Spec: resources.ArtifactTransferReceiptSpec{
			RecordedAt:                now.Add(90 * time.Second).Format(time.RFC3339Nano),
			PlanID:                    bundle.Spec.PlanID,
			BundleID:                  bundle.Metadata.BundleID,
			CatalogDigest:             bundle.Spec.CatalogDigest,
			Target:                    target,
			Stage:                     "vault-to-registry",
			SourceAttestationRef:      "ticket-source",
			DestinationAttestationRef: "ticket-destination",
			PriorReceiptIDs:           []string{importReceipt.Metadata.ImportReceiptID},
			ModelArtifacts:            importReceipt.Spec.ModelArtifacts,
			Limitations:               []string{"Transfer evidence excludes secret-bearing payload metadata."},
		},
	}
	transferReceipt, err = transferReceipt.AssignTransferReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	transferPath := filepath.Join(directory, "transfer-receipt.yaml")
	writeYAMLFixture(t, transferPath, transferReceipt)
	scanReceipt := resources.ArtifactScanReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "ArtifactScanReceipt",
		Metadata: resources.ArtifactScanReceiptMetadata{
			Name: "reference-scan",
		},
		Spec: resources.ArtifactScanReceiptSpec{
			RecordedAt:      now.Add(100 * time.Second).Format(time.RFC3339Nano),
			PlanID:          bundle.Spec.PlanID,
			BundleID:        bundle.Metadata.BundleID,
			CatalogDigest:   bundle.Spec.CatalogDigest,
			Target:          target,
			Scanner:         resources.ScanToolIdentity{Name: "trivy", Version: "0.53.0", Profile: "offline-policy-default", PolicyDigest: testCLIDigest('9')},
			Verdict:         "passed",
			ReasonReference: "ticket-scan",
			PriorReceiptIDs: []string{transferReceipt.Metadata.TransferReceiptID},
			ModelArtifacts:  importReceipt.Spec.ModelArtifacts,
			Limitations:     []string{"Scan evidence excludes raw scanner output and findings payloads."},
		},
	}
	scanReceipt, err = scanReceipt.AssignScanReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	scanPath := filepath.Join(directory, "scan-receipt.yaml")
	writeYAMLFixture(t, scanPath, scanReceipt)
	return []string{"--bundle", bundlePath, "--preflight", preflightPath, "--change-set", changeSetPath, "--approval", approvalPath, "--import-receipt", importPath, "--transfer-receipt", transferPath, "--scan-receipt", scanPath, "--authorization", authorizationPath, "--public-key", publicPath}, authorization
}

func testModelArtifact(t *testing.T, bundle resources.DeploymentBundle) resources.BundleArtifact {
	t.Helper()
	for _, artifact := range bundle.Spec.Artifacts {
		if artifact.Type == "huggingface-snapshot" {
			return artifact
		}
	}
	t.Fatal("fixture bundle missing huggingface-snapshot artifact")
	return resources.BundleArtifact{}
}

func removeFlag(args []string, flag string) []string {
	result := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		if args[index] == flag {
			index++
			continue
		}
		result = append(result, args[index])
	}
	return result
}

func valueForFlag(args []string, flag string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == flag {
			return args[index+1]
		}
	}
	return ""
}
