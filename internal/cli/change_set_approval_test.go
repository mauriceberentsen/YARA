package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/targetpreflight"
	"gopkg.in/yaml.v3"
)

type fixedChangeSetObserver struct {
	observation changeset.Observation
	err         error
}

func (o fixedChangeSetObserver) Observe(_ context.Context, _ []changeset.DesiredObject, _ string) (changeset.Observation, error) {
	return o.observation, o.err
}

func TestChangeSetAndLocalReviewApprovalAreAuditedAndBound(t *testing.T) {
	directory := t.TempDir()
	bundlePath := writeKubernetesBundle(t, directory)
	bundle, err := resources.LoadDeploymentBundle(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('c'), ServerVersion: "v1.35.2"}
	baseTime := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	preflightPath := writeFreshPreflight(t, directory, bundle, target, baseTime)
	changeSetPath, changeAuditPath := filepath.Join(directory, "change-set.yaml"), filepath.Join(directory, "change-set.audit.jsonl")
	factory := func(kubeconfig, contextName string) (changeset.Observer, error) {
		if kubeconfig != "/private/admin.conf" || contextName != "production-admin" {
			t.Fatalf("ephemeral target options not forwarded")
		}
		desired, _ := changeset.DesiredObjects(bundle)
		observation := changeset.Observation{Target: target}
		for _, object := range desired {
			observation.Objects = append(observation.Objects, changeset.ObjectObservation{Reference: object.Reference, Readable: true})
		}
		return fixedChangeSetObserver{observation: observation}, nil
	}
	args := []string{"--bundle", bundlePath, "--preflight", preflightPath, "--name", "reference-change-set", "--output", changeSetPath, "--audit-output", changeAuditPath, "--kubeconfig", "/private/admin.conf", "--context", "production-admin"}
	var stdout, stderr bytes.Buffer
	if exit := runKubernetesChangeSet(args, &stdout, &stderr, factory, func() time.Time { return baseTime.Add(time.Minute) }); exit != ExitSuccess {
		t.Fatalf("change set failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	changeSet, err := resources.LoadKubernetesChangeSet(changeSetPath)
	if err != nil {
		t.Fatal(err)
	}
	if changeSet.Spec.Summary.Creates != 12 || changeSet.Spec.Outcome != "review-required" {
		t.Fatalf("unexpected change set: %#v", changeSet.Spec.Summary)
	}
	changeEvents, err := audit.LoadJSONL(changeAuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(changeEvents); err != nil {
		t.Fatal(err)
	}
	terminal := changeEvents[len(changeEvents)-1]
	if terminal.Spec.Action != "target.kubernetes-changeset.completed" || len(terminal.Spec.Subjects) != 4 || terminal.Spec.Subjects[3].Digest != changeSet.Metadata.ChangeSetID {
		t.Fatalf("unexpected audit: %#v", terminal.Spec)
	}

	approvalPath, approvalAuditPath := filepath.Join(directory, "approval.yaml"), filepath.Join(directory, "approval.audit.jsonl")
	stdout.Reset()
	stderr.Reset()
	approvalArgs := []string{"--bundle", bundlePath, "--preflight", preflightPath, "--change-set", changeSetPath, "--name", "reference-approval", "--decision", "approve", "--reason-reference", "ticket-123", "--output", approvalPath, "--audit-output", approvalAuditPath}
	if exit := recordDeploymentApprovalAt(approvalArgs, &stdout, &stderr, func() time.Time { return baseTime.Add(2 * time.Minute) }); exit != ExitSuccess {
		t.Fatalf("approval failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	approval, err := resources.LoadDeploymentApproval(approvalPath)
	if err != nil {
		t.Fatal(err)
	}
	if approval.Spec.Decision != "approved" || approval.Spec.Effect != "review-only" || approval.Spec.Actor.Assurance != "self-asserted-local" {
		t.Fatalf("local approval overstated authority: %#v", approval.Spec)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"approval", "validate", approvalPath}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("validate approval: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	approvalEvents, err := audit.LoadJSONL(approvalAuditPath)
	if err != nil {
		t.Fatal(err)
	}
	approvalTerminal := approvalEvents[len(approvalEvents)-1]
	if approvalTerminal.Spec.Action != "approval.record.completed" || len(approvalTerminal.Spec.Subjects) != 4 || approvalTerminal.Spec.Subjects[3].Digest != approval.Metadata.ApprovalID {
		t.Fatalf("unexpected approval audit: %#v", approvalTerminal.Spec)
	}
	failedApprovalPath, failedAuditPath := filepath.Join(directory, "failed-approval.yaml"), filepath.Join(directory, "approval-audit-collision")
	if err := os.Mkdir(failedAuditPath, 0o700); err != nil {
		t.Fatal(err)
	}
	failedArgs := append([]string(nil), approvalArgs...)
	for index := range failedArgs {
		if failedArgs[index] == approvalPath {
			failedArgs[index] = failedApprovalPath
		} else if failedArgs[index] == approvalAuditPath {
			failedArgs[index] = failedAuditPath
		}
	}
	stdout.Reset()
	stderr.Reset()
	_ = recordDeploymentApprovalAt(failedArgs, &stdout, &stderr, func() time.Time { return baseTime.Add(3 * time.Minute) })
	if _, err := os.Stat(failedApprovalPath); !os.IsNotExist(err) {
		t.Fatalf("approval survived mandatory audit failure: %v", err)
	}
	durable := string(mustReadFile(t, changeSetPath)) + string(mustReadFile(t, changeAuditPath)) + string(mustReadFile(t, approvalPath)) + string(mustReadFile(t, approvalAuditPath))
	for _, forbidden := range []string{"/private/admin.conf", "production-admin", "cluster.internal"} {
		if strings.Contains(durable, forbidden) {
			t.Fatalf("durable evidence leaked %q", forbidden)
		}
	}
}

func TestReceiptValidationIsValidationOnly(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	evidence, err := canonical.Digest(struct {
		Passed bool `json:"passed"`
	}{Passed: true})
	if err != nil {
		t.Fatal(err)
	}
	receipt := resources.DeploymentReceipt{
		APIVersion: resources.APIVersion, Kind: "DeploymentReceipt", Metadata: resources.DeploymentReceiptMetadata{Name: "external-receipt"},
		Spec: resources.DeploymentReceiptSpec{
			Outcome: "succeeded", StartedAt: now.Format(time.RFC3339Nano), CompletedAt: now.Add(time.Minute).Format(time.RFC3339Nano), ExecutionCorrelationID: "external-execution-1",
			PlanID: testCLIDigest('a'), BundleID: testCLIDigest('b'), PreflightResultID: testCLIDigest('c'), ChangeSetID: testCLIDigest('d'), ApprovalID: testCLIDigest('e'), AuthorizationID: testCLIDigest('f'),
			Target:     resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('f'), ServerVersion: "v1.35.2"},
			Executor:   resources.DeploymentExecutorIdentity{Name: "external-executor", Version: "0.1.0", BinaryDigest: testCLIDigest('a')},
			Operations: []resources.DeploymentOperationReceipt{{Resource: resources.KubernetesObjectReference{APIVersion: "v1", Kind: "Namespace", Name: "reference-stack"}, Action: "create", Outcome: "applied", AfterDigest: testCLIDigest('b')}},
			Postflight: []resources.DeploymentPostflightCheck{{ID: "namespace.exists", Status: "passed", EvidenceDigest: evidence}}, Limitations: []string{"Externally supplied fixture."},
		},
	}
	receipt, err = receipt.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := yaml.Marshal(receipt)
	path, auditPath := filepath.Join(directory, "receipt.yaml"), filepath.Join(directory, "receipt-validation.audit.jsonl")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"receipt", "validate", path, "--audit-output", auditPath}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("validate receipt: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "deployment.receipt.validate.completed" || terminal.Spec.Subjects[0].Digest != receipt.Metadata.ReceiptID {
		t.Fatalf("receipt validation was misclassified: %#v", terminal.Spec)
	}
}

func TestChangeSetRollsBackWhenAuditFails(t *testing.T) {
	directory := t.TempDir()
	bundlePath := writeKubernetesBundle(t, directory)
	bundle, _ := resources.LoadDeploymentBundle(bundlePath)
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('c'), ServerVersion: "v1.35.2"}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	preflightPath := writeFreshPreflight(t, directory, bundle, target, now)
	outputPath, auditPath := filepath.Join(directory, "change-set.yaml"), filepath.Join(directory, "audit-collision")
	if err := os.Mkdir(auditPath, 0o700); err != nil {
		t.Fatal(err)
	}
	desired, _ := changeset.DesiredObjects(bundle)
	observation := changeset.Observation{Target: target}
	for _, object := range desired {
		observation.Objects = append(observation.Objects, changeset.ObjectObservation{Reference: object.Reference, Readable: true})
	}
	factory := func(_, _ string) (changeset.Observer, error) {
		return fixedChangeSetObserver{observation: observation}, nil
	}
	args := []string{"--bundle", bundlePath, "--preflight", preflightPath, "--name", "reference-change-set", "--output", outputPath, "--audit-output", auditPath}
	var stdout, stderr bytes.Buffer
	_ = runKubernetesChangeSet(args, &stdout, &stderr, factory, func() time.Time { return now.Add(time.Minute) })
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("change set survived mandatory audit failure: %v", err)
	}
}

func TestChangeSetRejectsStalePreflightBeforeObservation(t *testing.T) {
	directory := t.TempDir()
	bundlePath := writeKubernetesBundle(t, directory)
	bundle, _ := resources.LoadDeploymentBundle(bundlePath)
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('c'), ServerVersion: "v1.35.2"}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	preflightPath := writeFreshPreflight(t, directory, bundle, target, now)
	called := false
	factory := func(_, _ string) (changeset.Observer, error) { called = true; return fixedChangeSetObserver{}, nil }
	args := []string{"--bundle", bundlePath, "--preflight", preflightPath, "--name", "reference-change-set", "--output", filepath.Join(directory, "change-set.yaml"), "--audit-output", filepath.Join(directory, "change.audit.jsonl")}
	var stdout, stderr bytes.Buffer
	if exit := runKubernetesChangeSet(args, &stdout, &stderr, factory, func() time.Time { return now.Add(16 * time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("unexpected exit %d", exit)
	}
	if called {
		t.Fatal("stale preflight contacted target")
	}
}

func writeFreshPreflight(t *testing.T, directory string, bundle resources.DeploymentBundle, target resources.TargetIdentity, observedAt time.Time) string {
	t.Helper()
	observation := targetpreflight.Observation{ReferenceDigest: target.ReferenceDigest, ServerVersion: target.ServerVersion, CoreV1: true, AppsV1: true, NetworkingV1: true, NodesReadable: true, GPUCount: 1, DNSReadable: true, DNSPodCount: 1, NamespaceReadable: true, PVCReadable: true, PVCExists: true, PVCPhase: "Bound"}
	result, err := targetpreflight.Evaluate("reference-preflight", bundle, observation, observedAt)
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "preflight.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testCLIDigest(character byte) string {
	value := make([]byte, 64)
	for index := range value {
		value[index] = character
	}
	return "sha256:" + string(value)
}
