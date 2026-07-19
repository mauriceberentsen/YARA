package resources

import (
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
)

func TestKubernetesChangeSetIdentityAndDerivedOutcome(t *testing.T) {
	result := validChangeSet(t)
	if report := result.Validate(); !report.Valid {
		t.Fatalf("valid change set rejected: %#v", report.Diagnostics)
	}
	result.Spec.Operations[0].DesiredDigest = testDigest('f')
	assertDiagnostic(t, result.Validate(), "YARA-CHG-023", "metadata.changeSetId")
	result = validChangeSet(t)
	result.Metadata.ChangeSetID = ""
	result.Spec.Outcome = "review-required"
	assertDiagnostic(t, result.Validate(), "YARA-CHG-021", "spec.outcome")
}

func TestDeploymentApprovalRejectsExecutionAuthorizationWithoutVerifiableEnvelope(t *testing.T) {
	approval := validApproval(t)
	if report := approval.Validate(); !report.Valid {
		t.Fatalf("valid approval rejected: %#v", report.Diagnostics)
	}
	approval.Metadata.ApprovalID = ""
	approval.Spec.Effect = "execution-authorized"
	approval.Spec.Actor.Assurance = "hardware-backed"
	assertDiagnostic(t, approval.Validate(), "YARA-APR-014", "spec.effect")
}

func TestDeploymentReceiptIdentityAndDerivedOutcome(t *testing.T) {
	receipt := validReceipt(t)
	if report := receipt.Validate(); !report.Valid {
		t.Fatalf("valid receipt rejected: %#v", report.Diagnostics)
	}
	receipt.Metadata.ReceiptID = ""
	receipt.Spec.Outcome = "succeeded"
	receipt.Spec.Postflight[0].Status = "blocked"
	receipt.Spec.Postflight[0].DiagnosticCode = "YARA-RCP-101"
	assertDiagnostic(t, receipt.Validate(), "YARA-RCP-020", "spec.outcome")
}

func validChangeSet(t *testing.T) KubernetesChangeSet {
	t.Helper()
	result := KubernetesChangeSet{APIVersion: APIVersion, Kind: "KubernetesChangeSet", Metadata: KubernetesChangeSetMetadata{Name: "change-set"}, Spec: KubernetesChangeSetSpec{
		Outcome: "blocked", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), BundleID: testDigest('a'), PlanID: testDigest('b'), PreflightResultID: testDigest('c'),
		Observer: TargetPreflightObserver{Name: "observer", Version: "0.1.0", Mode: "read-only"}, Target: TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('d'), ServerVersion: "v1.35.2"},
		Summary: KubernetesChangeSummary{Conflicts: 1}, Operations: []KubernetesChangeOperation{{Resource: KubernetesObjectReference{APIVersion: "v1", Kind: "Namespace", Name: "example"}, Action: "conflict", Ownership: "foreign", DesiredDigest: testDigest('e'), CurrentDigest: testDigest('f'), RiskClasses: []string{"namespace"}, DiagnosticCode: "YARA-CHG-102"}}, Limitations: []string{"No mutation."},
	}}
	var err error
	result, err = result.AssignChangeSetID()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func validApproval(t *testing.T) DeploymentApproval {
	t.Helper()
	now := time.Now().UTC()
	result := DeploymentApproval{APIVersion: APIVersion, Kind: "DeploymentApproval", Metadata: DeploymentApprovalMetadata{Name: "approval"}, Spec: DeploymentApprovalSpec{
		Decision: "approved", Effect: "review-only", RecordedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), PlanID: testDigest('a'), BundleID: testDigest('b'), PreflightResultID: testDigest('c'), ChangeSetID: testDigest('d'), Target: TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('e'), ServerVersion: "v1.35.2"}, Actor: ApprovalActor{ID: "local:user", Type: "user", Assurance: "self-asserted-local"}, Reason: ApprovalReason{Type: "user-review", Reference: "ticket-1"}, Limitations: []string{"Review only."},
	}}
	var err error
	result, err = result.AssignApprovalID()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func validReceipt(t *testing.T) DeploymentReceipt {
	t.Helper()
	now := time.Now().UTC()
	evidence, _ := canonical.Digest(struct {
		Passed bool `json:"passed"`
	}{true})
	result := DeploymentReceipt{APIVersion: APIVersion, Kind: "DeploymentReceipt", Metadata: DeploymentReceiptMetadata{Name: "receipt"}, Spec: DeploymentReceiptSpec{
		Outcome: "succeeded", StartedAt: now.Format(time.RFC3339Nano), CompletedAt: now.Add(time.Minute).Format(time.RFC3339Nano), ExecutionCorrelationID: "execution-1", PlanID: testDigest('a'), BundleID: testDigest('b'), PreflightResultID: testDigest('c'), ChangeSetID: testDigest('d'), ApprovalID: testDigest('e'), Target: TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('f'), ServerVersion: "v1.35.2"}, Executor: DeploymentExecutorIdentity{Name: "executor", Version: "0.1.0", BinaryDigest: testDigest('a')}, Operations: []DeploymentOperationReceipt{{Resource: KubernetesObjectReference{APIVersion: "v1", Kind: "Namespace", Name: "example"}, Action: "create", Outcome: "applied", AfterDigest: testDigest('b')}}, Postflight: []DeploymentPostflightCheck{{ID: "namespace.exists", Status: "passed", EvidenceDigest: evidence}}, Limitations: []string{"Example."},
	}}
	var err error
	result, err = result.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testDigest(character byte) string { return "sha256:" + stringRepeat(character, 64) }
func stringRepeat(character byte, count int) string {
	value := make([]byte, count)
	for index := range value {
		value[index] = character
	}
	return string(value)
}
