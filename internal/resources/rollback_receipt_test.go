package resources

import (
	"testing"
	"time"
)

func TestRollbackReceiptIdentityAndDerivedOutcome(t *testing.T) {
	receipt := validRollbackReceipt(t)
	if report := receipt.Validate(); !report.Valid {
		t.Fatalf("valid rollback receipt rejected: %#v", report.Diagnostics)
	}
	receipt.Metadata.ReceiptID = ""
	receipt.Spec.Outcome = "succeeded"
	receipt.Spec.Operations[0].Outcome = "skipped"
	assertDiagnostic(t, receipt.Validate(), "YARA-RBK-018", "spec.outcome")
}

func TestRollbackReceiptRejectsUnsupportedAction(t *testing.T) {
	receipt := validRollbackReceipt(t)
	receipt.Spec.Operations[0].Action = "delete"
	assertDiagnostic(t, receipt.Validate(), "YARA-RBK-015", "spec.operations[0]")
}

func validRollbackReceipt(t *testing.T) RollbackReceipt {
	t.Helper()
	now := time.Now().UTC()
	receipt := RollbackReceipt{
		APIVersion: APIVersion,
		Kind:       "RollbackReceipt",
		Metadata: RollbackReceiptMetadata{
			Name: "rollback",
		},
		Spec: RollbackReceiptSpec{
			Outcome:                "succeeded",
			StartedAt:              now.Format(time.RFC3339Nano),
			CompletedAt:            now.Add(time.Minute).Format(time.RFC3339Nano),
			ExecutionCorrelationID: "rollback-1",
			PlanID:                 testDigest('a'),
			BundleID:               testDigest('b'),
			PreflightResultID:      testDigest('c'),
			ChangeSetID:            testDigest('d'),
			ApprovalID:             testDigest('e'),
			AuthorizationID:        testDigest('f'),
			Target: TargetIdentity{
				Type:            "kubernetes",
				ReferenceDigest: testDigest('0'),
				ServerVersion:   "v1.35.6",
			},
			Executor: DeploymentExecutorIdentity{
				Name:         "yara-kubernetes-executor",
				Version:      "0.1.0",
				BinaryDigest: testDigest('1'),
			},
			Operations: []RollbackOperationReceipt{{
				Resource: KubernetesObjectReference{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Namespace:  "reference-stack",
					Name:       "gateway",
				},
				Action:       "update",
				Outcome:      "reverted",
				BeforeDigest: testDigest('2'),
				AfterDigest:  testDigest('3'),
			}},
			Limitations: []string{"Rollback does not prune unmanaged resources."},
		},
	}
	var err error
	receipt, err = receipt.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
