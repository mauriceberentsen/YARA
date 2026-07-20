package resources

import (
	"testing"
	"time"
)

func TestRetirementReceiptIdentityAndDerivedOutcome(t *testing.T) {
	receipt := validRetirementReceipt(t)
	if report := receipt.Validate(); !report.Valid {
		t.Fatalf("valid retirement receipt rejected: %#v", report.Diagnostics)
	}
	receipt.Metadata.ReceiptID = ""
	receipt.Spec.Outcome = "succeeded"
	receipt.Spec.Operations[0].Outcome = "skipped"
	assertDiagnostic(t, receipt.Validate(), "YARA-RTR-018", "spec.outcome")
}

func TestRetirementReceiptRejectsUnsupportedAction(t *testing.T) {
	receipt := validRetirementReceipt(t)
	receipt.Spec.Operations[0].Action = "update"
	assertDiagnostic(t, receipt.Validate(), "YARA-RTR-015", "spec.operations[0]")
}

func validRetirementReceipt(t *testing.T) RetirementReceipt {
	t.Helper()
	now := time.Now().UTC()
	receipt := RetirementReceipt{
		APIVersion: APIVersion,
		Kind:       "RetirementReceipt",
		Metadata: RetirementReceiptMetadata{
			Name: "retirement",
		},
		Spec: RetirementReceiptSpec{
			Outcome:                "succeeded",
			StartedAt:              now.Format(time.RFC3339Nano),
			CompletedAt:            now.Add(time.Minute).Format(time.RFC3339Nano),
			ExecutionCorrelationID: "retire-1",
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
			Operations: []RetirementOperationReceipt{{
				Resource: KubernetesObjectReference{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Namespace:  "reference-stack",
					Name:       "gateway",
				},
				Action:       "delete",
				Outcome:      "deleted",
				BeforeDigest: testDigest('2'),
			}},
			Limitations: []string{"Retirement does not prune unmanaged resources."},
		},
	}
	var err error
	receipt, err = receipt.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
