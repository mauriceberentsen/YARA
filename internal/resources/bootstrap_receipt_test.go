package resources

import "testing"

func TestBootstrapReceiptIdentityAndDeterminism(t *testing.T) {
	first := validBootstrapReceipt(t)
	second := validBootstrapReceipt(t)
	if first.Metadata.ReceiptID != second.Metadata.ReceiptID {
		t.Fatalf("expected deterministic bootstrap receipt identity, got %q and %q", first.Metadata.ReceiptID, second.Metadata.ReceiptID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("valid bootstrap receipt rejected: %#v", report.Diagnostics)
	}
	first.Spec.StorageClass = "different-class"
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated bootstrap receipt retained identity")
	}
}

func TestBootstrapReceiptRejectsUnsafeStorageConfiguration(t *testing.T) {
	receipt := validBootstrapReceipt(t)
	receipt.Spec.Size = "0Gi"
	assertDiagnostic(t, receipt.Validate(), "YARA-BST-015", "spec.storageClass")
}

func TestBootstrapReceiptRequiresDiagnosticCodeOnFailure(t *testing.T) {
	receipt := validBootstrapReceipt(t)
	receipt.Spec.Operations[0].Outcome = "failed"
	receipt.Spec.Operations[0].DiagnosticCode = ""
	assertDiagnostic(t, receipt.Validate(), "YARA-BST-020", "spec.operations[0].diagnosticCode")
}

func validBootstrapReceipt(t *testing.T) BootstrapReceipt {
	t.Helper()
	receipt := BootstrapReceipt{
		APIVersion: APIVersion,
		Kind:       "BootstrapReceipt",
		Metadata:   BootstrapReceiptMetadata{Name: "reference-bootstrap"},
		Spec: BootstrapReceiptSpec{
			Outcome:                "succeeded",
			StartedAt:              "2026-07-20T10:00:00Z",
			CompletedAt:            "2026-07-20T10:00:10Z",
			ExecutionCorrelationID: "bootstrap-123",
			Target: TargetIdentity{
				Type:            "kubernetes",
				ReferenceDigest: testDigest('a'),
				ServerVersion:   "v1.35.6",
			},
			Namespace:    "yara-reference",
			ModelPVC:     "yara-model",
			StorageClass: "fast-ssd",
			Size:         "200Gi",
			Executor: DeploymentExecutorIdentity{
				Name:         "yara-kubernetes-executor",
				Version:      "0.1.0",
				BinaryDigest: testDigest('b'),
			},
			Operations: []BootstrapOperationReceipt{
				{
					Resource: KubernetesObjectReference{
						APIVersion: "v1",
						Kind:       "Namespace",
						Name:       "yara-reference",
					},
					Action:      "create",
					Outcome:     "created",
					AfterDigest: testDigest('c'),
				},
				{
					Resource: KubernetesObjectReference{
						APIVersion: "v1",
						Kind:       "PersistentVolumeClaim",
						Namespace:  "yara-reference",
						Name:       "yara-model",
					},
					Action:      "create",
					Outcome:     "created",
					AfterDigest: testDigest('d'),
				},
			},
			Limitations: []string{
				"Bootstrap creates only one namespace and one model PVC.",
				"Bootstrap does not import artifacts or execute deployment, retirement or rollback workflows.",
			},
		},
	}
	var err error
	receipt, err = receipt.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
