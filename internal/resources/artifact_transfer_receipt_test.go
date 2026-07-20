package resources

import (
	"testing"
	"time"
)

func TestArtifactTransferReceiptIdentityAndValidation(t *testing.T) {
	first := validTransferReceipt(t)
	second := validTransferReceipt(t)
	if first.Metadata.TransferReceiptID != second.Metadata.TransferReceiptID {
		t.Fatalf("expected deterministic transfer receipt identity, got %q and %q", first.Metadata.TransferReceiptID, second.Metadata.TransferReceiptID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid transfer receipt: %#v", report.Diagnostics)
	}
	first.Spec.ModelArtifacts[0].Files[0].Digest = testDigest('f')
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated content retained transfer receipt identity")
	}
}

func TestArtifactTransferReceiptRejectsUnsortedPriorReceipts(t *testing.T) {
	receipt := validTransferReceipt(t)
	receipt.Spec.PriorReceiptIDs = []string{testDigest('b'), testDigest('a')}
	assertDiagnostic(t, receipt.Validate(), "YARA-ATR-015", "spec.priorReceiptIds")
}

func validTransferReceipt(t *testing.T) ArtifactTransferReceipt {
	t.Helper()
	receipt := ArtifactTransferReceipt{
		APIVersion: APIVersion,
		Kind:       "ArtifactTransferReceipt",
		Metadata: ArtifactTransferReceiptMetadata{
			Name: "transfer-receipt",
		},
		Spec: ArtifactTransferReceiptSpec{
			RecordedAt:                time.Date(2026, 7, 20, 8, 30, 0, 0, time.UTC).Format(time.RFC3339Nano),
			PlanID:                    testDigest('1'),
			BundleID:                  testDigest('2'),
			CatalogDigest:             testDigest('3'),
			Target:                    TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('4'), ServerVersion: "v1.35.2"},
			Stage:                     "vault-to-registry",
			SourceAttestationRef:      "ticket-stage-source",
			DestinationAttestationRef: "ticket-stage-destination",
			PriorReceiptIDs:           []string{testDigest('5')},
			ModelArtifacts: []ImportedModelArtifact{{
				Ref:      "model.qwen",
				Revision: "main",
				Files: []ImportedModelArtifactBinding{
					{Path: "config.json", Digest: testDigest('6'), SizeBytes: 1200},
					{Path: "weights.safetensors", Digest: testDigest('7'), SizeBytes: 4200},
				},
			}},
			Limitations: []string{"Transfer evidence excludes secret-bearing payload metadata."},
		},
	}
	assigned, err := receipt.AssignTransferReceiptID()
	if err != nil {
		t.Fatalf("assign transfer receipt identity: %v", err)
	}
	return assigned
}
