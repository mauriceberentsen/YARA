package resources

import (
	"testing"
	"time"
)

func TestArtifactScanReceiptIdentityAndValidation(t *testing.T) {
	first := validScanReceipt(t)
	second := validScanReceipt(t)
	if first.Metadata.ScanReceiptID != second.Metadata.ScanReceiptID {
		t.Fatalf("expected deterministic scan receipt identity, got %q and %q", first.Metadata.ScanReceiptID, second.Metadata.ScanReceiptID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid scan receipt: %#v", report.Diagnostics)
	}
	first.Spec.ModelArtifacts[0].Files[0].Digest = testDigest('f')
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated content retained scan receipt identity")
	}
}

func TestArtifactScanReceiptRejectsInvalidVerdict(t *testing.T) {
	receipt := validScanReceipt(t)
	receipt.Spec.Verdict = "unknown"
	assertDiagnostic(t, receipt.Validate(), "YARA-ASC-014", "spec.verdict")
}

func validScanReceipt(t *testing.T) ArtifactScanReceipt {
	t.Helper()
	receipt := ArtifactScanReceipt{
		APIVersion: APIVersion,
		Kind:       "ArtifactScanReceipt",
		Metadata: ArtifactScanReceiptMetadata{
			Name: "scan-receipt",
		},
		Spec: ArtifactScanReceiptSpec{
			RecordedAt:      time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
			PlanID:          testDigest('1'),
			BundleID:        testDigest('2'),
			CatalogDigest:   testDigest('3'),
			Target:          TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('4'), ServerVersion: "v1.35.2"},
			Scanner:         ScanToolIdentity{Name: "trivy", Version: "0.53.0", Profile: "offline-policy-default", PolicyDigest: testDigest('5')},
			Verdict:         "passed",
			ReasonReference: "ticket-scan-1001",
			PriorReceiptIDs: []string{testDigest('6')},
			ModelArtifacts: []ImportedModelArtifact{{
				Ref:      "model.qwen",
				Revision: "main",
				Files: []ImportedModelArtifactBinding{
					{Path: "config.json", Digest: testDigest('7'), SizeBytes: 1200},
					{Path: "weights.safetensors", Digest: testDigest('8'), SizeBytes: 4200},
				},
			}},
			Limitations: []string{"Scan evidence excludes raw scanner output and findings payloads."},
		},
	}
	assigned, err := receipt.AssignScanReceiptID()
	if err != nil {
		t.Fatalf("assign scan receipt identity: %v", err)
	}
	return assigned
}
