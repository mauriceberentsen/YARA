package resources

import "testing"

func TestArtifactImportReceiptIdentityAndDeterminism(t *testing.T) {
	first := validArtifactImportReceipt(t)
	second := validArtifactImportReceipt(t)
	if first.Metadata.ImportReceiptID != second.Metadata.ImportReceiptID {
		t.Fatalf("expected deterministic import receipt identity, got %q and %q", first.Metadata.ImportReceiptID, second.Metadata.ImportReceiptID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("valid import receipt rejected: %#v", report.Diagnostics)
	}
	first.Spec.ModelArtifacts[0].Files[0].InternalPath = "model/changed.safetensors"
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated import receipt retained identity")
	}
}

func TestArtifactImportReceiptRejectsUnsafeInternalPath(t *testing.T) {
	receipt := validArtifactImportReceipt(t)
	receipt.Spec.ModelArtifacts[0].Files[0].InternalPath = "../outside.bin"
	assertDiagnostic(t, receipt.Validate(), "YARA-AIR-017", "spec.modelArtifacts[0].files[0]")
}

func TestArtifactImportReceiptRequiresCompleteVerification(t *testing.T) {
	receipt := validArtifactImportReceipt(t)
	receipt.Spec.Verification.CompleteSet = false
	assertDiagnostic(t, receipt.Validate(), "YARA-AIR-014", "spec.verification")
}

func validArtifactImportReceipt(t *testing.T) ArtifactImportReceipt {
	t.Helper()
	receipt := ArtifactImportReceipt{
		APIVersion: APIVersion,
		Kind:       "ArtifactImportReceipt",
		Metadata:   ArtifactImportReceiptMetadata{Name: "reference-import"},
		Spec: ArtifactImportReceiptSpec{
			RecordedAt: "2026-07-20T09:00:00Z",
			PlanID:     testDigest('a'),
			BundleID:   testDigest('b'),
			Target: TargetIdentity{
				Type:            "kubernetes",
				ReferenceDigest: testDigest('c'),
				ServerVersion:   "v1.35.6",
			},
			Importer: ImporterIdentity{
				Name:    "yara-importer",
				Version: "0.1.0",
			},
			Verification: ImportVerificationStatus{
				DigestVerified: true,
				SizeVerified:   true,
				CompleteSet:    true,
			},
			ModelArtifacts: []ImportedModelArtifact{{
				Ref:      "Qwen/Qwen2.5-Coder-7B-Instruct-AWQ",
				Revision: "8e8ed24",
				Files: []ImportedModelArtifactBinding{
					{
						Path:         "model-00001-of-00002.safetensors",
						Digest:       testDigest('d'),
						SizeBytes:    1024,
						InternalPath: "model/model-00001-of-00002.safetensors",
					},
					{
						Path:         "model-00002-of-00002.safetensors",
						Digest:       testDigest('e'),
						SizeBytes:    2048,
						InternalPath: "model/model-00002-of-00002.safetensors",
					},
				},
			}},
			Limitations: []string{
				"Import receipt proves exact model-file placement only for this run.",
			},
		},
	}
	var err error
	receipt, err = receipt.AssignImportReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
