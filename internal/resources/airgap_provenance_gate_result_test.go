package resources

import (
	"testing"
	"time"
)

func TestAirgapProvenanceGateResultIdentityAndValidation(t *testing.T) {
	first := validAirgapGateResult(t)
	second := validAirgapGateResult(t)
	if first.Metadata.GateResultID != second.Metadata.GateResultID {
		t.Fatalf("expected deterministic gate-result identity, got %q and %q", first.Metadata.GateResultID, second.Metadata.GateResultID)
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("expected valid gate result: %#v", report.Diagnostics)
	}
	first.Spec.Gates[1].Status = "failed"
	first.Spec.Gates[1].Blocker = "scan-failed"
	if report := first.Validate(); report.Valid {
		t.Fatal("mutated content retained gate-result identity")
	}
}

func TestAirgapProvenanceGateResultRejectsUnsortedScanReceipts(t *testing.T) {
	result := validAirgapGateResult(t)
	result.Spec.ScanReceiptIDs = []string{testDigest('3'), testDigest('2')}
	assertDiagnostic(t, result.Validate(), "YARA-AGP-014", "spec.scanReceiptIds")
}

func validAirgapGateResult(t *testing.T) AirgapProvenanceGateResult {
	t.Helper()
	result := AirgapProvenanceGateResult{
		APIVersion: APIVersion,
		Kind:       "AirgapProvenanceGateResult",
		Metadata: AirgapProvenanceGateResultMetadata{
			Name: "airgap-gate-result",
		},
		Spec: AirgapProvenanceGateResultSpec{
			RecordedAt:         time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
			PlanID:             testDigest('a'),
			BundleID:           testDigest('b'),
			CatalogDigest:      testDigest('c'),
			Target:             TargetIdentity{Type: "kubernetes", ReferenceDigest: testDigest('d'), ServerVersion: "v1.35.2"},
			ImportReceiptID:    testDigest('e'),
			TransferReceiptIDs: []string{testDigest('1')},
			ScanReceiptIDs:     []string{testDigest('2')},
			Gates: []ProvenanceGateEvaluation{
				{ID: "scan-chain", Status: "passed"},
				{ID: "transfer-chain", Status: "passed"},
			},
			Outcome:         "passed",
			ReasonReference: "ticket-airgap-gate",
			Limitations: []string{
				"Gate result remains bounded to immutable receipt identities and offline policy inputs.",
			},
		},
	}
	assigned, err := result.AssignGateResultID()
	if err != nil {
		t.Fatalf("assign gate result identity: %v", err)
	}
	return assigned
}
