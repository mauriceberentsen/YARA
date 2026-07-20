package resources

import (
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type AirgapProvenanceGateResult struct {
	APIVersion string                             `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                             `json:"kind" yaml:"kind"`
	Metadata   AirgapProvenanceGateResultMetadata `json:"metadata" yaml:"metadata"`
	Spec       AirgapProvenanceGateResultSpec     `json:"spec" yaml:"spec"`
}

type AirgapProvenanceGateResultMetadata struct {
	Name         string `json:"name" yaml:"name"`
	GateResultID string `json:"gateResultId" yaml:"gateResultId"`
}

type AirgapProvenanceGateResultSpec struct {
	RecordedAt         string                     `json:"recordedAt" yaml:"recordedAt"`
	PlanID             string                     `json:"planId" yaml:"planId"`
	BundleID           string                     `json:"bundleId" yaml:"bundleId"`
	CatalogDigest      string                     `json:"catalogDigest" yaml:"catalogDigest"`
	Target             TargetIdentity             `json:"target" yaml:"target"`
	ImportReceiptID    string                     `json:"importReceiptId" yaml:"importReceiptId"`
	TransferReceiptIDs []string                   `json:"transferReceiptIds" yaml:"transferReceiptIds"`
	ScanReceiptIDs     []string                   `json:"scanReceiptIds" yaml:"scanReceiptIds"`
	Gates              []ProvenanceGateEvaluation `json:"gates" yaml:"gates"`
	Outcome            string                     `json:"outcome" yaml:"outcome"`
	ReasonReference    string                     `json:"reasonReference" yaml:"reasonReference"`
	Limitations        []string                   `json:"limitations" yaml:"limitations"`
}

type ProvenanceGateEvaluation struct {
	ID      string `json:"id" yaml:"id"`
	Status  string `json:"status" yaml:"status"`
	Blocker string `json:"blocker,omitempty" yaml:"blocker,omitempty"`
}

func (r AirgapProvenanceGateResult) AssignGateResultID() (AirgapProvenanceGateResult, error) {
	r.Metadata.GateResultID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return AirgapProvenanceGateResult{}, fmt.Errorf("digest airgap provenance gate result: %w", err)
	}
	r.Metadata.GateResultID = digest
	return r, nil
}

func (r AirgapProvenanceGateResult) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "AirgapProvenanceGateResult", "AGP", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.gateResultId":       r.Metadata.GateResultID,
		"spec.planId":                 r.Spec.PlanID,
		"spec.bundleId":               r.Spec.BundleID,
		"spec.catalogDigest":          r.Spec.CatalogDigest,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
		"spec.importReceiptId":        r.Spec.ImportReceiptID,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-AGP-010", "Gate-result bindings must be SHA-256 digests.", path))
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-AGP-011", "RecordedAt must be a valid RFC3339 timestamp.", "spec.recordedAt"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" {
		items = append(items, diagnostics.Error("YARA-AGP-012", "A complete Kubernetes target identity is required.", "spec.target"))
	}
	for index, path := range [][]string{r.Spec.TransferReceiptIDs, r.Spec.ScanReceiptIDs} {
		field := "spec.transferReceiptIds"
		code := "YARA-AGP-013"
		if index == 1 {
			field = "spec.scanReceiptIds"
			code = "YARA-AGP-014"
		}
		if len(path) == 0 || !slices.IsSorted(path) || hasDuplicateStrings(path) {
			items = append(items, diagnostics.Error(code, "Gate result receipt IDs must be non-empty, unique and sorted.", field))
		}
		for receiptIndex, value := range path {
			if !sha256DigestPattern.MatchString(value) {
				items = append(items, diagnostics.Error(code, "Gate result receipt IDs must be SHA-256 digests.", fmt.Sprintf("%s[%d]", field, receiptIndex)))
			}
		}
	}
	if len(r.Spec.Gates) == 0 {
		items = append(items, diagnostics.Error("YARA-AGP-015", "At least one provenance gate evaluation is required.", "spec.gates"))
	}
	previousGateID := ""
	derived := "passed"
	for index, gate := range r.Spec.Gates {
		path := fmt.Sprintf("spec.gates[%d]", index)
		if gate.ID == "" || gate.ID <= previousGateID || !slices.Contains([]string{"passed", "failed", "blocked"}, gate.Status) {
			items = append(items, diagnostics.Error("YARA-AGP-016", "Gate evaluations must be complete, unique and sorted.", path))
		}
		if gate.Status != "passed" {
			if gate.Blocker == "" {
				items = append(items, diagnostics.Error("YARA-AGP-017", "Non-passing gates require a blocker reference.", path+".blocker"))
			}
			if derived == "passed" {
				derived = gate.Status
			}
		}
		previousGateID = gate.ID
	}
	if !slices.Contains([]string{"passed", "failed", "blocked"}, r.Spec.Outcome) || r.Spec.Outcome != derived {
		items = append(items, diagnostics.Error("YARA-AGP-018", "Outcome must match derived gate statuses.", "spec.outcome"))
	}
	if r.Spec.ReasonReference == "" {
		items = append(items, diagnostics.Error("YARA-AGP-019", "A non-secret reason reference is required.", "spec.reasonReference"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-AGP-020", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.GateResultID != "" {
		claimed := r.Metadata.GateResultID
		recomputed, err := r.AssignGateResultID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-AGP-500", "Could not recompute airgap-provenance-gate-result identity."))
		} else if recomputed.Metadata.GateResultID != claimed {
			items = append(items, diagnostics.Error("YARA-AGP-021", "Gate result contents do not match metadata.gateResultId.", "metadata.gateResultId"))
		}
	}
	return diagnostics.NewReport(items...)
}
