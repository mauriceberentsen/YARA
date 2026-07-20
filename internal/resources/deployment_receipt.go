package resources

import (
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// DeploymentReceipt describes an executor outcome and binds the complete
// authorization chain used for the mutation.
type DeploymentReceipt struct {
	APIVersion string                    `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                    `json:"kind" yaml:"kind"`
	Metadata   DeploymentReceiptMetadata `json:"metadata" yaml:"metadata"`
	Spec       DeploymentReceiptSpec     `json:"spec" yaml:"spec"`
}

type DeploymentReceiptMetadata struct {
	Name      string `json:"name" yaml:"name"`
	ReceiptID string `json:"receiptId" yaml:"receiptId"`
}

type DeploymentReceiptSpec struct {
	Outcome                 string                       `json:"outcome" yaml:"outcome"`
	StartedAt               string                       `json:"startedAt" yaml:"startedAt"`
	CompletedAt             string                       `json:"completedAt" yaml:"completedAt"`
	ExecutionCorrelationID  string                       `json:"executionCorrelationId" yaml:"executionCorrelationId"`
	PlanID                  string                       `json:"planId" yaml:"planId"`
	BundleID                string                       `json:"bundleId" yaml:"bundleId"`
	PreflightResultID       string                       `json:"preflightResultId" yaml:"preflightResultId"`
	ChangeSetID             string                       `json:"changeSetId" yaml:"changeSetId"`
	ApprovalID              string                       `json:"approvalId" yaml:"approvalId"`
	AuthorizationID         string                       `json:"authorizationId" yaml:"authorizationId"`
	ImportReceiptID         string                       `json:"importReceiptId" yaml:"importReceiptId"`
	TransferReceiptIDs      []string                     `json:"transferReceiptIds,omitempty" yaml:"transferReceiptIds,omitempty"`
	ScanReceiptIDs          []string                     `json:"scanReceiptIds,omitempty" yaml:"scanReceiptIds,omitempty"`
	AirgapGateResultID      string                       `json:"airgapGateResultId,omitempty" yaml:"airgapGateResultId,omitempty"`
	AirgapGateTrustPolicyID string                       `json:"airgapGateTrustPolicyId,omitempty" yaml:"airgapGateTrustPolicyId,omitempty"`
	Target                  TargetIdentity               `json:"target" yaml:"target"`
	Executor                DeploymentExecutorIdentity   `json:"executor" yaml:"executor"`
	Operations              []DeploymentOperationReceipt `json:"operations" yaml:"operations"`
	Postflight              []DeploymentPostflightCheck  `json:"postflight" yaml:"postflight"`
	Limitations             []string                     `json:"limitations" yaml:"limitations"`
}

type DeploymentExecutorIdentity struct {
	Name         string `json:"name" yaml:"name"`
	Version      string `json:"version" yaml:"version"`
	BinaryDigest string `json:"binaryDigest" yaml:"binaryDigest"`
}

type DeploymentOperationReceipt struct {
	Resource       KubernetesObjectReference `json:"resource" yaml:"resource"`
	Action         string                    `json:"action" yaml:"action"`
	Outcome        string                    `json:"outcome" yaml:"outcome"`
	BeforeDigest   string                    `json:"beforeDigest,omitempty" yaml:"beforeDigest,omitempty"`
	AfterDigest    string                    `json:"afterDigest,omitempty" yaml:"afterDigest,omitempty"`
	DiagnosticCode string                    `json:"diagnosticCode,omitempty" yaml:"diagnosticCode,omitempty"`
}

type DeploymentPostflightCheck struct {
	ID             string `json:"id" yaml:"id"`
	Status         string `json:"status" yaml:"status"`
	EvidenceDigest string `json:"evidenceDigest" yaml:"evidenceDigest"`
	DiagnosticCode string `json:"diagnosticCode,omitempty" yaml:"diagnosticCode,omitempty"`
}

func (r DeploymentReceipt) AssignReceiptID() (DeploymentReceipt, error) {
	r.Metadata.ReceiptID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return DeploymentReceipt{}, fmt.Errorf("digest deployment receipt: %w", err)
	}
	r.Metadata.ReceiptID = digest
	return r, nil
}

func (r DeploymentReceipt) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "DeploymentReceipt", "RCP", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.receiptId": r.Metadata.ReceiptID, "spec.planId": r.Spec.PlanID, "spec.bundleId": r.Spec.BundleID,
		"spec.preflightResultId": r.Spec.PreflightResultID, "spec.changeSetId": r.Spec.ChangeSetID,
		"spec.approvalId": r.Spec.ApprovalID, "spec.authorizationId": r.Spec.AuthorizationID, "spec.importReceiptId": r.Spec.ImportReceiptID,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
		"spec.executor.binaryDigest":  r.Spec.Executor.BinaryDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-RCP-010", "Receipt bindings must be SHA-256 digests.", path))
		}
	}
	started, startedErr := time.Parse(time.RFC3339Nano, r.Spec.StartedAt)
	completed, completedErr := time.Parse(time.RFC3339Nano, r.Spec.CompletedAt)
	if startedErr != nil || completedErr != nil || completed.Before(started) {
		items = append(items, diagnostics.Error("YARA-RCP-011", "Receipt timestamps must form a valid RFC3339 interval.", "spec.completedAt"))
	}
	if !slices.Contains([]string{"succeeded", "failed", "partial"}, r.Spec.Outcome) || r.Spec.ExecutionCorrelationID == "" {
		items = append(items, diagnostics.Error("YARA-RCP-012", "Receipt outcome and execution correlation are required.", "spec.outcome"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" || r.Spec.Executor.Name == "" || r.Spec.Executor.Version == "" {
		items = append(items, diagnostics.Error("YARA-RCP-013", "A Kubernetes target and exact executor identity are required.", "spec"))
	}
	if len(r.Spec.Operations) == 0 || len(r.Spec.Postflight) == 0 {
		items = append(items, diagnostics.Error("YARA-RCP-014", "Operation and postflight evidence are required.", "spec"))
	}
	if len(r.Spec.TransferReceiptIDs) > 0 {
		if !slices.IsSorted(r.Spec.TransferReceiptIDs) || hasDuplicateStrings(r.Spec.TransferReceiptIDs) {
			items = append(items, diagnostics.Error("YARA-RCP-023", "Transfer receipt IDs must be unique and sorted when present.", "spec.transferReceiptIds"))
		}
		for index, value := range r.Spec.TransferReceiptIDs {
			if !sha256DigestPattern.MatchString(value) {
				items = append(items, diagnostics.Error("YARA-RCP-024", "Transfer receipt IDs must be SHA-256 digests.", fmt.Sprintf("spec.transferReceiptIds[%d]", index)))
			}
		}
	}
	if len(r.Spec.ScanReceiptIDs) > 0 {
		if !slices.IsSorted(r.Spec.ScanReceiptIDs) || hasDuplicateStrings(r.Spec.ScanReceiptIDs) {
			items = append(items, diagnostics.Error("YARA-RCP-025", "Scan receipt IDs must be unique and sorted when present.", "spec.scanReceiptIds"))
		}
		for index, value := range r.Spec.ScanReceiptIDs {
			if !sha256DigestPattern.MatchString(value) {
				items = append(items, diagnostics.Error("YARA-RCP-026", "Scan receipt IDs must be SHA-256 digests.", fmt.Sprintf("spec.scanReceiptIds[%d]", index)))
			}
		}
	}
	if r.Spec.AirgapGateResultID != "" && !sha256DigestPattern.MatchString(r.Spec.AirgapGateResultID) {
		items = append(items, diagnostics.Error("YARA-RCP-027", "Air-gap gate result ID must be a SHA-256 digest when present.", "spec.airgapGateResultId"))
	}
	if r.Spec.AirgapGateTrustPolicyID != "" && !sha256DigestPattern.MatchString(r.Spec.AirgapGateTrustPolicyID) {
		items = append(items, diagnostics.Error("YARA-RCP-028", "Air-gap gate trust-policy ID must be a SHA-256 digest when present.", "spec.airgapGateTrustPolicyId"))
	}
	previous, derived := "", "succeeded"
	for index, operation := range r.Spec.Operations {
		path := fmt.Sprintf("spec.operations[%d]", index)
		key := kubernetesObjectKey(operation.Resource)
		if operation.Resource.APIVersion == "" || operation.Resource.Kind == "" || operation.Resource.Name == "" || key <= previous || !slices.Contains([]string{"create", "update", "no-op"}, operation.Action) || !slices.Contains([]string{"applied", "unchanged", "failed", "skipped"}, operation.Outcome) {
			items = append(items, diagnostics.Error("YARA-RCP-015", "Operation receipts must be complete, supported, unique and sorted.", path))
		}
		if (operation.BeforeDigest != "" && !sha256DigestPattern.MatchString(operation.BeforeDigest)) || (operation.AfterDigest != "" && !sha256DigestPattern.MatchString(operation.AfterDigest)) {
			items = append(items, diagnostics.Error("YARA-RCP-016", "Before/after identities must be SHA-256 digests when present.", path))
		}
		if operation.Outcome == "failed" {
			derived = "failed"
			if !diagnosticCodePattern.MatchString(operation.DiagnosticCode) {
				items = append(items, diagnostics.Error("YARA-RCP-017", "Failed operations require a stable diagnostic code.", path+".diagnosticCode"))
			}
		} else if operation.Outcome == "skipped" && derived == "succeeded" {
			derived = "partial"
		}
		previous = key
	}
	postflightPrevious := ""
	for index, check := range r.Spec.Postflight {
		path := fmt.Sprintf("spec.postflight[%d]", index)
		if check.ID == "" || check.ID <= postflightPrevious || !slices.Contains([]string{"passed", "failed", "blocked"}, check.Status) || !sha256DigestPattern.MatchString(check.EvidenceDigest) {
			items = append(items, diagnostics.Error("YARA-RCP-018", "Postflight checks must be complete, unique and sorted.", path))
		}
		if check.Status != "passed" {
			if derived == "succeeded" {
				derived = "partial"
			}
			if !diagnosticCodePattern.MatchString(check.DiagnosticCode) {
				items = append(items, diagnostics.Error("YARA-RCP-019", "Non-passing postflight checks require a stable diagnostic code.", path+".diagnosticCode"))
			}
		}
		postflightPrevious = check.ID
	}
	if r.Spec.Outcome != derived {
		items = append(items, diagnostics.Error("YARA-RCP-020", "Receipt outcome must match operation and postflight evidence.", "spec.outcome"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-RCP-021", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ReceiptID != "" {
		claimed := r.Metadata.ReceiptID
		recomputed, err := r.AssignReceiptID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-RCP-500", "Could not recompute receipt identity."))
		} else if recomputed.Metadata.ReceiptID != claimed {
			items = append(items, diagnostics.Error("YARA-RCP-022", "Receipt contents do not match metadata.receiptId.", "metadata.receiptId"))
		}
	}
	return diagnostics.NewReport(items...)
}
