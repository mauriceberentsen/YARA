package resources

import (
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// RetirementReceipt describes a separately authorized delete-only execution.
type RetirementReceipt struct {
	APIVersion string                    `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                    `json:"kind" yaml:"kind"`
	Metadata   RetirementReceiptMetadata `json:"metadata" yaml:"metadata"`
	Spec       RetirementReceiptSpec     `json:"spec" yaml:"spec"`
}

type RetirementReceiptMetadata struct {
	Name      string `json:"name" yaml:"name"`
	ReceiptID string `json:"receiptId" yaml:"receiptId"`
}

type RetirementReceiptSpec struct {
	Outcome                string                       `json:"outcome" yaml:"outcome"`
	StartedAt              string                       `json:"startedAt" yaml:"startedAt"`
	CompletedAt            string                       `json:"completedAt" yaml:"completedAt"`
	ExecutionCorrelationID string                       `json:"executionCorrelationId" yaml:"executionCorrelationId"`
	PlanID                 string                       `json:"planId" yaml:"planId"`
	BundleID               string                       `json:"bundleId" yaml:"bundleId"`
	PreflightResultID      string                       `json:"preflightResultId" yaml:"preflightResultId"`
	ChangeSetID            string                       `json:"changeSetId" yaml:"changeSetId"`
	ApprovalID             string                       `json:"approvalId" yaml:"approvalId"`
	AuthorizationID        string                       `json:"authorizationId" yaml:"authorizationId"`
	Target                 TargetIdentity               `json:"target" yaml:"target"`
	Executor               DeploymentExecutorIdentity   `json:"executor" yaml:"executor"`
	Operations             []RetirementOperationReceipt `json:"operations" yaml:"operations"`
	Limitations            []string                     `json:"limitations" yaml:"limitations"`
}

type RetirementOperationReceipt struct {
	Resource       KubernetesObjectReference `json:"resource" yaml:"resource"`
	Action         string                    `json:"action" yaml:"action"`
	Outcome        string                    `json:"outcome" yaml:"outcome"`
	BeforeDigest   string                    `json:"beforeDigest,omitempty" yaml:"beforeDigest,omitempty"`
	DiagnosticCode string                    `json:"diagnosticCode,omitempty" yaml:"diagnosticCode,omitempty"`
}

func (r RetirementReceipt) AssignReceiptID() (RetirementReceipt, error) {
	r.Metadata.ReceiptID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return RetirementReceipt{}, fmt.Errorf("digest retirement receipt: %w", err)
	}
	r.Metadata.ReceiptID = digest
	return r, nil
}

func (r RetirementReceipt) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "RetirementReceipt", "RTR", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.receiptId":          r.Metadata.ReceiptID,
		"spec.planId":                 r.Spec.PlanID,
		"spec.bundleId":               r.Spec.BundleID,
		"spec.preflightResultId":      r.Spec.PreflightResultID,
		"spec.changeSetId":            r.Spec.ChangeSetID,
		"spec.approvalId":             r.Spec.ApprovalID,
		"spec.authorizationId":        r.Spec.AuthorizationID,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
		"spec.executor.binaryDigest":  r.Spec.Executor.BinaryDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-RTR-010", "Retirement bindings must be SHA-256 digests.", path))
		}
	}
	started, startedErr := time.Parse(time.RFC3339Nano, r.Spec.StartedAt)
	completed, completedErr := time.Parse(time.RFC3339Nano, r.Spec.CompletedAt)
	if startedErr != nil || completedErr != nil || completed.Before(started) {
		items = append(items, diagnostics.Error("YARA-RTR-011", "Retirement timestamps must form a valid RFC3339 interval.", "spec.completedAt"))
	}
	if !slices.Contains([]string{"succeeded", "failed", "partial"}, r.Spec.Outcome) || r.Spec.ExecutionCorrelationID == "" {
		items = append(items, diagnostics.Error("YARA-RTR-012", "Retirement outcome and execution correlation are required.", "spec.outcome"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" || r.Spec.Executor.Name == "" || r.Spec.Executor.Version == "" {
		items = append(items, diagnostics.Error("YARA-RTR-013", "A Kubernetes target and exact executor identity are required.", "spec"))
	}
	if len(r.Spec.Operations) == 0 {
		items = append(items, diagnostics.Error("YARA-RTR-014", "At least one retirement operation is required.", "spec.operations"))
	}
	previous, derived := "", "succeeded"
	for index, operation := range r.Spec.Operations {
		path := fmt.Sprintf("spec.operations[%d]", index)
		key := kubernetesObjectKey(operation.Resource)
		if operation.Resource.APIVersion == "" || operation.Resource.Kind == "" || operation.Resource.Name == "" || key <= previous || operation.Action != "delete" || !slices.Contains([]string{"deleted", "failed", "skipped", "unchanged"}, operation.Outcome) {
			items = append(items, diagnostics.Error("YARA-RTR-015", "Retirement operations must be complete, delete-only, unique and sorted.", path))
		}
		if operation.BeforeDigest != "" && !sha256DigestPattern.MatchString(operation.BeforeDigest) {
			items = append(items, diagnostics.Error("YARA-RTR-016", "Operation identities must be SHA-256 digests when present.", path))
		}
		if operation.Outcome == "failed" {
			derived = "failed"
			if !diagnosticCodePattern.MatchString(operation.DiagnosticCode) {
				items = append(items, diagnostics.Error("YARA-RTR-017", "Failed retirement operations require a stable diagnostic code.", path+".diagnosticCode"))
			}
		} else if (operation.Outcome == "skipped" || operation.Outcome == "unchanged") && derived == "succeeded" {
			derived = "partial"
		}
		previous = key
	}
	if r.Spec.Outcome != derived {
		items = append(items, diagnostics.Error("YARA-RTR-018", "Retirement outcome must match operation evidence.", "spec.outcome"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-RTR-019", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ReceiptID != "" {
		claimed := r.Metadata.ReceiptID
		recomputed, err := r.AssignReceiptID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-RTR-500", "Could not recompute retirement receipt identity."))
		} else if recomputed.Metadata.ReceiptID != claimed {
			items = append(items, diagnostics.Error("YARA-RTR-020", "Retirement receipt contents do not match metadata.receiptId.", "metadata.receiptId"))
		}
	}
	return diagnostics.NewReport(items...)
}
