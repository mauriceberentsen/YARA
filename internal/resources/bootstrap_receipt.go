package resources

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// BootstrapReceipt describes the bounded namespace/PVC bootstrap outcome.
type BootstrapReceipt struct {
	APIVersion string                   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                   `json:"kind" yaml:"kind"`
	Metadata   BootstrapReceiptMetadata `json:"metadata" yaml:"metadata"`
	Spec       BootstrapReceiptSpec     `json:"spec" yaml:"spec"`
}

type BootstrapReceiptMetadata struct {
	Name      string `json:"name" yaml:"name"`
	ReceiptID string `json:"receiptId" yaml:"receiptId"`
}

type BootstrapReceiptSpec struct {
	Outcome                string                      `json:"outcome" yaml:"outcome"`
	StartedAt              string                      `json:"startedAt" yaml:"startedAt"`
	CompletedAt            string                      `json:"completedAt" yaml:"completedAt"`
	ExecutionCorrelationID string                      `json:"executionCorrelationId" yaml:"executionCorrelationId"`
	Target                 TargetIdentity              `json:"target" yaml:"target"`
	Namespace              string                      `json:"namespace" yaml:"namespace"`
	ModelPVC               string                      `json:"modelPvc" yaml:"modelPvc"`
	StorageClass           string                      `json:"storageClass" yaml:"storageClass"`
	Size                   string                      `json:"size" yaml:"size"`
	Executor               DeploymentExecutorIdentity  `json:"executor" yaml:"executor"`
	Operations             []BootstrapOperationReceipt `json:"operations" yaml:"operations"`
	Limitations            []string                    `json:"limitations" yaml:"limitations"`
}

type BootstrapOperationReceipt struct {
	Resource       KubernetesObjectReference `json:"resource" yaml:"resource"`
	Action         string                    `json:"action" yaml:"action"`
	Outcome        string                    `json:"outcome" yaml:"outcome"`
	AfterDigest    string                    `json:"afterDigest,omitempty" yaml:"afterDigest,omitempty"`
	DiagnosticCode string                    `json:"diagnosticCode,omitempty" yaml:"diagnosticCode,omitempty"`
}

var storageClassNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9_.]{0,251}[a-z0-9])?$`)
var storageSizePattern = regexp.MustCompile(`^[1-9][0-9]*(?:Ei|Pi|Ti|Gi|Mi|Ki)?$`)

func (r BootstrapReceipt) AssignReceiptID() (BootstrapReceipt, error) {
	r.Metadata.ReceiptID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return BootstrapReceipt{}, fmt.Errorf("digest bootstrap receipt: %w", err)
	}
	r.Metadata.ReceiptID = digest
	return r, nil
}

func (r BootstrapReceipt) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "BootstrapReceipt", "BST", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.receiptId":          r.Metadata.ReceiptID,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
		"spec.executor.binaryDigest":  r.Spec.Executor.BinaryDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-BST-010", "Bootstrap identities must be SHA-256 digests.", path))
		}
	}
	started, startedErr := time.Parse(time.RFC3339Nano, r.Spec.StartedAt)
	completed, completedErr := time.Parse(time.RFC3339Nano, r.Spec.CompletedAt)
	if startedErr != nil || completedErr != nil || completed.Before(started) {
		items = append(items, diagnostics.Error("YARA-BST-011", "Bootstrap timestamps must form a valid RFC3339 interval.", "spec.completedAt"))
	}
	if !slices.Contains([]string{"succeeded", "failed", "partial"}, r.Spec.Outcome) || strings.TrimSpace(r.Spec.ExecutionCorrelationID) == "" {
		items = append(items, diagnostics.Error("YARA-BST-012", "Bootstrap outcome and execution correlation are required.", "spec.outcome"))
	}
	if r.Spec.Target.Type != "kubernetes" || strings.TrimSpace(r.Spec.Target.ServerVersion) == "" {
		items = append(items, diagnostics.Error("YARA-BST-013", "A complete Kubernetes target identity is required.", "spec.target"))
	}
	if !resourceNamePattern.MatchString(r.Spec.Namespace) || !resourceNamePattern.MatchString(r.Spec.ModelPVC) {
		items = append(items, diagnostics.Error("YARA-BST-014", "Namespace and model PVC names must be lowercase DNS-style names.", "spec.namespace"))
	}
	if !storageClassNamePattern.MatchString(r.Spec.StorageClass) || !storageSizePattern.MatchString(r.Spec.Size) {
		items = append(items, diagnostics.Error("YARA-BST-015", "Storage class and size must be explicitly bounded and well formed.", "spec.storageClass"))
	}
	if r.Spec.Executor.Name == "" || r.Spec.Executor.Version == "" {
		items = append(items, diagnostics.Error("YARA-BST-016", "A complete bootstrap executor identity is required.", "spec.executor"))
	}
	if len(r.Spec.Operations) == 0 {
		items = append(items, diagnostics.Error("YARA-BST-017", "At least one bootstrap operation is required.", "spec.operations"))
	}
	previous, derived := "", "succeeded"
	for index, operation := range r.Spec.Operations {
		path := fmt.Sprintf("spec.operations[%d]", index)
		key := kubernetesObjectKey(operation.Resource)
		if operation.Resource.APIVersion == "" || operation.Resource.Kind == "" || operation.Resource.Name == "" || key <= previous || !slices.Contains([]string{"create", "no-op"}, operation.Action) || !slices.Contains([]string{"created", "unchanged", "failed", "skipped"}, operation.Outcome) {
			items = append(items, diagnostics.Error("YARA-BST-018", "Bootstrap operations must be complete, bounded, unique and sorted.", path))
		}
		if operation.AfterDigest != "" && !sha256DigestPattern.MatchString(operation.AfterDigest) {
			items = append(items, diagnostics.Error("YARA-BST-019", "Bootstrap operation after-digests must be SHA-256 when present.", path+".afterDigest"))
		}
		if operation.Outcome == "failed" {
			derived = "failed"
			if !diagnosticCodePattern.MatchString(operation.DiagnosticCode) {
				items = append(items, diagnostics.Error("YARA-BST-020", "Failed bootstrap operations require a stable diagnostic code.", path+".diagnosticCode"))
			}
		} else if (operation.Outcome == "skipped" || operation.Outcome == "unchanged") && derived == "succeeded" {
			derived = "partial"
		}
		previous = key
	}
	if r.Spec.Outcome != derived {
		items = append(items, diagnostics.Error("YARA-BST-021", "Bootstrap outcome must match operation evidence.", "spec.outcome"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-BST-022", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ReceiptID != "" {
		claimed := r.Metadata.ReceiptID
		recomputed, err := r.AssignReceiptID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-BST-500", "Could not recompute bootstrap receipt identity."))
		} else if recomputed.Metadata.ReceiptID != claimed {
			items = append(items, diagnostics.Error("YARA-BST-023", "Bootstrap receipt contents do not match metadata.receiptId.", "metadata.receiptId"))
		}
	}
	return diagnostics.NewReport(items...)
}
