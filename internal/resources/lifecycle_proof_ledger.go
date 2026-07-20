package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

const (
	LifecycleStageApply    = "apply"
	LifecycleStageRetire   = "retire"
	LifecycleStageRollback = "rollback"
)

type LifecycleProofLedger struct {
	APIVersion string                   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                   `json:"kind" yaml:"kind"`
	Metadata   LifecycleProofLedgerMeta `json:"metadata" yaml:"metadata"`
	Spec       LifecycleProofLedgerSpec `json:"spec" yaml:"spec"`
}

type LifecycleProofLedgerMeta struct {
	Name     string `json:"name" yaml:"name"`
	LedgerID string `json:"ledgerId" yaml:"ledgerId"`
}

type LifecycleProofLedgerSpec struct {
	RecordedAt            string                      `json:"recordedAt" yaml:"recordedAt"`
	PlanID                string                      `json:"planId" yaml:"planId"`
	BundleID              string                      `json:"bundleId" yaml:"bundleId"`
	TargetReferenceDigest string                      `json:"targetReferenceDigest" yaml:"targetReferenceDigest"`
	Reviewer              ReviewerRecord              `json:"reviewer" yaml:"reviewer"`
	Decision              string                      `json:"decision" yaml:"decision"`
	ReasonReference       string                      `json:"reasonReference" yaml:"reasonReference"`
	Stages                []LifecycleProofLedgerStage `json:"stages" yaml:"stages"`
	Limitations           []string                    `json:"limitations" yaml:"limitations"`
}

type LifecycleProofLedgerStage struct {
	Stage                  string `json:"stage" yaml:"stage"`
	ReceiptID              string `json:"receiptId" yaml:"receiptId"`
	ExecutionCorrelationID string `json:"executionCorrelationId" yaml:"executionCorrelationId"`
	Outcome                string `json:"outcome" yaml:"outcome"`
	CompletedAt            string `json:"completedAt" yaml:"completedAt"`
}

func (r LifecycleProofLedger) AssignLedgerID() (LifecycleProofLedger, error) {
	r.Metadata.LedgerID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return LifecycleProofLedger{}, fmt.Errorf("digest lifecycle proof ledger: %w", err)
	}
	r.Metadata.LedgerID = digest
	return r, nil
}

func (r LifecycleProofLedger) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "LifecycleProofLedger", "LGR", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.ledgerId":          r.Metadata.LedgerID,
		"spec.planId":                r.Spec.PlanID,
		"spec.bundleId":              r.Spec.BundleID,
		"spec.targetReferenceDigest": r.Spec.TargetReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-LGR-010", "Lifecycle proof ledger bindings must be SHA-256 digests.", path))
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-LGR-011", "Lifecycle proof ledger recordedAt must be RFC3339.", "spec.recordedAt"))
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-LGR-012", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if !validPromotionDecision(r.Spec.Decision) {
		items = append(items, diagnostics.Error("YARA-LGR-013", "Decision must be approved, changes-required or abstained.", "spec.decision"))
	}
	if strings.TrimSpace(r.Spec.ReasonReference) == "" {
		items = append(items, diagnostics.Error("YARA-LGR-014", "A non-secret reason reference is required.", "spec.reasonReference"))
	}
	if len(r.Spec.Stages) != 3 {
		items = append(items, diagnostics.Error("YARA-LGR-015", "Lifecycle proof ledger requires exactly apply, retire and rollback stages.", "spec.stages"))
	}
	expected := []string{LifecycleStageApply, LifecycleStageRetire, LifecycleStageRollback}
	seenReceiptIDs := map[string]struct{}{}
	seenExecutionIDs := map[string]struct{}{}
	previousCompletedAt := time.Time{}
	for index, stage := range r.Spec.Stages {
		path := fmt.Sprintf("spec.stages[%d]", index)
		if index >= len(expected) || stage.Stage != expected[index] {
			items = append(items, diagnostics.Error("YARA-LGR-016", "Lifecycle stages must be ordered as apply, retire, rollback.", path+".stage"))
		}
		if !sha256DigestPattern.MatchString(stage.ReceiptID) {
			items = append(items, diagnostics.Error("YARA-LGR-017", "Stage receiptId must be a SHA-256 digest.", path+".receiptId"))
		}
		if strings.TrimSpace(stage.ExecutionCorrelationID) == "" {
			items = append(items, diagnostics.Error("YARA-LGR-018", "Stage executionCorrelationId is required.", path+".executionCorrelationId"))
		}
		if stage.Outcome != "succeeded" {
			items = append(items, diagnostics.Error("YARA-LGR-019", "Lifecycle proof stages must have succeeded outcomes.", path+".outcome"))
		}
		completedAt, err := time.Parse(time.RFC3339Nano, stage.CompletedAt)
		if err != nil {
			items = append(items, diagnostics.Error("YARA-LGR-020", "Stage completedAt must be RFC3339.", path+".completedAt"))
		} else if !previousCompletedAt.IsZero() && (completedAt.Before(previousCompletedAt) || completedAt.Equal(previousCompletedAt)) {
			items = append(items, diagnostics.Error("YARA-LGR-021", "Lifecycle stages must progress with strictly increasing completedAt timestamps.", path+".completedAt"))
		} else {
			previousCompletedAt = completedAt
		}
		if _, exists := seenReceiptIDs[stage.ReceiptID]; exists {
			items = append(items, diagnostics.Error("YARA-LGR-022", "Lifecycle stage receipt IDs must be unique.", path+".receiptId"))
		}
		seenReceiptIDs[stage.ReceiptID] = struct{}{}
		if _, exists := seenExecutionIDs[stage.ExecutionCorrelationID]; exists {
			items = append(items, diagnostics.Error("YARA-LGR-023", "Lifecycle stage execution correlation IDs must be unique.", path+".executionCorrelationId"))
		}
		seenExecutionIDs[stage.ExecutionCorrelationID] = struct{}{}
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-LGR-024", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.LedgerID != "" {
		claimed := r.Metadata.LedgerID
		recomputed, err := r.AssignLedgerID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-LGR-500", "Could not recompute lifecycle proof ledger identity."))
		} else if recomputed.Metadata.LedgerID != claimed {
			items = append(items, diagnostics.Error("YARA-LGR-025", "Lifecycle proof ledger contents do not match metadata.ledgerId.", "metadata.ledgerId"))
		}
	}
	return diagnostics.NewReport(items...)
}
