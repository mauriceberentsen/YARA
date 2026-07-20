package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type LifecycleProofApproval struct {
	APIVersion string                     `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                     `json:"kind" yaml:"kind"`
	Metadata   LifecycleProofApprovalMeta `json:"metadata" yaml:"metadata"`
	Spec       LifecycleProofApprovalSpec `json:"spec" yaml:"spec"`
}

type LifecycleProofApprovalMeta struct {
	Name       string `json:"name" yaml:"name"`
	ApprovalID string `json:"approvalId" yaml:"approvalId"`
}

type LifecycleProofApprovalSpec struct {
	ReviewedAt       string         `json:"reviewedAt" yaml:"reviewedAt"`
	ExpiresAt        string         `json:"expiresAt" yaml:"expiresAt"`
	CatalogDigest    string         `json:"catalogDigest" yaml:"catalogDigest"`
	AssertionRef     string         `json:"assertionRef" yaml:"assertionRef"`
	LedgerID         string         `json:"ledgerId" yaml:"ledgerId"`
	SelectedEvidence []string       `json:"selectedEvidence" yaml:"selectedEvidence"`
	Reviewer         ReviewerRecord `json:"reviewer" yaml:"reviewer"`
	Decision         string         `json:"decision" yaml:"decision"`
	ReasonReference  string         `json:"reasonReference" yaml:"reasonReference"`
	MaxLedgerAge     string         `json:"maxLedgerAge" yaml:"maxLedgerAge"`
	Limitations      []string       `json:"limitations" yaml:"limitations"`
}

func (r LifecycleProofApproval) AssignApprovalID() (LifecycleProofApproval, error) {
	r.Metadata.ApprovalID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return LifecycleProofApproval{}, fmt.Errorf("digest lifecycle proof approval: %w", err)
	}
	r.Metadata.ApprovalID = digest
	return r, nil
}

func (r LifecycleProofApproval) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "LifecycleProofApproval", "LPA", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.approvalId": r.Metadata.ApprovalID,
		"spec.catalogDigest":  r.Spec.CatalogDigest,
		"spec.ledgerId":       r.Spec.LedgerID,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-LPA-010", "Lifecycle-proof approval identities must be SHA-256 digests.", path))
		}
	}
	if strings.TrimSpace(r.Spec.AssertionRef) == "" {
		items = append(items, diagnostics.Error("YARA-LPA-011", "Assertion reference is required.", "spec.assertionRef"))
	}
	reviewedAt, reviewedErr := time.Parse(time.RFC3339Nano, r.Spec.ReviewedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, r.Spec.ExpiresAt)
	if reviewedErr != nil || expiresErr != nil || !expiresAt.After(reviewedAt) {
		items = append(items, diagnostics.Error("YARA-LPA-012", "Lifecycle-proof approval reviewed/expires window must be a valid RFC3339 interval.", "spec.expiresAt"))
	}
	if len(r.Spec.SelectedEvidence) == 0 || !slices.IsSorted(r.Spec.SelectedEvidence) || hasDuplicateStrings(r.Spec.SelectedEvidence) {
		items = append(items, diagnostics.Error("YARA-LPA-013", "Selected evidence IDs must be unique and sorted.", "spec.selectedEvidence"))
	}
	for index, value := range r.Spec.SelectedEvidence {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-LPA-014", "Selected evidence IDs must be SHA-256 digests.", fmt.Sprintf("spec.selectedEvidence[%d]", index)))
		}
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-LPA-015", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if !validPromotionDecision(r.Spec.Decision) {
		items = append(items, diagnostics.Error("YARA-LPA-016", "Decision must be approved, changes-required or abstained.", "spec.decision"))
	}
	if strings.TrimSpace(r.Spec.ReasonReference) == "" {
		items = append(items, diagnostics.Error("YARA-LPA-017", "Reason reference is required.", "spec.reasonReference"))
	}
	maxLedgerAge, err := time.ParseDuration(strings.TrimSpace(r.Spec.MaxLedgerAge))
	if err != nil || maxLedgerAge <= 0 {
		items = append(items, diagnostics.Error("YARA-LPA-018", "Max ledger age must be a positive Go duration.", "spec.maxLedgerAge"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-LPA-019", "At least one unique sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ApprovalID != "" {
		claimed := r.Metadata.ApprovalID
		recomputed, err := r.AssignApprovalID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-LPA-500", "Could not recompute lifecycle-proof approval identity."))
		} else if recomputed.Metadata.ApprovalID != claimed {
			items = append(items, diagnostics.Error("YARA-LPA-020", "Lifecycle-proof approval contents do not match metadata.approvalId.", "metadata.approvalId"))
		}
	}
	return diagnostics.NewReport(items...)
}
