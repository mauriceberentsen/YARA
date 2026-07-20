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
	PromotionDecisionApproved        = "approved"
	PromotionDecisionChangesRequired = "changes-required"
	PromotionDecisionAbstained       = "abstained"
)

// PromotionReview records an independent review decision over exact accepted
// evidence for one catalog assertion.
type PromotionReview struct {
	APIVersion string                  `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                  `json:"kind" yaml:"kind"`
	Metadata   PromotionReviewMetadata `json:"metadata" yaml:"metadata"`
	Spec       PromotionReviewSpec     `json:"spec" yaml:"spec"`
}

type PromotionReviewMetadata struct {
	Name     string `json:"name" yaml:"name"`
	ReviewID string `json:"reviewId" yaml:"reviewId"`
}

type PromotionReviewSpec struct {
	CatalogDigest    string         `json:"catalogDigest" yaml:"catalogDigest"`
	AssertionRef     string         `json:"assertionRef" yaml:"assertionRef"`
	SelectedEvidence []string       `json:"selectedEvidence" yaml:"selectedEvidence"`
	Reviewer         ReviewerRecord `json:"reviewer" yaml:"reviewer"`
	ReviewedAt       string         `json:"reviewedAt" yaml:"reviewedAt"`
	Decision         string         `json:"decision" yaml:"decision"`
	ReasonReference  string         `json:"reasonReference" yaml:"reasonReference"`
	Limitations      []string       `json:"limitations" yaml:"limitations"`
}

func (r PromotionReview) AssignReviewID() (PromotionReview, error) {
	r.Metadata.ReviewID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return PromotionReview{}, fmt.Errorf("digest promotion review: %w", err)
	}
	r.Metadata.ReviewID = digest
	return r, nil
}

func (r PromotionReview) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "PromotionReview", "PRM", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.reviewId":  r.Metadata.ReviewID,
		"spec.catalogDigest": r.Spec.CatalogDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-PRM-010", "Promotion review digests must be SHA-256 identities.", path))
		}
	}
	if strings.TrimSpace(r.Spec.AssertionRef) == "" {
		items = append(items, diagnostics.Error("YARA-PRM-011", "Promotion review requires an exact assertion reference.", "spec.assertionRef"))
	}
	if len(r.Spec.SelectedEvidence) == 0 || !slices.IsSorted(r.Spec.SelectedEvidence) || hasDuplicateStrings(r.Spec.SelectedEvidence) {
		items = append(items, diagnostics.Error("YARA-PRM-012", "Promotion review requires unique sorted selected evidence IDs.", "spec.selectedEvidence"))
	}
	for index, value := range r.Spec.SelectedEvidence {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-PRM-013", "Selected evidence IDs must be SHA-256 digests.", fmt.Sprintf("spec.selectedEvidence[%d]", index)))
		}
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-PRM-014", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.ReviewedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-PRM-015", "Promotion review requires an RFC3339 reviewedAt timestamp.", "spec.reviewedAt"))
	}
	if !validPromotionDecision(r.Spec.Decision) {
		items = append(items, diagnostics.Error("YARA-PRM-016", "Decision must be approved, changes-required or abstained.", "spec.decision"))
	}
	if strings.TrimSpace(r.Spec.ReasonReference) == "" {
		items = append(items, diagnostics.Error("YARA-PRM-017", "A non-secret reason reference is required.", "spec.reasonReference"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-PRM-018", "At least one unique sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ReviewID != "" {
		claimed := r.Metadata.ReviewID
		recomputed, err := r.AssignReviewID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-PRM-500", "Could not recompute promotion review identity."))
		} else if recomputed.Metadata.ReviewID != claimed {
			items = append(items, diagnostics.Error("YARA-PRM-019", "Promotion review contents do not match metadata.reviewId.", "metadata.reviewId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func validPromotionDecision(value string) bool {
	return value == PromotionDecisionApproved || value == PromotionDecisionChangesRequired || value == PromotionDecisionAbstained
}
